#!/usr/bin/env python3
"""User-owned macOS runner for bounded U2 Maker and Reviewer queues.

This process is intentionally started by the user, outside Codex.  It never
signs an approval, edits source, pushes, merges, or deploys.  It may ask the
controller to release one user-directed read-only Reviewer queue under an
already signed standing policy.  It consumes at most one signed work item per
polling cycle and records each release and item attempt before invoking the
controller so a failed launch is never retried automatically.
"""

from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
import plistlib
import re
import shlex
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence


DENY = 77
INVALID = 78
ROOT = Path(__file__).parents[1]
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
LAUNCH_AGENT_LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{2,127}$")
RUNNER_FIELDS = {
    "schema_version",
    "status",
    "poll_seconds",
    "automatic_retries",
    "maximum_operations_per_cycle",
    "state_directory",
    "executor_root",
    "trusted_executor_sha",
    "executor_config",
    "controller_key_path",
    "approval_public_key_path",
    "approval_public_key_sha256",
    "repositories",
}
OPTIONAL_RUNNER_FIELDS = {
    "standing_policy_path",
    "standing_release_ledger",
}
LEGACY_REPOSITORY_FIELDS = {
    "repository",
    "worktree",
    "queue_directory",
    "git_excludes_file",
}
DISCOVERY_REPOSITORY_FIELDS = {
    "lane_id",
    "repository",
    "worktree_parent",
    "branch_prefix",
    "queue_directory",
    "git_excludes_file",
}
LANE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")
ALLOWED_DISCOVERY_BRANCH_PREFIXES = {"codex/review-snapshot/"}
ALLOWED_REPOSITORIES = {
    "leeshsnu/treeXchange-agent-executor",
    "leeshsnu/treeXchange-season2",
}
BASE_INHERITED_ENVIRONMENT = {
    "HOME",
    "LANG",
    "LC_ALL",
    "LOGNAME",
    "PATH",
    "SHELL",
    "SSH_AUTH_SOCK",
    "TMPDIR",
    "USER",
    "XDG_CONFIG_HOME",
}
RUN_INHERITED_ENVIRONMENT = BASE_INHERITED_ENVIRONMENT | {"CLAUDE_CODE_OAUTH_TOKEN"}


class RunnerError(Exception):
    def __init__(self, message: str, code: int = DENY):
        super().__init__(message)
        self.code = code


def fail(message: str, code: int = DENY) -> None:
    raise RunnerError(message, code)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def absolute_path(value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value:
        fail(f"{label} must be a non-empty absolute path", INVALID)
    path = Path(value)
    if not path.is_absolute():
        fail(f"{label} must be an absolute path", INVALID)
    return path


def private_file_bytes(path: Path, label: str) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        fail(f"{label} is unavailable: {error}")
    try:
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode):
            fail(f"{label} must be a regular file")
        if details.st_uid != os.getuid():
            fail(f"{label} must be owned by the current user")
        if stat.S_IMODE(details.st_mode) & 0o077:
            fail(f"{label} must not be accessible by group or other users")
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            value = source.read()
    finally:
        os.close(descriptor)
    if not value:
        fail(f"{label} must not be empty")
    return value


def load_private_json(path: Path, label: str) -> dict[str, Any]:
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate key: {key}")
            value[key] = item
        return value

    try:
        value = json.loads(
            private_file_bytes(path, label).decode("utf-8"),
            object_pairs_hook=unique_object,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        fail(f"{label} is not valid JSON: {error}", INVALID)
    if not isinstance(value, dict):
        fail(f"{label} must contain a JSON object", INVALID)
    return value


def is_within(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def validate_config(value: dict[str, Any]) -> dict[str, Any]:
    if set(value) not in {
        frozenset(RUNNER_FIELDS),
        frozenset(RUNNER_FIELDS | OPTIONAL_RUNNER_FIELDS),
    } or value.get("schema_version") != 1:
        fail("U2 user-runner config contract drifted", INVALID)
    if value.get("status") not in {"paused", "active"}:
        fail("U2 user-runner status must be paused or active", INVALID)
    if not isinstance(value.get("poll_seconds"), int) or not 5 <= value["poll_seconds"] <= 3600:
        fail("U2 user-runner poll_seconds must be between 5 and 3600", INVALID)
    if value.get("automatic_retries") != 0:
        fail("U2 user-runner automatic retries must remain zero", INVALID)
    if value.get("maximum_operations_per_cycle") != 1:
        fail("U2 user-runner must remain limited to one operation per cycle", INVALID)

    state = absolute_path(value.get("state_directory"), "state_directory")
    executor = absolute_path(value.get("executor_root"), "executor_root")
    controller_key = absolute_path(value.get("controller_key_path"), "controller_key_path")
    approval_public = absolute_path(
        value.get("approval_public_key_path"), "approval_public_key_path"
    )
    approval_public_digest = value.get("approval_public_key_sha256")
    if not isinstance(approval_public_digest, str) or not re.fullmatch(
        r"[0-9a-f]{64}", approval_public_digest
    ):
        fail("approval_public_key_sha256 must be an exact lowercase SHA-256", INVALID)
    executor_config = value.get("executor_config")
    if (
        not isinstance(executor_config, str)
        or not executor_config
        or Path(executor_config).is_absolute()
        or ".." in Path(executor_config).parts
    ):
        fail("executor_config must be a non-empty relative path", INVALID)
    trusted = value.get("trusted_executor_sha")
    if not SHA_RE.fullmatch(trusted or ""):
        fail("trusted_executor_sha must be an exact 40-character SHA", INVALID)

    repositories = value.get("repositories")
    if not isinstance(repositories, list) or not repositories:
        fail("U2 user-runner requires at least one repository", INVALID)
    seen_lanes: set[str] = set()
    repository_roots: list[Path] = []
    discovery_roots: list[Path] = []
    exclude_files: list[Path] = []
    for entry in repositories:
        if not isinstance(entry, dict) or set(entry) not in {
            frozenset(LEGACY_REPOSITORY_FIELDS),
            frozenset(DISCOVERY_REPOSITORY_FIELDS),
        }:
            fail("U2 user-runner repository contract drifted", INVALID)
        repository = entry.get("repository")
        if repository not in ALLOWED_REPOSITORIES:
            fail("U2 user-runner repository is outside the allowlist", INVALID)
        if set(entry) == LEGACY_REPOSITORY_FIELDS:
            lane_id = f"legacy-{repository.replace('/', '-').lower()}"
            worktree = absolute_path(entry.get("worktree"), "repository.worktree")
            repository_roots.append(worktree)
        else:
            lane_id = entry.get("lane_id")
            if not LANE_ID_RE.fullmatch(lane_id or ""):
                fail("U2 user-runner discovery lane id is invalid", INVALID)
            parent = absolute_path(
                entry.get("worktree_parent"), "repository.worktree_parent"
            )
            discovery_roots.append(parent)
            if entry.get("branch_prefix") not in ALLOWED_DISCOVERY_BRANCH_PREFIXES:
                fail("U2 user-runner discovery branch prefix is not approved", INVALID)
        if lane_id in seen_lanes:
            fail("U2 user-runner repository lane is duplicated", INVALID)
        seen_lanes.add(lane_id)
        queue_directory = entry.get("queue_directory")
        if queue_directory != ".agent-state/u2-queues":
            fail("queue_directory must remain under .agent-state/u2-queues", INVALID)
        excludes = entry.get("git_excludes_file")
        if excludes is not None:
            exclude_files.append(
                absolute_path(excludes, "repository.git_excludes_file")
            )

    managed_roots = [*repository_roots, *discovery_roots]
    if is_within(state, executor) or any(is_within(state, root) for root in managed_roots):
        fail("state_directory must remain outside every managed Git worktree", INVALID)
    protected_roots = [executor, *managed_roots]
    if any(is_within(controller_key, root) for root in protected_roots) or any(
        is_within(approval_public, root) for root in protected_roots
    ):
        fail("runner key files must remain outside every managed Git worktree", INVALID)
    if any(any(is_within(path, root) for root in protected_roots) for path in exclude_files):
        fail("git excludes files must remain outside every managed Git worktree", INVALID)
    standing_policy_value = value.get("standing_policy_path")
    standing_ledger_value = value.get("standing_release_ledger")
    if (standing_policy_value is None) != (standing_ledger_value is None):
        fail("standing policy path and release ledger must be configured together", INVALID)
    standing_policy: Path | None = None
    standing_ledger: Path | None = None
    if standing_policy_value is not None:
        standing_policy = absolute_path(standing_policy_value, "standing_policy_path")
        standing_ledger = absolute_path(standing_ledger_value, "standing_release_ledger")
        if any(is_within(standing_policy, root) for root in protected_roots) or any(
            is_within(standing_ledger, root) for root in protected_roots
        ):
            fail("standing-policy state must remain outside every managed Git worktree", INVALID)
    if value["status"] == "active":
        if not executor.is_dir():
            fail("active U2 user-runner executor_root is unavailable")
        if not (executor / executor_config).is_file():
            fail("active U2 user-runner executor_config is unavailable")
        private_file_bytes(controller_key, "controller key")
        approval_public_bytes = private_file_bytes(
            approval_public, "approval public key"
        )
        if hashlib.sha256(approval_public_bytes).hexdigest() != approval_public_digest:
            fail("approval public key does not match the pinned SHA-256")
        for path in exclude_files:
            if private_file_bytes(path, "git excludes file") != b".agent-state/\n":
                fail("git excludes file may ignore only .agent-state/")
        for root in repository_roots:
            if not root.is_dir():
                fail("active U2 user-runner repository worktree is unavailable")
        for root in discovery_roots:
            try:
                metadata = root.lstat()
            except OSError:
                fail("active U2 user-runner worktree discovery root is unavailable")
            if (
                stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) & 0o022
            ):
                fail("active U2 worktree discovery root must be owner-controlled")
        if standing_policy is not None and standing_ledger is not None:
            private_file_bytes(standing_policy, "signed standing policy")
            try:
                metadata = standing_ledger.lstat()
            except OSError:
                fail("standing release ledger is unavailable")
            if (
                stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) & 0o077
            ):
                fail("standing release ledger must be an owner-only real directory")
    return value


def load_config(path: Path) -> dict[str, Any]:
    value = validate_config(load_private_json(path, "U2 user-runner config"))
    roots = [Path(value["executor_root"])]
    for entry in value["repositories"]:
        root_field = (
            "worktree" if set(entry) == LEGACY_REPOSITORY_FIELDS else "worktree_parent"
        )
        roots.append(Path(entry[root_field]))
    if any(is_within(path, root) for root in roots):
        fail("U2 user-runner config must remain outside every managed Git worktree")
    return value


def run_command(
    args: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(args),
        cwd=cwd,
        env=None if env is None else dict(env),
        text=True,
        capture_output=True,
        check=False,
    )


def exact_executor_sha(config: dict[str, Any]) -> str:
    executor = Path(config["executor_root"])
    completed = run_command(["git", "rev-parse", "HEAD"], cwd=executor)
    if completed.returncode != 0:
        fail("U2 user-runner could not inspect the executor commit")
    return completed.stdout.strip()


def require_exact_executor(config: dict[str, Any]) -> None:
    executor = Path(config["executor_root"])
    if ROOT.resolve() != executor.resolve():
        fail("U2 user-runner must execute from the approved executor root")
    if exact_executor_sha(config) != config["trusted_executor_sha"]:
        fail("U2 user-runner executor SHA is not the approved exact commit")
    completed = run_command(
        ["git", "status", "--porcelain", "--untracked-files=all"],
        cwd=executor,
    )
    if completed.returncode != 0 or completed.stdout.strip():
        fail("U2 user-runner executor worktree must remain clean")


def private_state_directory(config: dict[str, Any]) -> Path:
    path = Path(config["state_directory"])
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    details = path.lstat()
    if stat.S_ISLNK(details.st_mode) or not stat.S_ISDIR(details.st_mode):
        fail("U2 user-runner state directory must be a real directory")
    os.chmod(path, 0o700)
    details = path.lstat()
    if details.st_uid != os.getuid() or stat.S_IMODE(details.st_mode) & 0o077:
        fail("U2 user-runner state directory must remain owner-only")
    return path


def save_private_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def load_attempts(state: Path) -> dict[str, Any]:
    path = state / "attempts.json"
    if not path.exists():
        return {"schema_version": 1, "attempts": {}}
    value = load_private_json(path, "U2 user-runner attempts")
    if set(value) != {"schema_version", "attempts"} or value.get("schema_version") != 1:
        fail("U2 user-runner attempt ledger contract drifted", INVALID)
    if not isinstance(value.get("attempts"), dict):
        fail("U2 user-runner attempt ledger is invalid", INVALID)
    return value


def runner_environment(config: dict[str, Any], repository: dict[str, Any]) -> dict[str, str]:
    source = os.environ
    environment = {key: source[key] for key in RUN_INHERITED_ENVIRONMENT if key in source}
    try:
        controller_key = private_file_bytes(
            Path(config["controller_key_path"]), "controller key"
        ).decode("utf-8").strip()
    except UnicodeDecodeError:
        fail("controller key must be UTF-8 text")
    if len(controller_key.encode("utf-8")) < 32:
        fail("controller key must contain at least 32 bytes")
    environment.update(
        {
            "U2_EXECUTOR_TRUSTED_SHA": config["trusted_executor_sha"],
            "TREEXCHANGE_U2_CONTROLLER_KEY": controller_key,
            "TREEXCHANGE_U2_APPROVAL_PUBLIC_KEY_PATH": config[
                "approval_public_key_path"
            ],
            "TREEXCHANGE_U2_APPROVAL_PUBLIC_KEY_SHA256": config[
                "approval_public_key_sha256"
            ],
        }
    )
    excludes = repository.get("git_excludes_file")
    if excludes:
        environment.update(
            {
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "core.excludesFile",
                "GIT_CONFIG_VALUE_0": excludes,
            }
        )
    return environment


def inspection_environment(repository: dict[str, Any]) -> dict[str, str]:
    source = os.environ
    environment = {
        key: source[key] for key in BASE_INHERITED_ENVIRONMENT if key in source
    }
    excludes = repository.get("git_excludes_file")
    if excludes:
        environment.update(
            {
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "core.excludesFile",
                "GIT_CONFIG_VALUE_0": excludes,
            }
        )
    return environment


def inspect_queue(
    config: dict[str, Any],
    repository: dict[str, Any],
    queue: Path,
    command: Callable[..., subprocess.CompletedProcess[str]] = run_command,
) -> dict[str, Any] | None:
    executor = Path(config["executor_root"])
    controller = executor / "scripts/u2_controller.py"
    completed = command(
        [
            sys.executable,
            str(controller),
            "inspect",
            "--repo",
            repository["worktree"],
            "--queue",
            str(queue),
        ],
        cwd=executor,
        env=inspection_environment(repository),
    )
    if completed.returncode != 0:
        return None
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return None
    if not isinstance(value, dict):
        return None
    return value


def actionable_queue(value: dict[str, Any] | None) -> bool:
    if value is None or value.get("status") != "released":
        return False
    if value.get("external_release_claimed") is not False:
        return False
    maximum = value.get("maximum_operations")
    reserved = value.get("operations_reserved")
    return (
        isinstance(maximum, int)
        and not isinstance(maximum, bool)
        and 1 <= maximum <= 7
        and isinstance(reserved, int)
        and not isinstance(reserved, bool)
        and 0 <= reserved < maximum
        and value.get("next_ready") is True
        and isinstance(value.get("next_work_item_id"), str)
        and bool(value["next_work_item_id"])
        and value.get("next_role") in {"repository_reviewer", "scoped_maker"}
    )


def attempt_key(
    repository: str, queue: Path, digest: str, work_item_id: str
) -> str:
    payload = (
        f"{repository}\0{queue.resolve()}\0{digest}\0{work_item_id}"
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def discovered_repositories(
    entry: dict[str, Any],
    *,
    command: Callable[..., subprocess.CompletedProcess[str]] = run_command,
) -> list[dict[str, Any]]:
    parent = Path(entry["worktree_parent"]).resolve()
    values: list[dict[str, Any]] = []
    try:
        children = sorted(parent.iterdir(), key=lambda path: path.name)
    except OSError:
        return values
    for child in children[:64]:
        try:
            metadata = child.lstat()
        except OSError:
            continue
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            continue
        root = command(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=child,
            env=inspection_environment(entry),
        )
        branch = command(
            ["git", "symbolic-ref", "--quiet", "--short", "HEAD"],
            cwd=child,
            env=inspection_environment(entry),
        )
        if root.returncode != 0 or branch.returncode != 0:
            continue
        try:
            if Path(root.stdout.strip()).resolve() != child.resolve():
                continue
        except OSError:
            continue
        if not branch.stdout.strip().startswith(entry["branch_prefix"]):
            continue
        values.append(
            {
                "repository": entry["repository"],
                "worktree": str(child.resolve()),
                "queue_directory": entry["queue_directory"],
                "git_excludes_file": entry.get("git_excludes_file"),
                "lane_id": entry["lane_id"],
            }
        )
    return values


def queue_candidates(
    config: dict[str, Any],
    *,
    command: Callable[..., subprocess.CompletedProcess[str]] = run_command,
) -> list[tuple[dict[str, Any], Path]]:
    values: list[tuple[dict[str, Any], Path]] = []
    repositories: list[dict[str, Any]] = []
    for configured in config["repositories"]:
        if set(configured) == DISCOVERY_REPOSITORY_FIELDS:
            repositories.extend(discovered_repositories(configured, command=command))
        else:
            repositories.append(configured)
    for repository in repositories:
        root = Path(repository["worktree"])
        directory = root / repository["queue_directory"]
        if directory.is_dir():
            for queue in sorted(directory.glob("*.json")):
                values.append((repository, queue))
    return values


def run_cycle(
    config: dict[str, Any],
    *,
    command: Callable[..., subprocess.CompletedProcess[str]] = run_command,
) -> dict[str, Any]:
    if config["status"] != "active":
        return {"status": "PAUSED", "attempted": False}
    require_exact_executor(config)
    state_directory = private_state_directory(config)
    ledger = load_attempts(state_directory)
    for repository, queue in queue_candidates(config, command=command):
        inspected = inspect_queue(config, repository, queue, command)
        if (
            isinstance(inspected, dict)
            and inspected.get("status") == "draft_paused"
            and config.get("standing_policy_path") is not None
            and isinstance(inspected.get("approval_digest"), str)
            and isinstance(inspected.get("origin"), dict)
            and inspected["origin"].get("requested_assignee") == "Claude"
        ):
            release_key = attempt_key(
                repository["repository"],
                queue,
                inspected["approval_digest"],
                "STANDING-POLICY-RELEASE",
            )
            if release_key not in ledger["attempts"]:
                ledger["attempts"][release_key] = {
                    "at": utc_now(),
                    "queue_id": inspected.get("queue_id"),
                    "work_item_id": inspected.get("next_work_item_id"),
                    "role": inspected.get("next_role"),
                    "approval_digest": inspected["approval_digest"],
                    "status": "standing_release_reserved_before_launch",
                }
                save_private_json(state_directory / "attempts.json", ledger)
                executor = Path(config["executor_root"])
                controller = executor / "scripts/u2_controller.py"
                released = command(
                    [
                        sys.executable,
                        str(controller),
                        "release-under-standing-policy",
                        "--repo",
                        repository["worktree"],
                        "--queue",
                        str(queue),
                        "--config",
                        str(executor / config["executor_config"]),
                        "--policy",
                        config["standing_policy_path"],
                        "--ledger",
                        config["standing_release_ledger"],
                    ],
                    cwd=executor,
                    env=runner_environment(config, repository),
                )
                ledger = load_attempts(state_directory)
                ledger["attempts"][release_key]["finished_at"] = utc_now()
                ledger["attempts"][release_key]["status"] = (
                    "standing_release_completed"
                    if released.returncode == 0
                    else f"standing_release_exit_{released.returncode}"
                )
                save_private_json(state_directory / "attempts.json", ledger)
                if released.returncode != 0:
                    continue
                inspected = inspect_queue(config, repository, queue, command)
        if not actionable_queue(inspected):
            continue
        digest = inspected.get("approval_digest")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            continue
        work_item_id = inspected["next_work_item_id"]
        key = attempt_key(
            repository["repository"], queue, digest, work_item_id
        )
        if key in ledger["attempts"]:
            continue
        ledger["attempts"][key] = {
            "at": utc_now(),
            "queue_id": inspected.get("queue_id"),
            "work_item_id": work_item_id,
            "role": inspected.get("next_role"),
            "approval_digest": digest,
            "status": "reserved_before_launch",
        }
        save_private_json(state_directory / "attempts.json", ledger)

        executor = Path(config["executor_root"])
        controller = executor / "scripts/u2_controller.py"
        completed = command(
            [
                sys.executable,
                str(controller),
                "run-next",
                "--repo",
                repository["worktree"],
                "--queue",
                str(queue),
                "--config",
                str(executor / config["executor_config"]),
            ],
            cwd=executor,
            env=runner_environment(config, repository),
        )
        outcome = "completed" if completed.returncode == 0 else f"controller_exit_{completed.returncode}"
        ledger = load_attempts(state_directory)
        ledger["attempts"][key]["finished_at"] = utc_now()
        ledger["attempts"][key]["status"] = outcome
        save_private_json(state_directory / "attempts.json", ledger)
        return {
            "status": "ATTEMPT_FINISHED",
            "attempted": True,
            "queue_id": inspected.get("queue_id"),
            "work_item_id": work_item_id,
            "role": inspected.get("next_role"),
            "approval_digest": digest,
            "outcome": outcome,
        }
    return {"status": "IDLE", "attempted": False}


def print_event(value: dict[str, Any]) -> None:
    print(json.dumps(value, separators=(",", ":")), flush=True)


def locked_runner(state_directory: Path):
    path = state_directory / "runner.lock"
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(descriptor)
        fail("another U2 user-runner process already owns the lock")
    return descriptor


def require_stable_state_directory(config: dict[str, Any], locked_state: Path) -> None:
    if Path(config["state_directory"]).resolve() != locked_state.resolve():
        fail("U2 user-runner state directory changed after the process lock")


def run_once(args: argparse.Namespace) -> None:
    config = load_config(args.config)
    state = private_state_directory(config)
    descriptor = locked_runner(state)
    try:
        print_event(run_cycle(config))
    finally:
        os.close(descriptor)


def serve(args: argparse.Namespace) -> None:
    initial = load_config(args.config)
    state = private_state_directory(initial)
    descriptor = locked_runner(state)
    print_event({"status": "RUNNER_STARTED", "at": utc_now()})
    last_status: str | None = None
    try:
        while True:
            try:
                config = load_config(args.config)
                require_stable_state_directory(config, state)
                event = run_cycle(config)
                if event["attempted"] or event["status"] != last_status:
                    print_event(event)
                last_status = event["status"]
                delay = config["poll_seconds"]
            except RunnerError as error:
                if last_status != "FAIL_CLOSED":
                    print_event({"status": "FAIL_CLOSED", "code": error.code})
                last_status = "FAIL_CLOSED"
                delay = max(30, initial["poll_seconds"])
            time.sleep(delay)
    except KeyboardInterrupt:
        print_event({"status": "RUNNER_STOPPED", "at": utc_now()})
    finally:
        os.close(descriptor)


def validate(args: argparse.Namespace) -> None:
    config = load_config(args.config)
    if config["status"] == "active":
        require_exact_executor(config)
    print_event(
        {
            "status": "VALID",
            "runner_status": config["status"],
            "trusted_executor_sha": config["trusted_executor_sha"],
            "repositories": [entry["repository"] for entry in config["repositories"]],
            "automatic_retries": 0,
        }
    )


def launch_agent_payload(
    config: dict[str, Any], state: Path, label: str, config_path: Path
) -> dict[str, Any]:
    return {
        "Label": label,
        "ProgramArguments": [
            sys.executable,
            str((ROOT / "scripts/u2_user_runner.py").resolve()),
            "serve",
            "--config",
            str(config_path.resolve()),
        ],
        "RunAtLoad": True,
        "KeepAlive": True,
        "ThrottleInterval": max(30, config["poll_seconds"]),
        "StandardOutPath": str(state / "runner.stdout.log"),
        "StandardErrorPath": str(state / "runner.stderr.log"),
        "ProcessType": "Background",
        "Umask": 0o077,
    }


def ensure_owner_only_git_excludes(path: Path, state_directory: Path) -> None:
    resolved = path.expanduser().resolve()
    state = state_directory.resolve()
    try:
        resolved.relative_to(state)
    except ValueError:
        fail("configured Git excludes file must remain inside runner state", INVALID)
    parent = resolved.parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    metadata = parent.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        fail("Git excludes parent must be an owner-only real directory")
    if resolved.exists():
        if private_file_bytes(resolved, "git excludes file") != b".agent-state/\n":
            fail("git excludes file may ignore only .agent-state/")
        return
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(resolved, flags, 0o600)
        try:
            payload = b".agent-state/\n"
            written = 0
            while written < len(payload):
                count = os.write(descriptor, payload[written:])
                if count == 0:
                    fail("git excludes file write made no progress")
                written += count
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as error:
        fail(f"git excludes file could not be created: {error}")


def configure_standing_review(args: argparse.Namespace) -> None:
    config_path = args.config.expanduser().resolve()
    config = load_config(config_path)
    if config["status"] != "active":
        fail("standing review can be installed only into an active user runner")
    if config["trusted_executor_sha"] != args.expected_current_sha:
        fail("runner config changed after the approved installation plan")
    running_sha = exact_executor_sha(config)
    if running_sha != args.trusted_executor_sha:
        fail("new trusted executor SHA is not the exact installed executor Head")
    if config.get("standing_policy_path") is not None:
        fail("standing review is already configured; replacement requires a new command")
    if any(entry.get("lane_id") == args.lane_id for entry in config["repositories"]):
        fail("standing review discovery lane is already configured")

    state = Path(config["state_directory"])
    excludes = args.git_excludes_file.expanduser().resolve()
    ensure_owner_only_git_excludes(excludes, state)
    policy = args.standing_policy.expanduser().resolve()
    ledger = args.standing_release_ledger.expanduser().resolve()
    updated = {
        **config,
        "trusted_executor_sha": args.trusted_executor_sha,
        "standing_policy_path": str(policy),
        "standing_release_ledger": str(ledger),
        "repositories": [
            *config["repositories"],
            {
                "lane_id": args.lane_id,
                "repository": args.repository,
                "worktree_parent": str(args.worktree_parent.expanduser().resolve()),
                "branch_prefix": args.branch_prefix,
                "queue_directory": ".agent-state/u2-queues",
                "git_excludes_file": str(excludes),
            },
        ],
    }
    validate_config(updated)
    save_private_json(config_path, updated)
    print_event(
        {
            "status": "STANDING_REVIEW_CONFIGURED_NOT_RESTARTED",
            "trusted_executor_sha": updated["trusted_executor_sha"],
            "policy": updated["standing_policy_path"],
            "lane_id": args.lane_id,
            "worktree_parent": str(args.worktree_parent.expanduser().resolve()),
            "automatic_retries": 0,
        }
    )


def install_launch_agent(args: argparse.Namespace) -> None:
    if not LAUNCH_AGENT_LABEL_RE.fullmatch(args.label):
        fail("LaunchAgent label is invalid", INVALID)
    config = load_config(args.config)
    state = private_state_directory(config)
    require_exact_executor(config)
    home = Path.home()
    agents = home / "Library/LaunchAgents"
    agents.mkdir(parents=True, exist_ok=True)
    plist_path = agents / f"{args.label}.plist"
    if plist_path.exists() and not args.replace:
        fail("LaunchAgent already exists; pass --replace to update it")
    payload = launch_agent_payload(config, state, args.label, args.config)
    temporary = plist_path.with_suffix(".plist.tmp")
    with temporary.open("wb") as output:
        plistlib.dump(payload, output, sort_keys=True)
    os.chmod(temporary, 0o600)
    os.replace(temporary, plist_path)
    print_event(
        {
            "status": "LAUNCH_AGENT_WRITTEN_NOT_STARTED",
            "label": args.label,
            "plist": str(plist_path),
            "next_command": shlex.join(
                ["launchctl", "bootstrap", f"gui/{os.getuid()}", str(plist_path)]
            ),
        }
    )


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    subparsers = value.add_subparsers(dest="command", required=True)
    for name, handler in (("validate", validate), ("once", run_once), ("serve", serve)):
        command = subparsers.add_parser(name)
        command.add_argument("--config", type=Path, required=True)
        command.set_defaults(handler=handler)
    install = subparsers.add_parser("install-launch-agent")
    install.add_argument("--config", type=Path, required=True)
    install.add_argument("--label", default="com.treexchange.u2-user-runner")
    install.add_argument("--replace", action="store_true")
    install.set_defaults(handler=install_launch_agent)
    configure = subparsers.add_parser("configure-standing-review")
    configure.add_argument("--config", type=Path, required=True)
    configure.add_argument("--expected-current-sha", required=True)
    configure.add_argument("--trusted-executor-sha", required=True)
    configure.add_argument("--standing-policy", type=Path, required=True)
    configure.add_argument("--standing-release-ledger", type=Path, required=True)
    configure.add_argument("--lane-id", default="season2-review-snapshots")
    configure.add_argument(
        "--repository", default="leeshsnu/treeXchange-season2", choices=sorted(ALLOWED_REPOSITORIES)
    )
    configure.add_argument("--worktree-parent", type=Path, required=True)
    configure.add_argument(
        "--branch-prefix", default="codex/review-snapshot/", choices=sorted(ALLOWED_DISCOVERY_BRANCH_PREFIXES)
    )
    configure.add_argument("--git-excludes-file", type=Path, required=True)
    configure.set_defaults(handler=configure_standing_review)
    return value


def main() -> int:
    args = parser().parse_args()
    try:
        args.handler(args)
    except RunnerError as error:
        print(f"DENY: {error}", file=sys.stderr)
        return error.code
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
