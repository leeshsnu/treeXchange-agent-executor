#!/usr/bin/env python3
"""User-owned macOS runner for already released U2 Reviewer queues.

This process is intentionally started by the user, outside Codex.  It never
releases a queue, signs an approval, edits source, pushes, merges, or deploys.
It may consume one already signed Reviewer operation and records a local
attempt before invoking the controller so a failed launch is never retried
automatically.
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
    "repositories",
}
REPOSITORY_FIELDS = {
    "repository",
    "worktree",
    "queue_directory",
    "git_excludes_file",
}
ALLOWED_REPOSITORIES = {
    "leeshsnu/treeXchange-agent-executor",
    "leeshsnu/treeXchange-season2",
}
INHERITED_ENVIRONMENT = {
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
    "CLAUDE_CODE_OAUTH_TOKEN",
}


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
    if set(value) != RUNNER_FIELDS or value.get("schema_version") != 1:
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
    seen: set[str] = set()
    repository_roots: list[Path] = []
    exclude_files: list[Path] = []
    for entry in repositories:
        if not isinstance(entry, dict) or set(entry) != REPOSITORY_FIELDS:
            fail("U2 user-runner repository contract drifted", INVALID)
        repository = entry.get("repository")
        if repository not in ALLOWED_REPOSITORIES or repository in seen:
            fail("U2 user-runner repository is outside the allowlist or duplicated", INVALID)
        seen.add(repository)
        worktree = absolute_path(entry.get("worktree"), "repository.worktree")
        repository_roots.append(worktree)
        queue_directory = entry.get("queue_directory")
        if queue_directory != ".agent-state/u2-queues":
            fail("queue_directory must remain under .agent-state/u2-queues", INVALID)
        excludes = entry.get("git_excludes_file")
        if excludes is not None:
            exclude_files.append(
                absolute_path(excludes, "repository.git_excludes_file")
            )

    if is_within(state, executor) or any(is_within(state, root) for root in repository_roots):
        fail("state_directory must remain outside every managed Git worktree", INVALID)
    protected_roots = [executor, *repository_roots]
    if any(is_within(controller_key, root) for root in protected_roots) or any(
        is_within(approval_public, root) for root in protected_roots
    ):
        fail("runner key files must remain outside every managed Git worktree", INVALID)
    if any(any(is_within(path, root) for root in protected_roots) for path in exclude_files):
        fail("git excludes files must remain outside every managed Git worktree", INVALID)
    if value["status"] == "active":
        if not executor.is_dir():
            fail("active U2 user-runner executor_root is unavailable")
        if not (executor / executor_config).is_file():
            fail("active U2 user-runner executor_config is unavailable")
        private_file_bytes(controller_key, "controller key")
        private_file_bytes(approval_public, "approval public key")
        for path in exclude_files:
            if private_file_bytes(path, "git excludes file") != b".agent-state/\n":
                fail("git excludes file may ignore only .agent-state/")
        for root in repository_roots:
            if not root.is_dir():
                fail("active U2 user-runner repository worktree is unavailable")
    return value


def load_config(path: Path) -> dict[str, Any]:
    value = validate_config(load_private_json(path, "U2 user-runner config"))
    roots = [
        Path(value["executor_root"]),
        *(Path(entry["worktree"]) for entry in value["repositories"]),
    ]
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
    environment = {key: source[key] for key in INHERITED_ENVIRONMENT if key in source}
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
    environment = {key: source[key] for key in INHERITED_ENVIRONMENT if key in source}
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
    counts = value.get("counts")
    return (
        maximum == 1
        and reserved == 0
        and isinstance(counts, dict)
        and counts.get("planned", 0) + counts.get("ready", 0) > 0
    )


def attempt_key(repository: str, queue: Path, digest: str) -> str:
    payload = f"{repository}\0{queue.resolve()}\0{digest}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def queue_candidates(config: dict[str, Any]) -> list[tuple[dict[str, Any], Path]]:
    values: list[tuple[dict[str, Any], Path]] = []
    for repository in config["repositories"]:
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
    for repository, queue in queue_candidates(config):
        inspected = inspect_queue(config, repository, queue, command)
        if not actionable_queue(inspected):
            continue
        digest = inspected.get("approval_digest")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            continue
        key = attempt_key(repository["repository"], queue, digest)
        if key in ledger["attempts"]:
            continue
        ledger["attempts"][key] = {
            "at": utc_now(),
            "queue_id": inspected.get("queue_id"),
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
    payload = {
        "Label": args.label,
        "ProgramArguments": [
            sys.executable,
            str((ROOT / "scripts/u2_user_runner.py").resolve()),
            "serve",
            "--config",
            str(args.config.resolve()),
        ],
        "RunAtLoad": True,
        "KeepAlive": True,
        "ThrottleInterval": max(30, config["poll_seconds"]),
        "StandardOutPath": str(state / "runner.stdout.log"),
        "StandardErrorPath": str(state / "runner.stderr.log"),
        "ProcessType": "Background",
    }
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
