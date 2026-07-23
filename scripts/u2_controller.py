#!/usr/bin/env python3
"""Deterministic private queue controller for local U2 Maker and Reviewer lanes."""

from __future__ import annotations

import argparse
import base64
import contextlib
import datetime as dt
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any, Mapping

import local_claude_bridge as bridge
import local_claude_worker as worker
import u1_executor


DENY = 77
INVALID = 78
ROOT = Path(__file__).parents[1]
QUEUE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{7,95}$")
QUEUE_FIELDS = {
    "schema_version",
    "queue_id",
    "status",
    "repository",
    "release",
    "items",
    "events",
}
RELEASE_FIELDS = {
    "release_id",
    "approval_key_id",
    "approved_by",
    "approved_at",
    "expires_at",
    "allowed_roles",
    "maximum_operations",
    "queue_digest",
    "release_signature",
}
ED25519_SIGNATURE_RE = re.compile(r"^[A-Za-z0-9+/]{86}==$")
ITEM_FIELDS = {
    "work_item_id",
    "state",
    "depends_on",
    "role",
    "branch",
    "base_sha",
    "target_sha",
    "task_profile",
    "objective",
    "acceptance_criteria",
    "read_paths",
    "allowed_paths",
    "maximum_turns",
    "maximum_attempts",
    "attempts",
    "window_id",
    "request_id",
    "result",
}
EVENT_FIELDS = {
    "event_id",
    "at",
    "type",
    "work_item_id",
    "request_id",
    "state",
    "detail_code",
}
RESULT_FIELDS = {
    "verdict",
    "summary",
    "output_path",
    "request_digest",
    "target_sha",
    "completed_at",
}
ITEM_STATES = {
    "planned",
    "ready",
    "running",
    "completed",
    "changes_requested",
    "failed",
}
EVENT_TYPES = {
    "model_reserved",
    "review_completed",
    "review_changes_requested",
    "maker_completed",
    "maker_blocked",
    "run_failed",
}
MUTABLE_ITEM_FIELDS = {"state", "attempts", "request_id", "result"}


class ControllerError(Exception):
    def __init__(self, message: str, code: int = DENY):
        super().__init__(message)
        self.code = code


def fail(message: str, code: int = DENY) -> None:
    raise ControllerError(message, code)


def parse_utc(value: Any, label: str) -> dt.datetime:
    try:
        return worker.parse_utc(value, label)
    except worker.WorkerError as error:
        fail(str(error), error.code)


def queue_path(repo: Path, path: Path, *, must_exist: bool) -> Path:
    try:
        return worker.private_agent_path(repo, path, "U2 controller queue", must_exist=must_exist)
    except worker.WorkerError as error:
        fail(str(error), error.code)


def load_queue(repo: Path, path: Path) -> tuple[Path, dict[str, Any]]:
    resolved = queue_path(repo, path, must_exist=True)
    try:
        value = worker.load_json(resolved, "U2 controller queue")
    except worker.WorkerError as error:
        fail(str(error), error.code)
    validate_queue(value)
    return resolved, value


def valid_result(value: Any, state: str, role: str) -> bool:
    if not isinstance(value, dict) or set(value) != RESULT_FIELDS:
        return False
    verdict = value.get("verdict")
    if role == "repository_reviewer":
        expected = "APPROVE" if state == "completed" else "CHANGES_REQUESTED"
    else:
        expected = "DONE" if state == "completed" else "BLOCKED"
    return (
        verdict == expected
        and isinstance(value.get("summary"), str)
        and 0 < len(value["summary"]) <= 1000
        and isinstance(value.get("output_path"), str)
        and value["output_path"].startswith(".agent-state/")
        and worker.SIGNATURE_RE.fullmatch(value.get("request_digest", "")) is not None
        and u1_executor.SHA_RE.fullmatch(value.get("target_sha", "")) is not None
        and isinstance(value.get("completed_at"), str)
    )


def validate_queue(value: dict[str, Any]) -> None:
    if set(value) != QUEUE_FIELDS or value.get("schema_version") != 1:
        fail("U2 controller queue contract drifted", INVALID)
    if not QUEUE_ID_RE.fullmatch(value.get("queue_id", "")):
        fail("U2 queue id is invalid", INVALID)
    if value.get("status") not in {"draft_paused", "released"}:
        fail("U2 queue status is invalid", INVALID)
    if value.get("repository") not in bridge.ALLOWED_REPOSITORIES:
        fail("U2 queue repository is outside the fixed allowlist", INVALID)

    release = value.get("release")
    if not isinstance(release, dict) or set(release) != RELEASE_FIELDS:
        fail("U2 queue release contract drifted", INVALID)
    if value["status"] == "draft_paused":
        expected = {
            "release_id": None,
            "approval_key_id": None,
            "approved_by": None,
            "approved_at": None,
            "expires_at": None,
            "allowed_roles": [],
            "maximum_operations": 0,
            "queue_digest": None,
            "release_signature": None,
        }
        if release != expected:
            fail("paused U2 queue release must remain empty", INVALID)
    else:
        if not worker.CONTROL_EVIDENCE_RE.fullmatch(release.get("release_id", "")):
            fail("U2 release id is invalid", INVALID)
        if release.get("approval_key_id") != "u2-attended-approval-v1":
            fail("U2 attended approval key id is invalid", INVALID)
        if not isinstance(release.get("approved_by"), str) or not release["approved_by"].strip():
            fail("released U2 queue requires an approval identity", INVALID)
        approved = parse_utc(release.get("approved_at"), "release.approved_at")
        expires = parse_utc(release.get("expires_at"), "release.expires_at")
        if not dt.timedelta(0) < expires - approved <= dt.timedelta(days=7):
            fail("U2 queue release window must be positive and at most seven days", INVALID)
        allowed_roles = release.get("allowed_roles")
        if (
            not isinstance(allowed_roles, list)
            or not allowed_roles
            or allowed_roles != sorted(set(allowed_roles))
            or any(role not in {"repository_reviewer", "scoped_maker"} for role in allowed_roles)
        ):
            fail("U2 queue release roles are invalid", INVALID)
        maximum = release.get("maximum_operations")
        if (
            not isinstance(maximum, int)
            or isinstance(maximum, bool)
            or not 1 <= maximum <= 7
        ):
            fail("U2 queue release must authorize between one and seven operations", INVALID)
        if not worker.SIGNATURE_RE.fullmatch(release.get("queue_digest", "")):
            fail("U2 queue approval digest is invalid", INVALID)
        if not ED25519_SIGNATURE_RE.fullmatch(release.get("release_signature", "")):
            fail("U2 queue release signature is invalid", INVALID)

    items = value.get("items")
    if not isinstance(items, list) or not 1 <= len(items) <= 50:
        fail("U2 queue must contain between one and fifty work items", INVALID)
    item_ids: set[str] = set()
    for item in items:
        if not isinstance(item, dict) or set(item) != ITEM_FIELDS:
            fail("U2 queue work-item contract drifted", INVALID)
        work_item_id = item.get("work_item_id")
        if not bridge.WORK_ITEM_RE.fullmatch(work_item_id or "") or work_item_id in item_ids:
            fail("U2 queue work-item id is invalid or duplicated", INVALID)
        item_ids.add(work_item_id)
        if item.get("state") not in ITEM_STATES:
            fail("U2 queue work-item state is invalid", INVALID)
        role = item.get("role")
        if role not in {"repository_reviewer", "scoped_maker"}:
            fail("U2 queue role is invalid", INVALID)
        if value["status"] == "released" and role not in release["allowed_roles"]:
            fail("U2 queue item role is outside the attended release", INVALID)
        if item.get("task_profile") not in bridge.MODEL_BY_TASK_PROFILE:
            fail("U2 queue task profile is invalid", INVALID)
        branch = item.get("branch")
        branch_pattern = worker.REVIEW_BRANCH_RE if role == "repository_reviewer" else worker.MAKER_BRANCH_RE
        if (
            not isinstance(branch, str)
            or not branch_pattern.fullmatch(branch)
            or branch in {"main", "master"}
            or "//" in branch
            or any(part in {"", ".", ".."} for part in branch.split("/"))
        ):
            fail("U2 queue branch is invalid for its role", INVALID)
        for name in ("base_sha", "target_sha"):
            if not u1_executor.SHA_RE.fullmatch(item.get(name, "")):
                fail(f"U2 queue {name} is invalid", INVALID)
        if role == "repository_reviewer" and item["base_sha"] == item["target_sha"]:
            fail("U2 queue Reviewer requires a non-empty commit range", INVALID)
        if role == "scoped_maker" and item["base_sha"] != item["target_sha"]:
            fail("U2 queue Maker must start from one exact unchanged Head", INVALID)
        objective = item.get("objective")
        if not isinstance(objective, str) or objective != objective.strip() or not objective or len(objective) > 4000:
            fail("U2 queue objective is invalid", INVALID)
        for name, maximum, minimum, maximum_length in (
            ("acceptance_criteria", 12, 1, 1000),
            ("read_paths", 24, 0, 240),
            ("allowed_paths", 16, 1, 240),
        ):
            entries = item.get(name)
            if (
                not isinstance(entries, list)
                or not minimum <= len(entries) <= maximum
                or len(entries) != len(set(entries))
                or any(
                    not isinstance(entry, str)
                    or not entry
                    or len(entry) > maximum_length
                    for entry in entries
                )
            ):
                fail(f"U2 queue {name} is invalid", INVALID)
        for scope in [*item["read_paths"], *item["allowed_paths"]]:
            try:
                worker.normalize_scope_path(scope, "queue scope")
            except worker.WorkerError as error:
                fail(str(error), error.code)
        if role == "scoped_maker" and not item["read_paths"]:
            fail("U2 queue Maker requires readable context", INVALID)
        maximum_turns = item.get("maximum_turns")
        if (
            not isinstance(maximum_turns, int)
            or isinstance(maximum_turns, bool)
            or not 1 <= maximum_turns <= 8
        ):
            fail("U2 queue turn cap is invalid", INVALID)
        dependencies = item.get("depends_on")
        if (
            not isinstance(dependencies, list)
            or len(dependencies) != len(set(dependencies))
            or any(not bridge.WORK_ITEM_RE.fullmatch(dep or "") for dep in dependencies)
        ):
            fail("U2 queue dependencies are invalid", INVALID)
        attempts = item.get("attempts")
        maximum_attempts = item.get("maximum_attempts")
        if (
            not isinstance(attempts, int)
            or isinstance(attempts, bool)
            or attempts < 0
            or not isinstance(maximum_attempts, int)
            or isinstance(maximum_attempts, bool)
            or not 1 <= maximum_attempts <= 2
            or attempts > maximum_attempts
        ):
            fail("U2 queue attempt counters are invalid", INVALID)
        if not bridge.REVIEW_WINDOW_RE.fullmatch(item.get("window_id", "")):
            fail("U2 queue review window is invalid", INVALID)
        state = item["state"]
        request_id = item.get("request_id")
        result = item.get("result")
        if state in {"planned", "ready"} and (request_id is not None or result is not None):
            fail("unstarted U2 work cannot claim a request or result", INVALID)
        if state in {"running", "completed", "changes_requested", "failed"}:
            if not worker.REQUEST_ID_RE.fullmatch(request_id or "") or attempts < 1:
                fail("started U2 work requires an exact request id and attempt", INVALID)
        if state in {"completed", "changes_requested"} and not valid_result(result, state, role):
            fail("finished U2 result is invalid", INVALID)
        if state == "failed" and result is not None:
            fail("failed U2 work cannot claim a successful result", INVALID)

    by_id = {item["work_item_id"]: item for item in items}
    for item in items:
        if item["work_item_id"] in item["depends_on"] or any(
            dependency not in by_id for dependency in item["depends_on"]
        ):
            fail("U2 queue dependency is missing or self-referential", INVALID)

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(identifier: str) -> None:
        if identifier in visiting:
            fail("U2 queue dependencies contain a cycle", INVALID)
        if identifier in visited:
            return
        visiting.add(identifier)
        for dependency in by_id[identifier]["depends_on"]:
            visit(dependency)
        visiting.remove(identifier)
        visited.add(identifier)

    for identifier in by_id:
        visit(identifier)

    if value["status"] == "released":
        released_roles = sorted({item["role"] for item in items})
        if release["allowed_roles"] != released_roles:
            fail("U2 release roles do not match the immutable queue", INVALID)
        if release["maximum_operations"] != len(items) or len(items) > 7:
            fail("U2 release operation cap must equal its one-to-seven item queue", INVALID)

    events = value.get("events")
    if not isinstance(events, list) or len(events) > 500:
        fail("U2 queue event ledger is invalid", INVALID)
    event_ids: set[str] = set()
    for event in events:
        if not isinstance(event, dict) or set(event) != EVENT_FIELDS:
            fail("U2 queue event contract drifted", INVALID)
        if not QUEUE_ID_RE.fullmatch(event.get("event_id", "")) or event["event_id"] in event_ids:
            fail("U2 queue event id is invalid or duplicated", INVALID)
        event_ids.add(event["event_id"])
        parse_utc(event.get("at"), "event.at")
        if event.get("type") not in EVENT_TYPES or event.get("state") not in ITEM_STATES:
            fail("U2 queue event type or state is invalid", INVALID)
        if event.get("work_item_id") not in item_ids:
            fail("U2 queue event references an unknown work item", INVALID)
        if event.get("request_id") is not None and not worker.REQUEST_ID_RE.fullmatch(event["request_id"]):
            fail("U2 queue event request id is invalid", INVALID)
        if not isinstance(event.get("detail_code"), str) or not event["detail_code"]:
            fail("U2 queue event detail code is invalid", INVALID)
    if value["status"] == "draft_paused" and (
        events
        or any(item["attempts"] != 0 or item["state"] not in {"planned", "ready"} for item in items)
    ):
        fail("paused U2 queue cannot contain execution evidence", INVALID)


def release_is_current(queue: dict[str, Any], now: dt.datetime) -> None:
    if queue["status"] != "released":
        fail("U2 controller queue remains paused")
    release = queue["release"]
    approved = parse_utc(release["approved_at"], "release.approved_at")
    expires = parse_utc(release["expires_at"], "release.expires_at")
    if not approved <= now < expires:
        fail("U2 controller queue is outside its approved release window")
    used = sum(1 for event in queue["events"] if event["type"] == "model_reserved")
    if used >= release["maximum_operations"]:
        fail("U2 controller queue operation cap has been reached")


def immutable_item(item: dict[str, Any]) -> dict[str, Any]:
    return {key: item[key] for key in sorted(ITEM_FIELDS - MUTABLE_ITEM_FIELDS)}


def approval_digest(queue: dict[str, Any]) -> str:
    payload = {
        "schema_version": queue["schema_version"],
        "queue_id": queue["queue_id"],
        "repository": queue["repository"],
        "items": [immutable_item(item) for item in queue["items"]],
    }
    encoded = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def release_payload(queue: dict[str, Any]) -> bytes:
    release = queue["release"]
    value = {
        "schema_version": queue["schema_version"],
        "queue_id": queue["queue_id"],
        "repository": queue["repository"],
        "release_id": release["release_id"],
        "approval_key_id": release["approval_key_id"],
        "approved_by": release["approved_by"],
        "approved_at": release["approved_at"],
        "expires_at": release["expires_at"],
        "allowed_roles": release["allowed_roles"],
        "maximum_operations": release["maximum_operations"],
        "queue_digest": release["queue_digest"],
    }
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def run_openssl(
    arguments: list[str], *, pass_fds: tuple[int, ...] = ()
) -> subprocess.CompletedProcess[bytes]:
    executable = shutil.which("openssl")
    if executable is None:
        fail("OpenSSL is unavailable for attended U2 release verification")
    try:
        return subprocess.run(
            [executable, *arguments],
            capture_output=True,
            check=False,
            env={"PATH": os.defpath, "LANG": "C"},
            pass_fds=pass_fds,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        fail("OpenSSL could not process the attended U2 release")


def secure_private_key_bytes(path: Path) -> bytes:
    expanded = path.expanduser()
    descriptor: int | None = None
    try:
        initial = expanded.lstat()
        if stat.S_ISLNK(initial.st_mode):
            fail("U2 attended approval private key must be owner-only and non-symlink")
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(expanded, flags)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) & 0o077
            or not 1 <= metadata.st_size <= 16_384
        ):
            fail("U2 attended approval private key must be owner-only and non-symlink")
        value_buffer = bytearray()
        while len(value_buffer) <= 16_384:
            chunk = os.read(descriptor, 16_385 - len(value_buffer))
            if not chunk:
                break
            value_buffer.extend(chunk)
        value = bytes(value_buffer)
        final = expanded.lstat()
    except OSError:
        fail("U2 attended approval private key is unavailable")
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
    if (
        len(value) != metadata.st_size
        or not stat.S_ISREG(final.st_mode)
        or final.st_dev != metadata.st_dev
        or final.st_ino != metadata.st_ino
        or final.st_nlink != 1
    ):
        fail("U2 attended approval private key changed during inspection")
    return value


def ed25519_signature(payload: bytes, private_key: Path) -> bytes:
    private_key_bytes = secure_private_key_bytes(private_key)
    with tempfile.TemporaryFile() as message, tempfile.TemporaryFile() as isolated_key:
        message.write(payload)
        message.flush()
        message.seek(0)
        isolated_key.write(private_key_bytes)
        isolated_key.flush()
        isolated_key.seek(0)
        message_descriptor = message.fileno()
        key_descriptor = isolated_key.fileno()
        completed = run_openssl(
            [
                "pkeyutl",
                "-sign",
                "-inkey",
                f"/dev/fd/{key_descriptor}",
                "-rawin",
                "-in",
                f"/dev/fd/{message_descriptor}",
            ],
            pass_fds=(key_descriptor, message_descriptor),
        )
    if completed.returncode != 0 or len(completed.stdout) != 64:
        fail("U2 attended release could not be signed by the approved key")
    return completed.stdout


def ed25519_verify(payload: bytes, signature: bytes, public_key: bytes) -> None:
    with tempfile.TemporaryDirectory(prefix="u2-release-verify-") as directory:
        root = Path(directory)
        message = root / "release.payload"
        signature_path = root / "release.signature"
        public_path = root / "approval-public.pem"
        for path, content in (
            (message, payload),
            (signature_path, signature),
            (public_path, public_key),
        ):
            path.write_bytes(content)
            os.chmod(path, 0o600)
        completed = run_openssl(
            [
                "pkeyutl",
                "-verify",
                "-pubin",
                "-inkey",
                str(public_path),
                "-rawin",
                "-in",
                str(message),
                "-sigfile",
                str(signature_path),
            ]
        )
    if completed.returncode != 0:
        fail("U2 queue attended release signature verification failed")


def verify_release_signature(queue: dict[str, Any], public_key: bytes) -> None:
    release = queue["release"]
    if release["queue_digest"] != approval_digest(queue):
        fail("U2 queue changed after its approved digest was signed")
    try:
        signature = base64.b64decode(release["release_signature"], validate=True)
    except (ValueError, TypeError):
        fail("U2 queue attended release signature is malformed")
    if len(signature) != 64:
        fail("U2 queue attended release signature is malformed")
    ed25519_verify(release_payload(queue), signature, public_key)


def release_claim_path(
    repo: Path,
    queue: dict[str, Any],
    work_item_id: str,
    *,
    prepare: bool = False,
) -> Path:
    state_root = bridge.shared_ledger_path(repo).parent
    claims = state_root / "u2-release-claims"
    if prepare or claims.exists() or claims.is_symlink():
        try:
            if prepare:
                state_root.mkdir(mode=0o700, parents=True, exist_ok=True)
                claims.mkdir(mode=0o700, exist_ok=True)
            metadata = claims.lstat()
        except OSError:
            fail("U2 external release-claim directory is unavailable")
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            fail("U2 external release-claim directory must remain owner-only")
    identity = hashlib.sha256(
        release_payload(queue)
        + queue["release"]["release_signature"].encode("ascii")
        + b"\0"
        + work_item_id.encode("utf-8")
    ).hexdigest()
    return claims / f"{identity}.json"


def claim_release_once(
    repo: Path,
    queue: dict[str, Any],
    request: dict[str, Any],
    now: dt.datetime,
) -> Path:
    path = release_claim_path(
        repo, queue, request["work_item_id"], prepare=True
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags, 0o600)
        receipt = json.dumps(
            {
                "schema_version": 1,
                "repository": queue["repository"],
                "queue_id": queue["queue_id"],
                "release_id": queue["release"]["release_id"],
                "queue_digest": queue["release"]["queue_digest"],
                "request_id": request["request_id"],
                "work_item_id": request["work_item_id"],
                "claimed_at": now.isoformat().replace("+00:00", "Z"),
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        written = 0
        while written < len(receipt):
            written += os.write(descriptor, receipt[written:])
        os.fsync(descriptor)
    except FileExistsError:
        fail("U2 attended release has already been consumed")
    except OSError:
        fail("U2 external release claim could not be recorded")
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
    return path


def select_next(queue: dict[str, Any]) -> dict[str, Any]:
    completed = {
        item["work_item_id"] for item in queue["items"] if item["state"] == "completed"
    }
    for item in queue["items"]:
        if (
            item["state"] in {"planned", "ready"}
            and set(item["depends_on"]).issubset(completed)
            and item["attempts"] < item["maximum_attempts"]
        ):
            return item
    fail("U2 controller queue has no dependency-ready work")


def signing_key(config: dict[str, Any], environ: Mapping[str, str]) -> str:
    controller = config["controller"]
    value = environ.get(controller["key_environment"])
    if not isinstance(value, str) or len(value.encode("utf-8")) < controller["minimum_key_bytes"]:
        fail("U2 controller signing key is unavailable or too short")
    return value


def build_request(
    queue: dict[str, Any],
    item: dict[str, Any],
    config: dict[str, Any],
    key: str,
    now: dt.datetime,
) -> dict[str, Any]:
    release_expiry = parse_utc(queue["release"]["expires_at"], "release.expires_at")
    request_expiry = min(release_expiry, now + dt.timedelta(minutes=30))
    identifier = item["work_item_id"].lower()
    request: dict[str, Any] = {
        "schema_version": 1,
        "request_id": f"u2-{identifier}-{uuid.uuid4().hex[:12]}",
        "work_item_id": item["work_item_id"],
        "window_id": item["window_id"],
        "role": item["role"],
        "repository": queue["repository"],
        "branch": item["branch"],
        "base_sha": item["base_sha"],
        "target_sha": item["target_sha"],
        "risk_class": "low",
        "task_profile": item["task_profile"],
        "objective": item["objective"],
        "acceptance_criteria": item["acceptance_criteria"],
        "read_paths": item["read_paths"],
        "allowed_paths": item["allowed_paths"],
        "maximum_turns": item["maximum_turns"],
        "expires_at": request_expiry.isoformat().replace("+00:00", "Z"),
        "control_release_id": queue["release"]["release_id"],
        "budget_reservation_id": f"budget-{uuid.uuid4().hex}",
        "controller_key_id": config["controller"]["key_id"],
        "nonce": secrets.token_hex(16),
        "controller_signature": "0" * 64,
    }
    request["controller_signature"] = hmac.new(
        key.encode("utf-8"), worker.canonical_request(request), hashlib.sha256
    ).hexdigest()
    return worker.validate_request(request, config, now)


def event(
    event_type: str,
    item: dict[str, Any],
    request_id: str | None,
    state: str,
    detail_code: str,
    now: dt.datetime,
) -> dict[str, Any]:
    return {
        "event_id": f"event-{uuid.uuid4().hex}",
        "at": now.isoformat().replace("+00:00", "Z"),
        "type": event_type,
        "work_item_id": item["work_item_id"],
        "request_id": request_id,
        "state": state,
        "detail_code": detail_code,
    }


def relative_private_path(repo: Path, path: Path) -> str:
    return path.resolve().relative_to(repo.resolve()).as_posix()


def validate_worker_output(
    repo: Path,
    output_path: Path,
    request: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    try:
        output = worker.load_json(output_path, "U2 worker output")
    except worker.WorkerError as error:
        fail(str(error), error.code)
    if (
        output.get("schema_version") != 1
        or output.get("request_id") != request["request_id"]
        or output.get("request_digest") != worker.request_digest(request)
        or output.get("work_item_id") != request["work_item_id"]
        or output.get("role") != request["role"]
        or output.get("repository") != request["repository"]
        or output.get("base_sha") != request["base_sha"]
        or output.get("target_sha") != request["target_sha"]
    ):
        fail("U2 worker output is not bound to the reserved request")
    result = output.get("result")
    if request["role"] == "repository_reviewer":
        if output.get("actual_changed_paths") != [] or output.get("change_digest") is not None:
            fail("U2 Reviewer output claims a source change")
        try:
            u1_executor.validate_result(result)
        except u1_executor.GateError as error:
            fail(f"U2 Reviewer result is invalid: {error}")
    else:
        try:
            result = worker.validate_maker_result(result)
        except worker.WorkerError as error:
            fail(f"U2 Maker result is invalid: {error}")
        changed_paths = output.get("actual_changed_paths")
        change_digest = output.get("change_digest")
        if result["status"] == "DONE":
            if (
                not isinstance(changed_paths, list)
                or not changed_paths
                or not worker.SIGNATURE_RE.fullmatch(change_digest or "")
            ):
                fail("U2 Maker output lacks machine-derived change evidence")
        elif changed_paths != [] or change_digest is not None:
            fail("BLOCKED U2 Maker output cannot retain source changes")
    return relative_private_path(repo, output_path), result


def finalize_failure(
    repo: Path,
    path: Path,
    work_item_id: str,
    request_id: str,
    detail_code: str,
) -> None:
    try:
        resolved, queue = load_queue(repo, path)
        with bridge.locked_ledger(resolved):
            queue = worker.load_json(resolved, "U2 controller queue")
            validate_queue(queue)
            matches = [item for item in queue["items"] if item["work_item_id"] == work_item_id]
            if len(matches) != 1 or matches[0].get("request_id") != request_id:
                fail("U2 failed run could not be rebound to its queue item")
            item = matches[0]
            item["state"] = "failed"
            item["result"] = None
            queue["events"].append(
                event("run_failed", item, request_id, "failed", detail_code, dt.datetime.now(dt.timezone.utc))
            )
            validate_queue(queue)
            bridge.save_private_json(resolved, queue)
    except (ControllerError, worker.WorkerError, bridge.BridgeError):
        return


def run_next(args: argparse.Namespace) -> None:
    worker.require_trusted_config_path(args.config)
    config = worker.load_config(args.config)
    worker.require_activation(config)
    repo = args.repo.resolve()
    resolved = queue_path(repo, args.queue, must_exist=True)
    current = dt.datetime.now(dt.timezone.utc)
    key = signing_key(config, os.environ)
    approval_public_key = worker.approval_public_key_bytes(config, os.environ)

    with bridge.locked_ledger(resolved):
        queue = worker.load_json(resolved, "U2 controller queue")
        validate_queue(queue)
        if bridge.repository_identity(repo) != queue["repository"]:
            fail("U2 queue repository does not match the assigned worktree")
        verify_release_signature(queue, approval_public_key)
        release_is_current(queue, current)
        item = select_next(queue)
        worker.require_role_activation(config, item["role"])
        request = build_request(queue, item, config, key, current)
        claim_release_once(repo, queue, request, current)
        request_dir = repo / ".agent-state/u2-requests"
        request_path = request_dir / f"{request['request_id']}.json"
        request_path = worker.private_agent_path(repo, request_path, "U2 work request", must_exist=False)
        bridge.save_private_json(request_path, request)
        item["state"] = "running"
        item["attempts"] += 1
        item["request_id"] = request["request_id"]
        item["result"] = None
        queue["events"].append(
            event(
                "model_reserved",
                item,
                request["request_id"],
                "running",
                "REVIEW_RESERVED"
                if item["role"] == "repository_reviewer"
                else "MAKER_RESERVED",
                current,
            )
        )
        validate_queue(queue)
        bridge.save_private_json(resolved, queue)

    output_path = repo / ".agent-state/u2-results" / f"{request['request_id']}.json"
    output_path = worker.private_agent_path(repo, output_path, "U2 worker output", must_exist=False)
    worker_args = argparse.Namespace(
        repo=repo,
        request=request_path,
        output=output_path,
        ledger=bridge.shared_ledger_path(repo),
        config=args.config,
    )
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            worker.run(worker_args)
        output_relative, result = validate_worker_output(repo, output_path, request)
    except (
        ControllerError,
        worker.WorkerError,
        bridge.BridgeError,
        u1_executor.GateError,
    ) as error:
        detail = getattr(error, "failure_class", None) or type(error).__name__
        finalize_failure(repo, args.queue, item["work_item_id"], request["request_id"], detail)
        fail("U2 work run failed or was quarantined")

    finished = dt.datetime.now(dt.timezone.utc)
    if request["role"] == "repository_reviewer":
        outcome = result["verdict"]
        state = "completed" if outcome == "APPROVE" else "changes_requested"
        event_type = (
            "review_completed" if state == "completed" else "review_changes_requested"
        )
    else:
        outcome = result["status"]
        state = "completed" if outcome == "DONE" else "changes_requested"
        event_type = "maker_completed" if state == "completed" else "maker_blocked"
    with bridge.locked_ledger(resolved):
        queue = worker.load_json(resolved, "U2 controller queue")
        validate_queue(queue)
        verify_release_signature(queue, approval_public_key)
        approved = parse_utc(queue["release"]["approved_at"], "release.approved_at")
        expires = parse_utc(queue["release"]["expires_at"], "release.expires_at")
        if not approved <= finished < expires:
            fail("U2 queue release expired before the review result was accepted")
        matches = [entry for entry in queue["items"] if entry["work_item_id"] == item["work_item_id"]]
        if len(matches) != 1 or matches[0].get("request_id") != request["request_id"] or matches[0]["state"] != "running":
            fail("U2 completed run no longer matches its reserved queue item")
        queued_item = matches[0]
        queued_item["state"] = state
        queued_item["result"] = {
            "verdict": outcome,
            "summary": result["summary"],
            "output_path": output_relative,
            "request_digest": worker.request_digest(request),
            "target_sha": request["target_sha"],
            "completed_at": finished.isoformat().replace("+00:00", "Z"),
        }
        queue["events"].append(
            event(event_type, queued_item, request["request_id"], state, outcome, finished)
        )
        validate_queue(queue)
        bridge.save_private_json(resolved, queue)

    print(
        json.dumps(
            {
                "status": "WORK_COMPLETED" if state == "completed" else "CHANGES_REQUESTED",
                "queue_id": queue["queue_id"],
                "work_item_id": item["work_item_id"],
                "request_id": request["request_id"],
                "role": request["role"],
                "target_sha": request["target_sha"],
                "outcome": outcome,
                "verdict": outcome,
                "next_ready": any(
                    entry["state"] in {"planned", "ready"}
                    and set(entry["depends_on"]).issubset(
                        {done["work_item_id"] for done in queue["items"] if done["state"] == "completed"}
                    )
                    for entry in queue["items"]
                ),
            },
            separators=(",", ":"),
        )
    )


def inspect_queue(args: argparse.Namespace) -> None:
    repo = args.repo.resolve()
    _, queue = load_queue(repo, args.queue)
    counts = {state: 0 for state in sorted(ITEM_STATES)}
    for item in queue["items"]:
        counts[item["state"]] += 1
    completed = {
        item["work_item_id"] for item in queue["items"] if item["state"] == "completed"
    }
    next_item = next(
        (
            item
            for item in queue["items"]
            if item["state"] in {"planned", "ready"}
            and set(item["depends_on"]).issubset(completed)
            and item["attempts"] < item["maximum_attempts"]
        ),
        None,
    )
    print(
        json.dumps(
            {
                "status": queue["status"],
                "queue_id": queue["queue_id"],
                "repository": queue["repository"],
                "counts": counts,
                "next_ready": next_item is not None,
                "next_work_item_id": (
                    next_item["work_item_id"] if next_item is not None else None
                ),
                "next_role": next_item["role"] if next_item is not None else None,
                "operations_reserved": sum(
                    1 for event in queue["events"] if event["type"] == "model_reserved"
                ),
                "maximum_operations": queue["release"]["maximum_operations"],
                "approval_digest": approval_digest(queue),
                "external_release_claimed": (
                    queue["status"] == "released"
                    and next_item is not None
                    and release_claim_path(
                        repo, queue, next_item["work_item_id"]
                    ).exists()
                ),
            },
            separators=(",", ":"),
        )
    )


def release_queue(args: argparse.Namespace) -> None:
    worker.require_trusted_config_path(args.config)
    config = worker.load_config(args.config)
    worker.require_activation(config)
    approval_public_key = worker.approval_public_key_bytes(config, os.environ)
    repo = args.repo.resolve()
    resolved = queue_path(repo, args.queue, must_exist=True)
    current = dt.datetime.now(dt.timezone.utc)
    expires = parse_utc(args.expires_at, "expires_at")
    if not current < expires <= current + dt.timedelta(days=7):
        fail("U2 release expiry must be future and no more than seven days away", INVALID)
    with bridge.locked_ledger(resolved):
        queue = worker.load_json(resolved, "U2 controller queue")
        validate_queue(queue)
        if bridge.repository_identity(repo) != queue["repository"]:
            fail("U2 queue repository does not match the attended release worktree")
        if queue["status"] != "draft_paused":
            fail("only a paused U2 queue can receive an attended release")
        if len(queue["items"]) > 7:
            fail("one attended U2 release can contain at most seven work items")
        allowed_roles = sorted({item["role"] for item in queue["items"]})
        for role in allowed_roles:
            worker.require_role_activation(config, role)
        digest = approval_digest(queue)
        if not hmac.compare_digest(digest, args.expected_digest):
            fail("user-approved U2 queue digest does not match the current queue")
        queue["status"] = "released"
        queue["release"] = {
            "release_id": args.release_id,
            "approval_key_id": config["approver"]["key_id"],
            "approved_by": args.approved_by,
            "approved_at": current.isoformat().replace("+00:00", "Z"),
            "expires_at": expires.isoformat().replace("+00:00", "Z"),
            "allowed_roles": allowed_roles,
            "maximum_operations": len(queue["items"]),
            "queue_digest": digest,
            "release_signature": "A" * 86 + "==",
        }
        signature = ed25519_signature(release_payload(queue), args.approval_private_key)
        queue["release"]["release_signature"] = base64.b64encode(signature).decode("ascii")
        validate_queue(queue)
        verify_release_signature(queue, approval_public_key)
        bridge.save_private_json(resolved, queue)
    print(
        json.dumps(
            {
                "status": "RELEASED_BOUNDED_QUEUE",
                "queue_id": queue["queue_id"],
                "approval_digest": digest,
                "expires_at": queue["release"]["expires_at"],
                "allowed_roles": queue["release"]["allowed_roles"],
                "maximum_operations": queue["release"]["maximum_operations"],
            },
            separators=(",", ":"),
        )
    )


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    subparsers = value.add_subparsers(dest="command", required=True)
    inspect = subparsers.add_parser("inspect")
    inspect.add_argument("--repo", type=Path, required=True)
    inspect.add_argument("--queue", type=Path, required=True)
    inspect.set_defaults(handler=inspect_queue)
    release = subparsers.add_parser("release")
    release.add_argument("--repo", type=Path, required=True)
    release.add_argument("--queue", type=Path, required=True)
    release.add_argument("--config", type=Path, default=worker.CONFIG_PATH)
    release.add_argument("--expected-digest", required=True)
    release.add_argument("--approved-by", required=True)
    release.add_argument("--release-id", required=True)
    release.add_argument("--expires-at", required=True)
    release.add_argument("--approval-private-key", type=Path, required=True)
    release.set_defaults(handler=release_queue)
    run = subparsers.add_parser("run-next")
    run.add_argument("--repo", type=Path, required=True)
    run.add_argument("--queue", type=Path, required=True)
    run.add_argument("--config", type=Path, default=worker.CONFIG_PATH)
    run.set_defaults(handler=run_next)
    return value


def main() -> int:
    args = parser().parse_args()
    try:
        args.handler(args)
    except (ControllerError, worker.WorkerError, bridge.BridgeError, u1_executor.GateError) as error:
        print(f"DENY: {error}", file=sys.stderr)
        return getattr(error, "code", DENY)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
