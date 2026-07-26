#!/usr/bin/env python3
"""Create one canonical paused U2 queue from a bounded task manifest.

This command records routing; it never releases work or invokes Claude.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import local_claude_bridge as bridge
import local_claude_worker as worker
import u2_controller as controller


DENY = 77
INVALID = 78
MANIFEST_FIELDS = {"schema_version", "queue_id", "repository", "origin", "item"}
ITEM_FIELDS = {
    "work_item_id",
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
    "window_id",
}


class IntakeError(Exception):
    def __init__(self, message: str, code: int = DENY):
        super().__init__(message)
        self.code = code


def fail(message: str, code: int = DENY) -> None:
    raise IntakeError(message, code)


def git(repo: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=repo,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=30,
        check=False,
    )
    if completed.returncode != 0:
        fail("task intake could not resolve exact Git evidence")
    return completed.stdout.strip()


def load_manifest(repo: Path, path: Path) -> dict[str, Any]:
    try:
        resolved = worker.private_agent_path(
            repo, path, "U2 task manifest", must_exist=True
        )
        value = worker.load_json(resolved, "U2 task manifest")
    except worker.WorkerError as error:
        fail(str(error), error.code)
    if set(value) != MANIFEST_FIELDS or value.get("schema_version") != 1:
        fail("U2 task manifest contract drifted", INVALID)
    return value


def require_exact_repository_state(repo: Path, manifest: dict[str, Any]) -> None:
    item = manifest["item"]
    if bridge.repository_identity(repo) != manifest["repository"]:
        fail("task manifest repository does not match its worktree", INVALID)
    if git(repo, "symbolic-ref", "--quiet", "--short", "HEAD") != item["branch"]:
        fail("task manifest branch is not checked out exactly", INVALID)
    if git(repo, "rev-parse", "HEAD") != item["target_sha"]:
        fail("task manifest target SHA is not the exact checked-out Head", INVALID)
    if git(repo, "status", "--porcelain", "--untracked-files=all"):
        fail("task intake requires a clean exact worktree; create a scoped snapshot first", INVALID)
    if git(repo, "rev-parse", "--verify", f"{item['base_sha']}^{{commit}}") != item["base_sha"]:
        fail("task manifest base SHA is unavailable", INVALID)
    ancestor = subprocess.run(
        ["git", "merge-base", "--is-ancestor", item["base_sha"], item["target_sha"]],
        cwd=repo,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=30,
        check=False,
    )
    if ancestor.returncode != 0:
        fail("task manifest Base is not an ancestor of Head", INVALID)


def validate_manifest(repo: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    if not controller.QUEUE_ID_RE.fullmatch(manifest.get("queue_id", "")):
        fail("task manifest queue id is invalid", INVALID)
    if manifest.get("repository") not in bridge.ALLOWED_REPOSITORIES:
        fail("task manifest repository is outside the fixed allowlist", INVALID)
    try:
        controller.validate_origin(manifest.get("origin"))
    except controller.ControllerError as error:
        fail(str(error), error.code)
    origin = manifest["origin"]
    if origin["requested_assignee"] != "Claude":
        fail("U2 task intake accepts only work explicitly assigned to Claude", INVALID)

    item = manifest.get("item")
    if not isinstance(item, dict) or set(item) != ITEM_FIELDS:
        fail("U2 task item contract drifted", INVALID)
    role = item.get("role")
    intent = origin["intent"]
    if intent in {"review", "design_review", "advice"} and role != "repository_reviewer":
        fail("read-only Claude intents must use the Reviewer role", INVALID)
    if intent == "build" and role != "scoped_maker":
        fail("Claude build intent must use the Maker role", INVALID)
    if intent == "plan":
        fail("U2 has no Planner role; plan work must remain paused", INVALID)
    if intent == "design_review" and item.get("task_profile") != "design":
        fail("design review must use the design task profile", INVALID)
    if role == "repository_reviewer" and item.get("maximum_attempts") != 1:
        fail("user-directed Reviewer work permits one attempt and no retry", INVALID)

    queue = {
        "schema_version": 1,
        "queue_id": manifest["queue_id"],
        "status": "draft_paused",
        "repository": manifest["repository"],
        "origin": origin,
        "release": {
            "release_id": None,
            "approval_key_id": None,
            "approved_by": None,
            "approved_at": None,
            "expires_at": None,
            "allowed_roles": [],
            "maximum_operations": 0,
            "queue_digest": None,
            "release_signature": None,
        },
        "items": [
            {
                **item,
                "state": "planned",
                "attempts": 0,
                "request_id": None,
                "result": None,
            }
        ],
        "events": [],
    }
    try:
        controller.validate_queue(queue)
    except controller.ControllerError as error:
        fail(str(error), error.code)
    require_exact_repository_state(repo, manifest)
    return queue


def create(args: argparse.Namespace) -> None:
    repo = args.repo.resolve()
    manifest = load_manifest(repo, args.manifest)
    queue = validate_manifest(repo, manifest)
    destination = Path(".agent-state/u2-queues") / f"{queue['queue_id']}.json"
    try:
        path = worker.private_agent_path(
            repo, destination, "U2 drafted queue", must_exist=False
        )
        bridge.save_private_json(path, queue)
    except (worker.WorkerError, bridge.BridgeError) as error:
        fail(str(error), getattr(error, "code", DENY))
    print(
        json.dumps(
            {
                "status": "DRAFTED_PAUSED",
                "queue_id": queue["queue_id"],
                "directive_id": queue["origin"]["directive_id"],
                "requested_assignee": queue["origin"]["requested_assignee"],
                "intent": queue["origin"]["intent"],
                "role": queue["items"][0]["role"],
                "target_sha": queue["items"][0]["target_sha"],
                "approval_digest": controller.approval_digest(queue),
                "queue": path.relative_to(repo).as_posix(),
                "released": False,
            },
            ensure_ascii=False,
            separators=(",", ":"),
        )
    )


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--repo", type=Path, required=True)
    value.add_argument("--manifest", type=Path, required=True)
    value.set_defaults(handler=create)
    return value


def main() -> int:
    args = parser().parse_args()
    try:
        args.handler(args)
    except (IntakeError, controller.ControllerError) as error:
        print(f"DENY: {error}", file=sys.stderr)
        return getattr(error, "code", DENY)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
