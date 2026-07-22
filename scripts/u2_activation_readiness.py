#!/usr/bin/env python3
"""Read-only readiness check for the first local U2 Reviewer activation."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import shutil
from pathlib import Path
from typing import Any, Mapping

import local_claude_bridge as bridge
import local_claude_worker as worker


ROOT = Path(__file__).parents[1]
DENY = 77


def assess(
    config_path: Path = worker.CONFIG_PATH,
    environ: Mapping[str, str] | None = None,
    *,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    source = os.environ if environ is None else environ
    blockers: list[str] = []
    config = worker.load_config(config_path)
    running_sha = bridge.exact_commit(ROOT, "HEAD")

    claude_cli_available = shutil.which("claude") is not None
    if not claude_cli_available:
        blockers.append("CLAUDE_CLI_UNAVAILABLE")

    local_runtime_private = False
    if claude_cli_available:
        try:
            bridge.require_local_claude_runtime()
            local_runtime_private = True
        except bridge.BridgeError:
            blockers.append("CLAUDE_LOCAL_STATE_UNAVAILABLE")

    activation = config["activation"]
    trusted_sha = source.get(activation["trusted_sha_environment"])
    trusted_sha_matches = trusted_sha == running_sha
    if not trusted_sha_matches:
        blockers.append("EXACT_MERGED_SHA_NOT_EXTERNALLY_PINNED")

    controller = config["controller"]
    controller_key = source.get(controller["key_environment"])
    controller_key_available = (
        isinstance(controller_key, str)
        and len(controller_key.encode("utf-8")) >= controller["minimum_key_bytes"]
    )
    if not controller_key_available:
        blockers.append("CONTROLLER_KEY_UNAVAILABLE")

    approver_public_key_available = False
    try:
        worker.approval_public_key_bytes(config, source)
        approver_public_key_available = True
    except worker.WorkerError:
        blockers.append("APPROVER_PUBLIC_KEY_UNAVAILABLE_OR_UNPINNED")

    reviewer_only = activation.get("enabled_roles") == ["repository_reviewer"]
    if config["status"] != "approved_active" or activation.get("enabled") is not True:
        blockers.append("REVIEWER_ACTIVATION_PACKET_NOT_INSTALLED")
    elif not reviewer_only:
        blockers.append("INITIAL_MAKER_ROLE_MUST_REMAIN_DISABLED")
    else:
        try:
            worker.require_activation(dict(config), dict(source), now)
        except worker.WorkerError:
            blockers.append("ACTIVATION_WINDOW_OR_SHA_INVALID")

    blockers = sorted(set(blockers))
    return {
        "schema_version": 1,
        "status": "READY_FOR_FIRST_REVIEW" if not blockers else "PAUSED_NOT_READY",
        "running_sha": running_sha,
        "checks": {
            "config_valid": True,
            "claude_cli_available": claude_cli_available,
            "local_runtime_private": local_runtime_private,
            "trusted_sha_matches": trusted_sha_matches,
            "controller_key_available": controller_key_available,
            "approver_public_key_available": approver_public_key_available,
            "reviewer_only_activation": reviewer_only,
        },
        "first_activation_target": {
            "enabled_roles": ["repository_reviewer"],
            "scoped_maker_enabled": False,
            "maximum_window_days": worker.MAX_ACTIVATION_WINDOW_DAYS,
        },
        "blockers": blockers,
        "claim_boundary": {
            "makes_model_call": False,
            "changes_source": False,
            "changes_github": False,
            "clears_pause": False,
            "prints_secret_values": False,
        },
    }


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--config", type=Path, default=worker.CONFIG_PATH)
    return value


def main() -> int:
    args = parser().parse_args()
    try:
        result = assess(
            args.config,
        )
    except (worker.WorkerError, bridge.BridgeError) as error:
        print(json.dumps({"status": "INVALID", "error": str(error)}, separators=(",", ":")))
        return DENY
    print(json.dumps(result, separators=(",", ":")))
    return 0 if result["status"] == "READY_FOR_FIRST_REVIEW" else DENY


if __name__ == "__main__":
    raise SystemExit(main())
