#!/usr/bin/env python3

from __future__ import annotations

import copy
import datetime as dt
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).with_name("u2_activation_readiness.py")
SPEC = importlib.util.spec_from_file_location("u2_activation_readiness", MODULE_PATH)
assert SPEC and SPEC.loader
readiness = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(readiness)

NOW = dt.datetime(2026, 7, 22, 12, 0, tzinfo=dt.timezone.utc)
SHA = "a" * 40
KEY = "controller-key-that-is-longer-than-thirty-two-bytes"
PUBLIC_KEY = b"test-pinned-public-key"


def active_config() -> dict:
    value = copy.deepcopy(readiness.worker.load_config())
    value["status"] = "approved_active"
    value["activation"].update(
        {
            "enabled": True,
            "enabled_roles": ["repository_reviewer", "scoped_maker"],
            "approved_by": "user",
            "approved_at": "2026-07-22T11:00:00Z",
            "expires_at": "2026-07-23T11:00:00Z",
        }
    )
    value["approver"]["public_key_sha256"] = hashlib.sha256(PUBLIC_KEY).hexdigest()
    return value


class ActivationReadinessTests(unittest.TestCase):
    def write_config(self, directory: str, value: dict) -> Path:
        path = Path(directory) / "config.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def test_checked_in_packet_stays_paused_and_never_exposes_values(self):
        environment = {
            "U2_EXECUTOR_TRUSTED_SHA": "b" * 40,
            "TREEXCHANGE_U2_CONTROLLER_KEY": "short",
        }
        with mock.patch.object(readiness.bridge, "exact_commit", return_value=SHA):
            with mock.patch.object(readiness.shutil, "which", return_value="/usr/bin/claude"):
                with mock.patch.object(readiness.bridge, "require_local_claude_runtime"):
                    result = readiness.assess(environ=environment, now=NOW)
        self.assertEqual(result["status"], "PAUSED_NOT_READY")
        self.assertIn("U2_ACTIVATION_PACKET_NOT_INSTALLED", result["blockers"])
        rendered = json.dumps(result)
        self.assertNotIn(environment["TREEXCHANGE_U2_CONTROLLER_KEY"], rendered)
        self.assertFalse(result["claim_boundary"]["makes_model_call"])

    def test_exact_maker_and_reviewer_packet_can_be_ready(self):
        with tempfile.TemporaryDirectory() as directory:
            public_key = Path(directory) / "approval-public.pem"
            public_key.write_bytes(PUBLIC_KEY)
            path = self.write_config(directory, active_config())
            environment = {
                "U2_EXECUTOR_TRUSTED_SHA": SHA,
                "TREEXCHANGE_U2_CONTROLLER_KEY": KEY,
                "TREEXCHANGE_U2_APPROVAL_PUBLIC_KEY_PATH": str(public_key),
            }
            with mock.patch.object(readiness.bridge, "exact_commit", return_value=SHA):
                with mock.patch.object(readiness.shutil, "which", return_value="/usr/bin/claude"):
                    with mock.patch.object(readiness.bridge, "require_local_claude_runtime"):
                        result = readiness.assess(path, environ=environment, now=NOW)
        self.assertEqual(result["status"], "READY_FOR_U2_WORK")
        self.assertEqual(result["blockers"], [])

    def test_operational_activation_rejects_reviewer_only_mode(self):
        config = active_config()
        config["activation"]["enabled_roles"] = ["repository_reviewer"]
        with tempfile.TemporaryDirectory() as directory:
            public_key = Path(directory) / "approval-public.pem"
            public_key.write_bytes(PUBLIC_KEY)
            path = self.write_config(directory, config)
            environment = {
                "U2_EXECUTOR_TRUSTED_SHA": SHA,
                "TREEXCHANGE_U2_CONTROLLER_KEY": KEY,
                "TREEXCHANGE_U2_APPROVAL_PUBLIC_KEY_PATH": str(public_key),
            }
            with mock.patch.object(readiness.bridge, "exact_commit", return_value=SHA):
                with mock.patch.object(readiness.shutil, "which", return_value="/usr/bin/claude"):
                    with mock.patch.object(readiness.bridge, "require_local_claude_runtime"):
                        result = readiness.assess(path, environ=environment, now=NOW)
        self.assertIn("MAKER_AND_REVIEWER_ROLES_NOT_ENABLED", result["blockers"])

    def test_ready_packet_rejects_a_public_key_that_misses_the_approved_pin(self):
        with tempfile.TemporaryDirectory() as directory:
            public_key = Path(directory) / "approval-public.pem"
            public_key.write_bytes(b"different-public-key")
            path = self.write_config(directory, active_config())
            environment = {
                "U2_EXECUTOR_TRUSTED_SHA": SHA,
                "TREEXCHANGE_U2_CONTROLLER_KEY": KEY,
                "TREEXCHANGE_U2_APPROVAL_PUBLIC_KEY_PATH": str(public_key),
            }
            with mock.patch.object(readiness.bridge, "exact_commit", return_value=SHA):
                with mock.patch.object(readiness.shutil, "which", return_value="/usr/bin/claude"):
                    with mock.patch.object(readiness.bridge, "require_local_claude_runtime"):
                        result = readiness.assess(path, environ=environment, now=NOW)
        self.assertIn(
            "APPROVER_PUBLIC_KEY_UNAVAILABLE_OR_UNPINNED", result["blockers"]
        )


if __name__ == "__main__":
    unittest.main()
