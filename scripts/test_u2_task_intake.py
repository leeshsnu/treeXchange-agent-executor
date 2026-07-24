#!/usr/bin/env python3

from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("u2_task_intake.py")
sys.path.insert(0, str(MODULE_PATH.parent))
SPEC = importlib.util.spec_from_file_location("u2_task_intake", MODULE_PATH)
assert SPEC and SPEC.loader
intake = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(intake)


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=repo, text=True, capture_output=True, check=True
    ).stdout.strip()


class Fixture:
    def __init__(self, directory: str):
        self.repo = Path(directory)
        git(self.repo, "init", "-b", "main")
        git(self.repo, "config", "user.name", "Intake Test")
        git(self.repo, "config", "user.email", "intake@example.invalid")
        git(
            self.repo,
            "remote",
            "add",
            "origin",
            "https://github.com/leeshsnu/treeXchange-season2.git",
        )
        (self.repo / ".gitignore").write_text(".agent-state/\n", encoding="utf-8")
        source = self.repo / "apps/ops-dashboard/app/page.tsx"
        source.parent.mkdir(parents=True)
        source.write_text("export default 1;\n", encoding="utf-8")
        git(self.repo, "add", ".")
        git(self.repo, "commit", "-m", "base")
        self.base = git(self.repo, "rev-parse", "HEAD")
        git(self.repo, "switch", "-c", "codex/review-snapshot/test")
        source.write_text("export default 2;\n", encoding="utf-8")
        git(self.repo, "add", ".")
        git(self.repo, "commit", "-m", "snapshot")
        self.head = git(self.repo, "rev-parse", "HEAD")
        self.manifests = self.repo / ".agent-state/task-manifests"
        self.manifests.mkdir(parents=True)

    def manifest(self) -> dict:
        return {
            "schema_version": 1,
            "queue_id": "u2-user-design-review-01",
            "repository": "leeshsnu/treeXchange-season2",
            "origin": {
                "kind": "user_directive",
                "directive_id": "directive-design-review-01",
                "requested_assignee": "Claude",
                "intent": "design_review",
                "instruction_digest": hashlib.sha256(b"review the design").hexdigest(),
                "recorded_at": "2026-07-24T00:00:00Z",
            },
            "item": {
                "work_item_id": "UX-REVIEW-01",
                "depends_on": [],
                "role": "repository_reviewer",
                "branch": "codex/review-snapshot/test",
                "base_sha": self.base,
                "target_sha": self.head,
                "task_profile": "design",
                "objective": "Review whether the owner can understand automated work.",
                "acceptance_criteria": ["Return prioritized evidence-backed findings."],
                "read_paths": ["apps/ops-dashboard/**"],
                "allowed_paths": ["apps/ops-dashboard/**"],
                "maximum_turns": 4,
                "maximum_attempts": 1,
                "window_id": "u2-user-design-review-window-01",
            },
        }

    def write(self, value: dict) -> Path:
        path = self.manifests / "manifest.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        os.chmod(path, 0o600)
        return path


class U2TaskIntakeTests(unittest.TestCase):
    def test_user_directed_design_review_becomes_one_paused_bound_queue(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(directory)
            path = fixture.write(fixture.manifest())
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                intake.create(argparse.Namespace(repo=fixture.repo, manifest=path))
            result = json.loads(output.getvalue())
            self.assertEqual(result["status"], "DRAFTED_PAUSED")
            self.assertFalse(result["released"])
            queue = json.loads(
                (fixture.repo / result["queue"]).read_text(encoding="utf-8")
            )
            self.assertEqual(queue["origin"]["requested_assignee"], "Claude")
            self.assertEqual(queue["origin"]["intent"], "design_review")
            self.assertEqual(queue["items"][0]["target_sha"], fixture.head)
            self.assertEqual(queue["items"][0]["state"], "planned")
            self.assertEqual(queue["release"]["maximum_operations"], 0)
            intake.controller.validate_queue(queue)

    def test_intake_rejects_codex_assignment_and_wrong_design_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(directory)
            value = fixture.manifest()
            value["origin"]["requested_assignee"] = "Codex"
            with self.assertRaisesRegex(intake.IntakeError, "assigned to Claude"):
                intake.validate_manifest(fixture.repo, value)
            value = fixture.manifest()
            value["item"]["task_profile"] = "standard"
            with self.assertRaisesRegex(intake.IntakeError, "design task profile"):
                intake.validate_manifest(fixture.repo, value)

    def test_intake_rejects_a_stale_or_different_worktree_head(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(directory)
            value = fixture.manifest()
            value["item"]["target_sha"] = "f" * 40
            with self.assertRaisesRegex(intake.IntakeError, "exact checked-out Head"):
                intake.validate_manifest(fixture.repo, value)

    def test_intake_rejects_dirty_code_instead_of_reviewing_an_unbound_state(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(directory)
            target = fixture.repo / "apps/ops-dashboard/app/page.tsx"
            target.write_text("export default 3;\n", encoding="utf-8")
            with self.assertRaisesRegex(intake.IntakeError, "scoped snapshot first"):
                intake.validate_manifest(fixture.repo, fixture.manifest())


if __name__ == "__main__":
    unittest.main()
