#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).with_name("u2_user_runner.py")
SPEC = importlib.util.spec_from_file_location("u2_user_runner", MODULE_PATH)
assert SPEC and SPEC.loader
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class UserRunnerFixture:
    def __init__(self, directory: str):
        self.root = Path(directory)
        self.executor = self.root / "executor"
        self.repository = self.root / "repository"
        self.state = self.root / "external-state"
        self.executor.mkdir()
        self.repository.mkdir()
        subprocess.run(["git", "init", "-b", "main"], cwd=self.executor, check=True, capture_output=True)
        subprocess.run(
            ["git", "config", "user.name", "Runner Test"],
            cwd=self.executor,
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.email", "runner@example.invalid"],
            cwd=self.executor,
            check=True,
        )
        (self.executor / "scripts").mkdir()
        (self.executor / "config").mkdir()
        (self.executor / "scripts/u2_controller.py").write_text("# controller\n", encoding="utf-8")
        (self.executor / "config/u2-local-worker.json").write_text("{}\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=self.executor, check=True)
        subprocess.run(["git", "commit", "-m", "initial"], cwd=self.executor, check=True, capture_output=True)
        self.sha = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=self.executor,
            text=True,
            capture_output=True,
            check=True,
        ).stdout.strip()
        self.controller_key = self.root / "controller.key"
        self.controller_key.write_text("x" * 40, encoding="utf-8")
        os.chmod(self.controller_key, 0o600)
        self.public_key = self.root / "approval-public.pem"
        self.public_key.write_text("public\n", encoding="utf-8")
        os.chmod(self.public_key, 0o600)
        self.queues = self.repository / ".agent-state/u2-queues"
        self.queues.mkdir(parents=True)
        self.queue = self.queues / "review.json"
        self.queue.write_text("{}\n", encoding="utf-8")
        os.chmod(self.queue, 0o600)

    def config(self, *, status: str = "active") -> dict:
        return {
            "schema_version": 1,
            "status": status,
            "poll_seconds": 30,
            "automatic_retries": 0,
            "maximum_operations_per_cycle": 1,
            "state_directory": str(self.state),
            "executor_root": str(self.executor),
            "trusted_executor_sha": self.sha,
            "executor_config": "config/u2-local-worker.json",
            "controller_key_path": str(self.controller_key),
            "approval_public_key_path": str(self.public_key),
            "repositories": [
                {
                    "repository": "leeshsnu/treeXchange-season2",
                    "worktree": str(self.repository),
                    "queue_directory": ".agent-state/u2-queues",
                    "git_excludes_file": None,
                }
            ],
        }


def completed(stdout: str = "", returncode: int = 0) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess([], returncode, stdout=stdout, stderr="")


class U2UserRunnerTests(unittest.TestCase):
    def test_paused_config_never_attempts_a_queue(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = UserRunnerFixture(directory)
            result = runner.run_cycle(fixture.config(status="paused"))
            self.assertEqual(result, {"status": "PAUSED", "attempted": False})
            self.assertFalse(fixture.state.exists())

    def test_active_state_directory_must_be_outside_managed_worktrees(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = UserRunnerFixture(directory)
            value = fixture.config()
            value["state_directory"] = str(fixture.repository / ".agent-state/runner")
            with self.assertRaisesRegex(runner.RunnerError, "outside every managed"):
                runner.validate_config(value)

    def test_key_files_must_be_outside_managed_worktrees(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = UserRunnerFixture(directory)
            internal = fixture.repository / ".agent-state/controller.key"
            internal.parent.mkdir(exist_ok=True)
            internal.write_text("x" * 40, encoding="utf-8")
            os.chmod(internal, 0o600)
            value = fixture.config()
            value["controller_key_path"] = str(internal)
            with self.assertRaisesRegex(runner.RunnerError, "key files must remain outside"):
                runner.validate_config(value)

    def test_queue_directory_cannot_escape_the_private_queue_root(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = UserRunnerFixture(directory)
            value = fixture.config()
            value["repositories"][0]["queue_directory"] = ".agent-state/u2-queues/../../elsewhere"
            with self.assertRaisesRegex(runner.RunnerError, "queue_directory"):
                runner.validate_config(value)

    def test_git_excludes_file_is_external_and_fixed(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = UserRunnerFixture(directory)
            excludes = fixture.root / "excludes"
            excludes.write_text("*\n", encoding="utf-8")
            os.chmod(excludes, 0o600)
            value = fixture.config()
            value["repositories"][0]["git_excludes_file"] = str(excludes)
            with self.assertRaisesRegex(runner.RunnerError, "ignore only"):
                runner.validate_config(value)
            excludes.write_text(".agent-state/\n", encoding="utf-8")
            runner.validate_config(value)

            internal = fixture.repository / ".agent-state/excludes"
            internal.write_text(".agent-state/\n", encoding="utf-8")
            os.chmod(internal, 0o600)
            value["repositories"][0]["git_excludes_file"] = str(internal)
            with self.assertRaisesRegex(runner.RunnerError, "excludes files must remain outside"):
                runner.validate_config(value)

    def test_loaded_config_must_be_external_to_managed_worktrees(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = UserRunnerFixture(directory)
            path = fixture.repository / ".agent-state/runner.json"
            path.write_text(json.dumps(fixture.config()), encoding="utf-8")
            os.chmod(path, 0o600)
            with self.assertRaisesRegex(runner.RunnerError, "config must remain outside"):
                runner.load_config(path)

    def test_private_config_rejects_duplicate_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runner.json"
            path.write_text('{"schema_version":1,"schema_version":1}\n', encoding="utf-8")
            os.chmod(path, 0o600)
            with self.assertRaisesRegex(runner.RunnerError, "duplicate key"):
                runner.load_private_json(path, "test config")

    def test_launch_agent_label_cannot_escape_its_directory(self):
        args = mock.Mock(label="../../evil")
        with self.assertRaisesRegex(runner.RunnerError, "label is invalid"):
            runner.install_launch_agent(args)

    def test_retry_and_cycle_caps_are_fixed(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = UserRunnerFixture(directory)
            value = fixture.config()
            value["automatic_retries"] = 1
            with self.assertRaisesRegex(runner.RunnerError, "retries must remain zero"):
                runner.validate_config(value)
            value = fixture.config()
            value["maximum_operations_per_cycle"] = 2
            with self.assertRaisesRegex(runner.RunnerError, "one operation per cycle"):
                runner.validate_config(value)

    def test_runner_must_execute_from_the_pinned_executor_root(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = UserRunnerFixture(directory)
            with self.assertRaisesRegex(runner.RunnerError, "approved executor root"):
                runner.require_exact_executor(fixture.config())

    def test_state_directory_cannot_change_after_process_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = UserRunnerFixture(directory)
            value = fixture.config()
            with self.assertRaisesRegex(runner.RunnerError, "changed after"):
                runner.require_stable_state_directory(value, fixture.root / "different-state")

    def test_released_queue_is_reserved_before_one_controller_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = UserRunnerFixture(directory)
            inspection = json.dumps(
                {
                    "status": "released",
                    "queue_id": "u2-runner-test-01",
                    "counts": {"planned": 1, "ready": 0},
                    "operations_reserved": 0,
                    "maximum_operations": 1,
                    "approval_digest": "a" * 64,
                    "external_release_claimed": False,
                }
            )
            calls: list[list[str]] = []

            def command(args, **_kwargs):
                calls.append(list(args))
                if "inspect" in args:
                    return completed(inspection)
                attempts = json.loads((fixture.state / "attempts.json").read_text())
                self.assertEqual(
                    next(iter(attempts["attempts"].values()))["status"],
                    "reserved_before_launch",
                )
                return completed('{"status":"WORK_COMPLETED"}')

            with mock.patch.object(runner, "ROOT", fixture.executor):
                result = runner.run_cycle(fixture.config(), command=command)
            self.assertTrue(result["attempted"])
            self.assertEqual(result["outcome"], "completed")
            self.assertEqual(len([args for args in calls if "run-next" in args]), 1)

            with mock.patch.object(runner, "ROOT", fixture.executor):
                second = runner.run_cycle(fixture.config(), command=command)
            self.assertEqual(second, {"status": "IDLE", "attempted": False})
            self.assertEqual(len([args for args in calls if "run-next" in args]), 1)

    def test_controller_failure_is_not_retried(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = UserRunnerFixture(directory)
            inspection = json.dumps(
                {
                    "status": "released",
                    "queue_id": "u2-runner-test-02",
                    "counts": {"planned": 1, "ready": 0},
                    "operations_reserved": 0,
                    "maximum_operations": 1,
                    "approval_digest": "b" * 64,
                    "external_release_claimed": False,
                }
            )
            run_calls = 0

            def command(args, **_kwargs):
                nonlocal run_calls
                if "inspect" in args:
                    return completed(inspection)
                run_calls += 1
                return completed(returncode=77)

            with mock.patch.object(runner, "ROOT", fixture.executor):
                first = runner.run_cycle(fixture.config(), command=command)
                second = runner.run_cycle(fixture.config(), command=command)
            self.assertEqual(first["outcome"], "controller_exit_77")
            self.assertEqual(second, {"status": "IDLE", "attempted": False})
            self.assertEqual(run_calls, 1)

    def test_environment_excludes_api_keys_and_private_approval_key(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = UserRunnerFixture(directory)
            with mock.patch.dict(
                os.environ,
                {
                    "ANTHROPIC_API_KEY": "must-not-pass",
                    "TREEXCHANGE_U2_APPROVAL_PRIVATE_KEY": "must-not-pass",
                },
                clear=False,
            ):
                environment = runner.runner_environment(
                    fixture.config(), fixture.config()["repositories"][0]
                )
            self.assertNotIn("ANTHROPIC_API_KEY", environment)
            self.assertNotIn("TREEXCHANGE_U2_APPROVAL_PRIVATE_KEY", environment)
            self.assertEqual(environment["TREEXCHANGE_U2_CONTROLLER_KEY"], "x" * 40)


if __name__ == "__main__":
    unittest.main()
