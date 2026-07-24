#!/usr/bin/env python3

from __future__ import annotations

import hashlib
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
            "approval_public_key_sha256": hashlib.sha256(
                self.public_key.read_bytes()
            ).hexdigest(),
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
    def test_review_snapshot_lane_allows_same_repository_without_manual_config_per_task(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = UserRunnerFixture(directory)
            parent = fixture.root / "review-worktrees"
            parent.mkdir()
            value = fixture.config()
            value["repositories"].append(
                {
                    "lane_id": "season2-review-snapshots",
                    "repository": "leeshsnu/treeXchange-season2",
                    "worktree_parent": str(parent),
                    "branch_prefix": "codex/review-snapshot/",
                    "queue_directory": ".agent-state/u2-queues",
                    "git_excludes_file": None,
                }
            )
            runner.validate_config(value)

            duplicate = json.loads(json.dumps(value))
            duplicate["repositories"].append(dict(duplicate["repositories"][-1]))
            with self.assertRaisesRegex(runner.RunnerError, "lane is duplicated"):
                runner.validate_config(duplicate)

    def test_load_config_accepts_external_review_snapshot_lane(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = UserRunnerFixture(directory)
            parent = fixture.root / "review-worktrees"
            parent.mkdir()
            value = fixture.config(status="paused")
            value["repositories"].append(
                {
                    "lane_id": "season2-review-snapshots",
                    "repository": "leeshsnu/treeXchange-season2",
                    "worktree_parent": str(parent),
                    "branch_prefix": "codex/review-snapshot/",
                    "queue_directory": ".agent-state/u2-queues",
                    "git_excludes_file": None,
                }
            )
            config_path = fixture.root / "runner.json"
            config_path.write_text(json.dumps(value), encoding="utf-8")
            os.chmod(config_path, 0o600)

            loaded = runner.load_config(config_path)

            self.assertEqual(loaded["repositories"][-1]["lane_id"], "season2-review-snapshots")

    def test_discovery_lane_finds_only_cleanly_named_review_worktrees(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            parent = root / "reviews"
            parent.mkdir()
            review = parent / "review-one"
            review.mkdir()
            subprocess.run(["git", "init", "-b", "main"], cwd=review, check=True, capture_output=True)
            subprocess.run(["git", "switch", "-c", "codex/review-snapshot/one"], cwd=review, check=True, capture_output=True)
            queue_dir = review / ".agent-state/u2-queues"
            queue_dir.mkdir(parents=True)
            (queue_dir / "task.json").write_text("{}\n", encoding="utf-8")
            ignored = parent / "maker"
            ignored.mkdir()
            subprocess.run(["git", "init", "-b", "main"], cwd=ignored, check=True, capture_output=True)
            entry = {
                "lane_id": "season2-review-snapshots",
                "repository": "leeshsnu/treeXchange-season2",
                "worktree_parent": str(parent),
                "branch_prefix": "codex/review-snapshot/",
                "queue_directory": ".agent-state/u2-queues",
                "git_excludes_file": None,
            }
            candidates = runner.queue_candidates(
                {"repositories": [entry]}, command=runner.run_command
            )
            self.assertEqual(len(candidates), 1)
            self.assertEqual(candidates[0][0]["worktree"], str(review.resolve()))
            self.assertEqual(candidates[0][1], queue_dir.resolve() / "task.json")

    def test_standing_policy_releases_then_runs_one_user_directed_review(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = UserRunnerFixture(directory)
            policy = fixture.root / "standing-policy.json"
            policy.write_text("{}\n", encoding="utf-8")
            os.chmod(policy, 0o600)
            standing_ledger = fixture.root / "standing-ledger"
            standing_ledger.mkdir(mode=0o700)
            config = fixture.config()
            config["standing_policy_path"] = str(policy)
            config["standing_release_ledger"] = str(standing_ledger)
            draft = {
                "status": "draft_paused",
                "queue_id": "u2-user-review-01",
                "origin": {
                    "requested_assignee": "Claude",
                    "intent": "review",
                },
                "next_ready": True,
                "next_work_item_id": "OPS-USER-01",
                "next_role": "repository_reviewer",
                "operations_reserved": 0,
                "maximum_operations": 0,
                "approval_digest": "d" * 64,
                "external_release_claimed": False,
            }
            released = {
                **draft,
                "status": "released",
                "authorization_type": "standing_policy",
                "maximum_operations": 1,
            }
            inspections = iter([draft, released])
            calls: list[list[str]] = []

            def command(args, **_kwargs):
                calls.append(list(args))
                if "inspect" in args:
                    return completed(json.dumps(next(inspections)))
                if "release-under-standing-policy" in args:
                    return completed('{"status":"RELEASED_UNDER_STANDING_POLICY"}')
                return completed('{"status":"WORK_COMPLETED"}')

            with mock.patch.object(runner, "ROOT", fixture.executor):
                result = runner.run_cycle(config, command=command)
            self.assertTrue(result["attempted"])
            self.assertEqual(result["outcome"], "completed")
            self.assertEqual(
                [
                    "inspect" if "inspect" in args else
                    "release" if "release-under-standing-policy" in args else
                    "run"
                    for args in calls
                ],
                ["inspect", "release", "inspect", "run"],
            )
            attempts = json.loads((fixture.state / "attempts.json").read_text())["attempts"]
            self.assertEqual(
                sorted(entry["status"] for entry in attempts.values()),
                ["completed", "standing_release_completed"],
            )

    def test_active_config_rejects_a_swapped_approval_public_key(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = UserRunnerFixture(directory)
            value = fixture.config()
            fixture.public_key.write_text("swapped\n", encoding="utf-8")
            with self.assertRaisesRegex(runner.RunnerError, "pinned SHA-256"):
                runner.validate_config(value)

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

    def test_launch_agent_uses_owner_only_umask_for_runtime_logs(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = UserRunnerFixture(directory)
            payload = runner.launch_agent_payload(
                fixture.config(),
                fixture.state,
                "com.treexchange.u2-user-runner",
                fixture.root / "runner.json",
            )
            self.assertEqual(payload["Umask"], 0o077)
            self.assertEqual(payload["StandardOutPath"], str(fixture.state / "runner.stdout.log"))
            self.assertEqual(payload["StandardErrorPath"], str(fixture.state / "runner.stderr.log"))

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
                    "next_ready": True,
                    "next_work_item_id": "OPS-RUNNER-01",
                    "next_role": "scoped_maker",
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
                    "next_ready": True,
                    "next_work_item_id": "OPS-RUNNER-02",
                    "next_role": "repository_reviewer",
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
            self.assertEqual(
                environment["TREEXCHANGE_U2_APPROVAL_PUBLIC_KEY_SHA256"],
                fixture.config()["approval_public_key_sha256"],
            )

    def test_inspection_receives_neither_controller_key_nor_claude_oauth(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = UserRunnerFixture(directory)
            with mock.patch.dict(
                os.environ,
                {
                    "CLAUDE_CODE_OAUTH_TOKEN": "must-not-pass-to-inspection",
                    "TREEXCHANGE_U2_CONTROLLER_KEY": "must-not-pass-to-inspection",
                },
                clear=False,
            ):
                environment = runner.inspection_environment(
                    fixture.config()["repositories"][0]
                )
            self.assertNotIn("CLAUDE_CODE_OAUTH_TOKEN", environment)
            self.assertNotIn("TREEXCHANGE_U2_CONTROLLER_KEY", environment)

    def test_dependency_blocked_queue_does_not_consume_runner_attempt(self):
        value = {
            "status": "released",
            "operations_reserved": 0,
            "maximum_operations": 1,
            "next_ready": False,
        }
        self.assertFalse(runner.actionable_queue(value))

    def test_one_release_can_advance_distinct_work_items_without_retrying_either(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = UserRunnerFixture(directory)
            inspections = iter(
                [
                    {
                        "status": "released",
                        "queue_id": "u2-runner-batch-01",
                        "next_ready": True,
                        "next_work_item_id": "OPS-BATCH-01",
                        "next_role": "scoped_maker",
                        "operations_reserved": 0,
                        "maximum_operations": 2,
                        "approval_digest": "c" * 64,
                        "external_release_claimed": False,
                    },
                    {
                        "status": "released",
                        "queue_id": "u2-runner-batch-01",
                        "next_ready": True,
                        "next_work_item_id": "OPS-BATCH-02",
                        "next_role": "repository_reviewer",
                        "operations_reserved": 1,
                        "maximum_operations": 2,
                        "approval_digest": "c" * 64,
                        "external_release_claimed": False,
                    },
                    {
                        "status": "released",
                        "queue_id": "u2-runner-batch-01",
                        "next_ready": False,
                        "next_work_item_id": None,
                        "next_role": None,
                        "operations_reserved": 2,
                        "maximum_operations": 2,
                        "approval_digest": "c" * 64,
                        "external_release_claimed": False,
                    },
                ]
            )
            run_calls = 0

            def command(args, **_kwargs):
                nonlocal run_calls
                if "inspect" in args:
                    return completed(json.dumps(next(inspections)))
                run_calls += 1
                return completed('{"status":"WORK_COMPLETED"}')

            with mock.patch.object(runner, "ROOT", fixture.executor):
                first = runner.run_cycle(fixture.config(), command=command)
                second = runner.run_cycle(fixture.config(), command=command)
                third = runner.run_cycle(fixture.config(), command=command)
            self.assertEqual(first["work_item_id"], "OPS-BATCH-01")
            self.assertEqual(second["work_item_id"], "OPS-BATCH-02")
            self.assertEqual(third, {"status": "IDLE", "attempted": False})
            self.assertEqual(run_calls, 2)


if __name__ == "__main__":
    unittest.main()
