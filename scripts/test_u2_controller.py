#!/usr/bin/env python3

from __future__ import annotations

import argparse
import base64
import contextlib
import copy
import datetime as dt
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
from unittest import mock


MODULE_PATH = Path(__file__).with_name("u2_controller.py")
sys.path.insert(0, str(MODULE_PATH.parent))
SPEC = importlib.util.spec_from_file_location("u2_controller", MODULE_PATH)
assert SPEC and SPEC.loader
controller = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(controller)

KEY = "controller-test-key-that-is-at-least-thirty-two-bytes"


def git(repo: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args], cwd=repo, text=True, capture_output=True, check=True
    )
    return completed.stdout.strip()


class ReviewRepository:
    def __init__(self, directory: str):
        self.root = Path(directory)
        git(self.root, "init", "-b", "main")
        git(self.root, "config", "user.name", "Controller Test")
        git(self.root, "config", "user.email", "controller@example.invalid")
        git(
            self.root,
            "remote",
            "add",
            "origin",
            "https://github.com/leeshsnu/treeXchange-season2.git",
        )
        (self.root / ".gitignore").write_text(".agent-state/\n", encoding="utf-8")
        target = self.root / "services/model"
        target.mkdir(parents=True)
        (target / "README.md").write_text("Initial\n", encoding="utf-8")
        git(self.root, "add", ".")
        git(self.root, "commit", "-m", "initial")
        self.base = git(self.root, "rev-parse", "HEAD")
        git(self.root, "switch", "-c", "agent/controller-test")
        (target / "README.md").write_text("Changed\n", encoding="utf-8")
        git(self.root, "add", ".")
        git(self.root, "commit", "-m", "change")
        self.head = git(self.root, "rev-parse", "HEAD")
        self.state = self.root / ".agent-state"
        self.state.mkdir()
        self.approval_private = self.state / "approval-private.pem"
        self.approval_public = self.state / "approval-public.pem"
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(self.approval_private)],
            check=True,
            capture_output=True,
        )
        os.chmod(self.approval_private, 0o600)
        subprocess.run(
            [
                "openssl",
                "pkey",
                "-in",
                str(self.approval_private),
                "-pubout",
                "-out",
                str(self.approval_public),
            ],
            check=True,
            capture_output=True,
        )
        self.approval_public_digest = hashlib.sha256(
            self.approval_public.read_bytes()
        ).hexdigest()

    def queue_path(self, value: dict) -> Path:
        path = self.state / "queue.json"
        controller.bridge.save_private_json(path, value)
        return path


def released_queue(repository: ReviewRepository, verdict_state: str = "ready") -> dict:
    now = dt.datetime.now(dt.timezone.utc)
    value = {
        "schema_version": 1,
        "queue_id": "u2-controller-test-01",
        "status": "released",
        "repository": "leeshsnu/treeXchange-season2",
        "release": {
            "release_id": "release-u2-review-0001",
            "approval_key_id": "u2-attended-approval-v1",
            "approved_by": "user",
            "approved_at": (now - dt.timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
            "expires_at": (now + dt.timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
            "allowed_roles": ["repository_reviewer"],
            "maximum_operations": 1,
            "queue_digest": "0" * 64,
            "release_signature": "0" * 64,
        },
        "items": [
            {
                "work_item_id": "OPS-TEST-01",
                "state": verdict_state,
                "depends_on": [],
                "role": "repository_reviewer",
                "branch": "agent/controller-test",
                "base_sha": repository.base,
                "target_sha": repository.head,
                "task_profile": "standard",
                "objective": "Review the exact bounded change.",
                "acceptance_criteria": ["Report all blocking findings."],
                "read_paths": ["services/model/**"],
                "allowed_paths": ["services/model/README.md"],
                "maximum_turns": 4,
                "maximum_attempts": 1,
                "attempts": 0,
                "window_id": "u2-controller-test-window-01",
                "request_id": None,
                "result": None,
            }
        ],
        "events": [],
    }
    value["release"]["queue_digest"] = controller.approval_digest(value)
    value["release"]["release_signature"] = base64.b64encode(
        controller.ed25519_signature(
            controller.release_payload(value), repository.approval_private
        )
    ).decode("ascii")
    return value


def paused_queue(repository: ReviewRepository) -> dict:
    value = released_queue(repository, "planned")
    value["status"] = "draft_paused"
    value["release"] = {
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
    return value


def active_config(repository: ReviewRepository) -> dict:
    value = copy.deepcopy(controller.worker.load_config())
    now = dt.datetime.now(dt.timezone.utc)
    value["status"] = "approved_active"
    value["activation"].update(
        {
            "enabled": True,
            "enabled_roles": ["repository_reviewer"],
            "approved_by": "user",
            "approved_at": (now - dt.timedelta(minutes=1)).isoformat(),
            "expires_at": (now + dt.timedelta(hours=1)).isoformat(),
        }
    )
    value["approver"]["public_key_sha256"] = repository.approval_public_digest
    return value


class U2ControllerTests(unittest.TestCase):
    def test_paused_queue_is_inspectable_but_contains_no_execution_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = ReviewRepository(directory)
            path = repository.queue_path(paused_queue(repository))
            args = argparse.Namespace(repo=repository.root, queue=path)
            with mock.patch("builtins.print") as output:
                controller.inspect_queue(args)
            result = json.loads(output.call_args.args[0])
            self.assertEqual(result["status"], "draft_paused")
            self.assertEqual(result["operations_reserved"], 0)
            self.assertTrue(result["next_ready"])
            self.assertFalse(result["external_release_claimed"])

            invalid = paused_queue(repository)
            invalid["events"].append(
                controller.event(
                    "model_reserved",
                    invalid["items"][0],
                    "u2-request-test-0001",
                    "running",
                    "INVALID",
                    dt.datetime.now(dt.timezone.utc),
                )
            )
            with self.assertRaisesRegex(controller.ControllerError, "execution evidence"):
                controller.validate_queue(invalid)

    def test_initial_release_is_reviewer_only_and_single_operation(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = ReviewRepository(directory)
            queue = released_queue(repository)
            queue["items"][0]["role"] = "scoped_maker"
            with self.assertRaisesRegex(controller.ControllerError, "only Reviewer"):
                controller.validate_queue(queue)
            queue = released_queue(repository)
            queue["release"]["maximum_operations"] = 2
            with self.assertRaisesRegex(controller.ControllerError, "exactly one"):
                controller.validate_queue(queue)

    def test_released_queue_stops_after_its_single_reserved_operation(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = ReviewRepository(directory)
            queue = released_queue(repository)
            queue["events"].append(
                controller.event(
                    "model_reserved",
                    queue["items"][0],
                    "u2-request-test-0001",
                    "running",
                    "REVIEW_RESERVED",
                    dt.datetime.now(dt.timezone.utc),
                )
            )
            with self.assertRaisesRegex(controller.ControllerError, "operation cap"):
                controller.release_is_current(queue, dt.datetime.now(dt.timezone.utc))

    def test_dependency_cycles_and_missing_dependencies_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = ReviewRepository(directory)
            queue = released_queue(repository)
            second = copy.deepcopy(queue["items"][0])
            second["work_item_id"] = "OPS-TEST-02"
            second["window_id"] = "u2-controller-test-window-02"
            queue["items"].append(second)
            queue["items"][0]["depends_on"] = ["OPS-TEST-02"]
            second["depends_on"] = ["OPS-TEST-01"]
            with self.assertRaisesRegex(controller.ControllerError, "cycle"):
                controller.validate_queue(queue)

    def test_signed_request_is_accepted_by_worker(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = ReviewRepository(directory)
            queue = released_queue(repository)
            config = active_config(repository)
            now = dt.datetime.now(dt.timezone.utc)
            request = controller.build_request(queue, queue["items"][0], config, KEY, now)
            controller.worker.verify_controller_signature(
                request,
                config,
                {config["controller"]["key_environment"]: KEY},
            )
            self.assertEqual(request["branch"], "agent/controller-test")
            self.assertEqual(request["role"], "repository_reviewer")

    def test_release_signature_binds_immutable_work_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = ReviewRepository(directory)
            queue = released_queue(repository)
            controller.verify_release_signature(
                queue, repository.approval_public.read_bytes()
            )
            queue["items"][0]["objective"] = "Tampered objective"
            with self.assertRaisesRegex(controller.ControllerError, "changed after"):
                controller.verify_release_signature(
                    queue, repository.approval_public.read_bytes()
                )

    def test_release_claim_is_external_atomic_and_single_use(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = ReviewRepository(directory)
            queue = released_queue(repository)
            config = active_config(repository)
            now = dt.datetime.now(dt.timezone.utc)
            request = controller.build_request(
                queue, queue["items"][0], config, KEY, now
            )
            claim = controller.claim_release_once(
                repository.root, queue, request, now
            )
            self.assertTrue(claim.is_file())
            self.assertNotEqual(claim.parent, repository.state)
            path = repository.queue_path(queue)
            args = argparse.Namespace(repo=repository.root, queue=path)
            with mock.patch("builtins.print") as output:
                controller.inspect_queue(args)
            self.assertTrue(
                json.loads(output.call_args.args[0])["external_release_claimed"]
            )
            with self.assertRaisesRegex(controller.ControllerError, "already been consumed"):
                controller.claim_release_once(repository.root, queue, request, now)

    def test_attended_release_requires_the_exact_user_approved_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = ReviewRepository(directory)
            queue = paused_queue(repository)
            path = repository.queue_path(queue)
            digest = controller.approval_digest(queue)
            args = argparse.Namespace(
                repo=repository.root,
                queue=path,
                config=controller.worker.CONFIG_PATH,
                expected_digest=digest,
                approved_by="user",
                release_id="release-u2-review-0001",
                expires_at=(
                    dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1)
                ).isoformat().replace("+00:00", "Z"),
                approval_private_key=repository.approval_private,
            )
            config = active_config(repository)
            environment = {
                config["controller"]["key_environment"]: KEY,
                config["approver"]["public_key_path_environment"]: str(
                    repository.approval_public
                ),
                "U2_EXECUTOR_TRUSTED_SHA": git(controller.ROOT, "rev-parse", "HEAD"),
            }
            with tempfile.TemporaryDirectory() as config_directory:
                config_path = Path(config_directory) / "active.json"
                config_path.write_text(json.dumps(config), encoding="utf-8")
                args.config = config_path
                with mock.patch.object(controller.worker, "CONFIG_PATH", config_path):
                    with mock.patch.dict(controller.os.environ, environment, clear=False):
                        with mock.patch("builtins.print"):
                            controller.release_queue(args)
            released = controller.worker.load_json(path, "queue")
            self.assertEqual(released["status"], "released")
            self.assertEqual(released["release"]["queue_digest"], digest)
            controller.verify_release_signature(
                released, repository.approval_public.read_bytes()
            )

    def test_paused_controller_denies_before_queue_access(self):
        args = argparse.Namespace(
            repo=Path("/must/not/read"),
            queue=Path("/must/not/read/queue.json"),
            config=controller.worker.CONFIG_PATH,
        )
        with mock.patch.object(controller, "queue_path") as queue_access:
            with self.assertRaisesRegex(controller.worker.WorkerError, "proposed and paused"):
                controller.run_next(args)
        queue_access.assert_not_called()

    def test_reviewer_approve_completes_item_and_records_machine_event(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = ReviewRepository(directory)
            path = repository.queue_path(released_queue(repository))
            config = active_config(repository)
            with tempfile.TemporaryDirectory() as config_directory:
                config_path = Path(config_directory) / "active.json"
                config_path.write_text(json.dumps(config), encoding="utf-8")
                args = argparse.Namespace(repo=repository.root, queue=path, config=config_path)

                def fake_worker_run(worker_args: argparse.Namespace) -> None:
                    self.assertEqual(
                        worker_args.ledger,
                        controller.bridge.shared_ledger_path(repository.root),
                    )
                    request = controller.worker.load_json(worker_args.request, "request")
                    controller.worker.verify_controller_signature(
                        request,
                        config,
                        {config["controller"]["key_environment"]: KEY},
                    )
                    result = {
                        "verdict": "APPROVE",
                        "summary": "No blocking finding remains.",
                        "findings": [],
                        "verification": ["Reviewed the exact diff."],
                        "requirement_coverage": ["Bounded Reviewer flow."],
                        "residual_risk": ["No live model call in this test."],
                    }
                    output = {
                        "schema_version": 1,
                        "request_id": request["request_id"],
                        "request_digest": controller.worker.request_digest(request),
                        "work_item_id": request["work_item_id"],
                        "role": request["role"],
                        "repository": request["repository"],
                        "base_sha": request["base_sha"],
                        "target_sha": request["target_sha"],
                        "model": controller.bridge.DEFAULT_MODEL,
                        "session_id": "test-session",
                        "num_turns": 1,
                        "result": result,
                        "actual_changed_paths": [],
                        "change_digest": None,
                    }
                    controller.bridge.save_private_json(worker_args.output, output)

                environment = {
                    config["controller"]["key_environment"]: KEY,
                    config["approver"]["public_key_path_environment"]: str(
                        repository.approval_public
                    ),
                    "U2_EXECUTOR_TRUSTED_SHA": git(controller.ROOT, "rev-parse", "HEAD"),
                }
                stdout = io.StringIO()
                with mock.patch.object(controller.worker, "CONFIG_PATH", config_path):
                    with mock.patch.object(
                        controller.worker, "run", side_effect=fake_worker_run
                    ):
                        with mock.patch.dict(controller.os.environ, environment, clear=False):
                            with contextlib.redirect_stdout(stdout):
                                controller.run_next(args)
            result = json.loads(stdout.getvalue())
            self.assertEqual(result["status"], "WORK_COMPLETED")
            queue = controller.worker.load_json(path, "queue")
            self.assertEqual(queue["items"][0]["state"], "completed")
            self.assertEqual(queue["items"][0]["result"]["verdict"], "APPROVE")
            self.assertEqual(
                [entry["type"] for entry in queue["events"]],
                ["model_reserved", "review_completed"],
            )
            rendered = json.dumps(queue)
            self.assertNotIn(KEY, rendered)

    def test_controller_happy_path_exercises_real_worker_budget_and_nonce_admission(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = ReviewRepository(directory)
            path = repository.queue_path(released_queue(repository))
            config = active_config(repository)
            with tempfile.TemporaryDirectory() as config_directory:
                config_path = Path(config_directory) / "active.json"
                config_path.write_text(json.dumps(config), encoding="utf-8")
                args = argparse.Namespace(repo=repository.root, queue=path, config=config_path)

                def fake_invoke(
                    repo: Path,
                    request: dict,
                    worker_config: dict,
                    prompt: str,
                    schema: dict,
                    model: str,
                    review_receipt: Path | None = None,
                ) -> tuple[dict, dict]:
                    self.assertIsNotNone(review_receipt)
                    diff = controller.bridge.bounded_diff(
                        repo, request["base_sha"], request["target_sha"]
                    )
                    controller.bridge.save_private_json(
                        review_receipt,
                        {
                            "schema_version": 1,
                            "base_sha": request["base_sha"],
                            "target_sha": request["target_sha"],
                            "sha256": hashlib.sha256(diff.encode("utf-8")).hexdigest(),
                            "bytes": len(diff.encode("utf-8")),
                        },
                    )
                    return (
                        {"session_id": "test-session", "num_turns": 1},
                        {
                            "verdict": "APPROVE",
                            "summary": "No blocking finding remains.",
                            "findings": [],
                            "verification": ["Reviewed the exact diff."],
                            "requirement_coverage": ["Bounded Reviewer flow."],
                            "residual_risk": ["Model call replaced by test double."],
                        },
                    )

                environment = {
                    config["controller"]["key_environment"]: KEY,
                    config["approver"]["public_key_path_environment"]: str(
                        repository.approval_public
                    ),
                    "U2_EXECUTOR_TRUSTED_SHA": git(controller.ROOT, "rev-parse", "HEAD"),
                }
                stdout = io.StringIO()
                with mock.patch.object(controller.worker, "CONFIG_PATH", config_path):
                    with mock.patch.object(
                        controller.worker.bridge, "require_local_claude_runtime"
                    ):
                        with mock.patch.object(
                            controller.worker, "invoke_claude", side_effect=fake_invoke
                        ):
                            with mock.patch.dict(
                                controller.os.environ, environment, clear=False
                            ):
                                with contextlib.redirect_stdout(stdout):
                                    controller.run_next(args)

            result = json.loads(stdout.getvalue())
            self.assertEqual(result["status"], "WORK_COMPLETED")
            ledger = controller.bridge.load_effective_ledger(
                controller.bridge.shared_ledger_path(repository.root), ()
            )
            self.assertEqual(len(ledger["calls"]), 1)
            call = ledger["calls"][0]
            self.assertEqual(call["status"], "succeeded")
            self.assertTrue(call["request_nonce"])
            self.assertTrue(call["budget_reservation_id"])


if __name__ == "__main__":
    unittest.main()
