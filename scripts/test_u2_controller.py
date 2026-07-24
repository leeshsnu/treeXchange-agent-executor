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


def paused_user_review_queue(repository: ReviewRepository) -> dict:
    value = paused_queue(repository)
    value["origin"] = {
        "kind": "user_directive",
        "directive_id": "directive-controller-review-01",
        "requested_assignee": "Claude",
        "intent": "review",
        "instruction_digest": hashlib.sha256(b"review exact code").hexdigest(),
        "recorded_at": "2026-07-24T00:00:00Z",
    }
    return value


def signed_standing_policy(repository: ReviewRepository, *, daily: int = 3) -> dict:
    now = dt.datetime.now(dt.timezone.utc)
    value = {
        "schema_version": 1,
        "policy_id": "u2-user-review-policy-01",
        "status": "active",
        "approval_key_id": "u2-attended-approval-v1",
        "approved_by": "user",
        "approved_at": (now - dt.timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
        "expires_at": (now + dt.timedelta(days=30)).isoformat().replace("+00:00", "Z"),
        "repository": "leeshsnu/treeXchange-season2",
        "allowed_origins": ["user_directive"],
        "allowed_intents": ["advice", "design_review", "review"],
        "allowed_roles": ["repository_reviewer"],
        "allowed_profiles": ["design", "standard"],
        "allowed_read_roots": ["services/model/**"],
        "maximum_calls_per_task": 1,
        "maximum_calls_per_utc_day": daily,
        "maximum_turns": 4,
        "automatic_retries": 0,
        "policy_digest": "0" * 64,
        "signature": "A" * 86 + "==",
    }
    value["policy_digest"] = controller.standing_policy_digest(value)
    value["signature"] = base64.b64encode(
        controller.ed25519_signature(
            controller.standing_policy_payload(value), repository.approval_private
        )
    ).decode("ascii")
    return value


def active_config(
    repository: ReviewRepository, *, maker: bool = False
) -> dict:
    value = copy.deepcopy(controller.worker.load_config())
    now = dt.datetime.now(dt.timezone.utc)
    value["status"] = "approved_active"
    value["activation"].update(
        {
            "enabled": True,
            "enabled_roles": (
                ["repository_reviewer", "scoped_maker"]
                if maker
                else ["repository_reviewer"]
            ),
            "approved_by": "user",
            "approved_at": (now - dt.timedelta(minutes=1)).isoformat(),
            "expires_at": (now + dt.timedelta(hours=1)).isoformat(),
        }
    )
    value["approver"]["public_key_sha256"] = repository.approval_public_digest
    return value


def maker_queue(repository: ReviewRepository, state: str = "ready") -> dict:
    git(repository.root, "switch", "-c", "claude/controller-maker-test")
    value = released_queue(repository, state)
    item = value["items"][0]
    item.update(
        {
            "role": "scoped_maker",
            "branch": "claude/controller-maker-test",
            "base_sha": repository.head,
            "target_sha": repository.head,
            "objective": "Update the bounded model service documentation.",
            "acceptance_criteria": ["Write the requested bounded text change."],
            "read_paths": ["services/model/**"],
            "allowed_paths": ["services/model/README.md"],
        }
    )
    value["release"]["allowed_roles"] = ["scoped_maker"]
    value["release"]["queue_digest"] = controller.approval_digest(value)
    value["release"]["release_signature"] = base64.b64encode(
        controller.ed25519_signature(
            controller.release_payload(value), repository.approval_private
        )
    ).decode("ascii")
    return value


class U2ControllerTests(unittest.TestCase):
    def test_unsigned_standing_policy_has_one_machine_computed_approval_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = ReviewRepository(directory)
            signed = signed_standing_policy(repository, daily=12)
            unsigned = {
                key: value
                for key, value in signed.items()
                if key not in {"policy_digest", "signature"}
            }
            path = repository.state / "standing-policy-draft.json"
            controller.bridge.save_private_json(path, unsigned)
            output = io.StringIO()

            with contextlib.redirect_stdout(output):
                controller.inspect_standing_policy_draft(
                    argparse.Namespace(repo=repository.root, policy=path)
                )

            result = json.loads(output.getvalue())
            self.assertEqual(result["status"], "VALID_UNSIGNED_STANDING_POLICY_NOT_ACTIVE")
            self.assertEqual(result["policy_digest"], signed["policy_digest"])
            self.assertEqual(result["maximum_calls_per_utc_day"], 12)
            self.assertEqual(result["automatic_retries"], 0)

    def test_signed_standing_policy_releases_only_one_explicit_read_only_task(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo_path = root / "repo"
            repo_path.mkdir()
            repository = ReviewRepository(str(repo_path))
            queue = paused_user_review_queue(repository)
            path = repository.queue_path(queue)
            policy = signed_standing_policy(repository)
            external = root / "external"
            external.mkdir(mode=0o700)
            policy_path = external / "signed-policy.json"
            policy_path.write_text(json.dumps(policy), encoding="utf-8")
            os.chmod(policy_path, 0o600)
            ledger = external / "standing-ledger"
            ledger.mkdir(mode=0o700)
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
                args = argparse.Namespace(
                    repo=repository.root,
                    queue=path,
                    config=config_path,
                    policy=policy_path,
                    ledger=ledger,
                )
                with mock.patch.object(controller.worker, "CONFIG_PATH", config_path):
                    with mock.patch.dict(controller.os.environ, environment, clear=False):
                        with mock.patch("builtins.print"):
                            controller.release_under_standing_policy(args)
            released = controller.worker.load_json(path, "queue")
            self.assertEqual(released["status"], "released")
            self.assertEqual(released["release"]["approval_key_id"], "u2-standing-policy-v1")
            controller.verify_release_authorization(
                released, repository.approval_public.read_bytes(), KEY
            )
            self.assertEqual(len(list(ledger.glob("*.json"))), 1)

    def test_standing_policy_rejects_maker_scope_and_enforces_daily_cap(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo_path = root / "repo"
            repo_path.mkdir()
            repository = ReviewRepository(str(repo_path))
            queue = paused_user_review_queue(repository)
            policy = signed_standing_policy(repository, daily=1)
            queue["items"][0]["role"] = "scoped_maker"
            queue["origin"]["intent"] = "build"
            with self.assertRaisesRegex(controller.ControllerError, "intent"):
                controller.policy_allows_queue(policy, queue)

            queue = paused_user_review_queue(repository)
            ledger = root / "standing-ledger"
            ledger.mkdir(mode=0o700)
            now = dt.datetime.now(dt.timezone.utc)
            controller.reserve_standing_release(repository.root, ledger, policy, queue, now)
            changed = copy.deepcopy(queue)
            changed["queue_id"] = "u2-controller-test-02"
            with self.assertRaisesRegex(controller.ControllerError, "daily release cap"):
                controller.reserve_standing_release(repository.root, ledger, policy, changed, now)

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

    def test_release_roles_and_operation_cap_match_the_signed_queue(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = ReviewRepository(directory)
            queue = released_queue(repository)
            queue["items"][0]["role"] = "scoped_maker"
            with self.assertRaisesRegex(controller.ControllerError, "outside the attended"):
                controller.validate_queue(queue)
            queue = released_queue(repository)
            queue["release"]["maximum_operations"] = 2
            with self.assertRaisesRegex(controller.ControllerError, "must equal"):
                controller.validate_queue(queue)

    def test_scoped_maker_queue_is_a_valid_released_role(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = ReviewRepository(directory)
            queue = maker_queue(repository)
            controller.validate_queue(queue)
            controller.verify_release_signature(
                queue, repository.approval_public.read_bytes()
            )

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

    def test_controller_denies_before_queue_access_without_pinned_runtime_sha(self):
        args = argparse.Namespace(
            repo=Path("/must/not/read"),
            queue=Path("/must/not/read/queue.json"),
            config=controller.worker.CONFIG_PATH,
        )
        with mock.patch.object(controller, "queue_path") as queue_access:
            with mock.patch.object(
                controller.worker.bridge, "exact_commit", return_value="a" * 40
            ):
                with mock.patch.dict(controller.os.environ, {}, clear=True):
                    with self.assertRaisesRegex(
                        controller.worker.WorkerError, "exact trusted SHA"
                    ):
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

    def test_scoped_maker_done_keeps_bounded_change_for_codex_handoff(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = ReviewRepository(directory)
            path = repository.queue_path(maker_queue(repository))
            config = active_config(repository, maker=True)
            with tempfile.TemporaryDirectory() as config_directory:
                config_path = Path(config_directory) / "active.json"
                config_path.write_text(json.dumps(config), encoding="utf-8")
                args = argparse.Namespace(
                    repo=repository.root, queue=path, config=config_path
                )

                def fake_worker_run(worker_args: argparse.Namespace) -> None:
                    request = controller.worker.load_json(worker_args.request, "request")
                    self.assertEqual(request["role"], "scoped_maker")
                    target = repository.root / "services/model/README.md"
                    target.write_text("Changed by scoped Maker\n", encoding="utf-8")
                    result = {
                        "status": "DONE",
                        "summary": "Updated the requested documentation.",
                        "changed_paths_claimed": ["services/model/README.md"],
                        "verification_requested": ["Review the exact diff."],
                        "residual_risk": [],
                        "decision_required": None,
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
                        "session_id": "test-maker-session",
                        "num_turns": 1,
                        "result": result,
                        "actual_changed_paths": ["services/model/README.md"],
                        "change_digest": "a" * 64,
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
                        with mock.patch.dict(
                            controller.os.environ, environment, clear=False
                        ):
                            with contextlib.redirect_stdout(stdout):
                                controller.run_next(args)

            result = json.loads(stdout.getvalue())
            self.assertEqual(result["status"], "WORK_COMPLETED")
            self.assertEqual(result["role"], "scoped_maker")
            self.assertEqual(result["outcome"], "DONE")
            queue = controller.worker.load_json(path, "queue")
            self.assertEqual(queue["items"][0]["result"]["verdict"], "DONE")
            self.assertEqual(
                [entry["type"] for entry in queue["events"]],
                ["model_reserved", "maker_completed"],
            )
            self.assertEqual(
                git(repository.root, "status", "--short"),
                "M services/model/README.md",
            )

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
