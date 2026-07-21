#!/usr/bin/env python3

from __future__ import annotations

import base64
import copy
import hashlib
import io
import json
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from scripts import u1_executor as core
from scripts import u1_maker as maker


ROOT = Path(__file__).parents[1]


def repository_config() -> dict:
    return json.loads((ROOT / "config/u1-maker.json").read_text(encoding="utf-8"))


def active_config() -> dict:
    config = repository_config()
    config["status"] = "approved_active"
    config["activation"] = {
        "enabled": True,
        "approved_by": "leeshsnu",
        "approved_at": "2026-07-21T08:00:00Z",
        "expires_at": "2026-07-28T08:00:00Z",
        "trusted_source_policy_sha": "a" * 40,
        "trusted_executor_sha_variable": "U1_EXECUTOR_TRUSTED_SHA",
        "trusted_executor_sha_variable_verified": True,
        "hard_cap_verified": True,
        "actions_step_debug_disabled_verified": True,
        "opaque_dispatch_verified": True,
        "claude_credential_installed_by_user": True,
        "season2_review_token_installed_by_user": True,
    }
    return config


def reservation_context(
    *, ticket_id: int = 42, claude_used: int = 1, pilot_used: int = 1
) -> dict:
    return {
        "now": "2026-07-21T08:30:00Z",
        "action": "reserve_model",
        "repository": core.EXPECTED_SOURCE,
        "workflow": "u1-model-reservation.yml",
        "run_id": f"github-actions-{ticket_id}-1",
        "policy_source": {
            "ref": "refs/heads/main",
            "sha": "a" * 40,
            "verified": True,
            "external_binding": "U1_TRUSTED_POLICY_SHA",
        },
        "pilot_id": "U1-P2",
        "issue_number": 10,
        "branch": maker.EXPECTED_PILOT["branch"],
        "role": "maker",
        "family": "Claude",
        "head_sha": "a" * 40,
        "requested_paths": [maker.EXPECTED_PILOT["allowed_path"]],
        "requested_side_effects": ["read_repository", "write_issue_comment"],
        "github_resolved": {
            "issue_number": 10,
            "issue_state": "open",
            "branch": maker.EXPECTED_PILOT["branch"],
            "head_ref": maker.EXPECTED_PILOT["branch"],
            "base_ref": "main",
            "base_sha": "a" * 40,
            "draft": False,
            "pr_state": "not_created",
            "current_head_sha": "a" * 40,
        },
        "lease": {
            "source": "github_actions_concurrency_and_run_ledger",
            "exclusive": True,
            "reservation_includes_current": True,
            "reservation_run_database_id": ticket_id,
            "live_reservation_run_verified": True,
            "request_id": "request-maker-1234",
            "pilot_id": "U1-P2",
            "run_id": f"github-actions-{ticket_id}-1",
            "head_sha": "a" * 40,
            "expires_at": "2026-07-21T09:30:00Z",
        },
        "usage_ledger": {
            "source": "github_actions_workflow_runs",
            "verified": True,
            "reservation_includes_current": True,
            "used_by_family_including_current": {"Codex": 0, "Claude": claude_used},
            "used_by_family_and_pilot_including_current": {
                "Claude:U1-P2": pilot_used
            },
        },
    }


def reservation_archive(context: dict) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("u1-reservation.json", json.dumps(context))
    return output.getvalue()


def valid_result(content: str = "# 모델 인수인계\n\n## 현재 사용 시 비주장 체크리스트\n- 정확도를 주장하지 않는다.\n") -> dict:
    return {
        "operation": "maker_proposal",
        "summary": "Added a bounded non-claim checklist.",
        "proposed_content": content,
        "verification": ["Preserved the fixed documentation scope."],
        "residual_risk": ["Codex must independently review the proposal."],
    }


class ConfigTests(unittest.TestCase):
    def test_repository_config_is_valid_and_paused(self):
        config = repository_config()
        self.assertEqual(maker.validate_config(config), maker.EXPECTED_PILOT)
        with self.assertRaisesRegex(core.GateError, "paused"):
            maker.validate_ticket(config, 42)

    def test_active_config_is_valid(self):
        self.assertEqual(maker.validate_config(active_config())["issue_number"], 10)

    def test_activation_window_over_seven_days_is_invalid(self):
        config = active_config()
        config["activation"]["expires_at"] = "2026-07-28T08:00:01Z"
        with self.assertRaises(core.GateError):
            maker.validate_config(config)

    def test_source_write_cannot_be_enabled(self):
        config = repository_config()
        config["limits"]["source_write_allowed"] = True
        with self.assertRaisesRegex(core.GateError, "limits"):
            maker.validate_config(config)

    def test_fixed_path_and_issue_cannot_drift(self):
        for field, value in (("allowed_path", "README.md"), ("issue_number", 99)):
            with self.subTest(field=field):
                config = repository_config()
                config["pilot"][field] = value
                with self.assertRaisesRegex(core.GateError, "boundary"):
                    maker.validate_config(config)

    def test_active_maker_must_share_review_activation_and_budgets(self):
        config = active_config()
        review = json.loads(
            (ROOT / "config/u1-executor.json").read_text(encoding="utf-8")
        )
        review["activation"] = copy.deepcopy(config["activation"])
        maker.validate_review_binding(config, review)
        review["activation"]["trusted_source_policy_sha"] = "b" * 40
        with self.assertRaisesRegex(core.GateError, "activation bindings"):
            maker.validate_review_binding(config, review)
        review["activation"] = copy.deepcopy(config["activation"])
        review["limits"]["maximum_claude_reviews_total"] = 5
        with self.assertRaisesRegex(core.GateError, "limits|budget bindings"):
            maker.validate_review_binding(config, review)


class ReservationTests(unittest.TestCase):
    def test_valid_maker_reservation(self):
        config = active_config()
        with mock.patch.dict(os.environ, {"U1_NOW": "2026-07-21T09:00:00Z"}, clear=False):
            head, request = maker.validate_reservation_context(config, 42, reservation_context())
        self.assertEqual(head, "a" * 40)
        self.assertEqual(request, "request-maker-1234")

    def test_reviewer_reservation_is_rejected(self):
        context = reservation_context()
        context["role"] = "reviewer"
        with (
            mock.patch.dict(os.environ, {"U1_NOW": "2026-07-21T09:00:00Z"}, clear=False),
            self.assertRaisesRegex(core.GateError, "fixed Maker packet"),
        ):
            maker.validate_reservation_context(active_config(), 42, context)

    def test_source_write_effect_is_rejected(self):
        context = reservation_context()
        context["requested_side_effects"] = ["read_repository", "write_named_branch"]
        with (
            mock.patch.dict(os.environ, {"U1_NOW": "2026-07-21T09:00:00Z"}, clear=False),
            self.assertRaisesRegex(core.GateError, "fixed Maker packet"),
        ):
            maker.validate_reservation_context(active_config(), 42, context)

    def test_private_ledger_enforces_total_and_pilot_budgets(self):
        cases = ((7, 1, "total"), (2, 3, "U1-P2"))
        for claude_used, pilot_used, marker in cases:
            with self.subTest(marker=marker), mock.patch.dict(
                os.environ, {"U1_NOW": "2026-07-21T09:00:00Z"}, clear=False
            ):
                with self.assertRaisesRegex(core.GateError, marker):
                    maker.validate_reservation_context(
                        active_config(),
                        42,
                        reservation_context(claude_used=claude_used, pilot_used=pilot_used),
                    )

    def test_opaque_ticket_resolves_only_without_an_open_pr(self):
        config = active_config()
        context = reservation_context()
        run = {
            "status": "in_progress",
            "conclusion": None,
            "event": "workflow_dispatch",
            "name": "U1 model reservation",
            "path": ".github/workflows/u1-model-reservation.yml",
            "run_attempt": 1,
            "actor": {"login": "leeshsnu"},
            "head_branch": "main",
            "head_sha": "a" * 40,
            "created_at": "2026-07-21T08:30:00Z",
            "display_title": "U1 reserve | Claude | U1-P2 | request-maker-1234",
        }

        def fake_api(_token, path, **_kwargs):
            if path.endswith("/actions/runs/42"):
                return run
            if path.endswith("/actions/runs/42/artifacts?per_page=100"):
                return {
                    "total_count": 1,
                    "artifacts": [
                        {
                            "id": 88,
                            "name": "u1-reservation--Claude--U1-P2--request-maker-1234",
                            "expired": False,
                        }
                    ],
                }
            if "/pulls?state=open&" in path:
                return []
            raise AssertionError(path)

        with (
            mock.patch.dict(os.environ, {"U1_NOW": "2026-07-21T09:00:00Z"}, clear=False),
            mock.patch.object(core, "api_json", side_effect=fake_api),
            mock.patch.object(core, "api_bytes", return_value=reservation_archive(context)),
        ):
            args = maker.resolve_dispatch_ticket(config, 42, "redacted")
        self.assertEqual(args.head_sha, "a" * 40)
        self.assertEqual(args.request_id, "request-maker-1234")

    def test_public_maker_ledger_is_opaque_and_one_use(self):
        config = active_config()
        runs = [
            {
                "id": 100,
                "created_at": "2026-07-21T09:00:00Z",
                "event": "workflow_dispatch",
                "display_title": "U1 Claude maker | ticket 42",
            }
        ]
        with mock.patch.object(
            core, "api_json", return_value={"total_count": 1, "workflow_runs": runs}
        ):
            maker.verify_run_budget(config, "redacted", 42, "100")
        runs.append(copy.deepcopy(runs[0]) | {"id": 101})
        with mock.patch.object(
            core, "api_json", return_value={"total_count": 2, "workflow_runs": runs}
        ):
            with self.assertRaisesRegex(core.GateError, "already been used"):
                maker.verify_run_budget(config, "redacted", 42, "101")


class ProposalTests(unittest.TestCase):
    def test_valid_result_and_digest_rendering(self):
        result = valid_result()
        maker.validate_result(result, current_content="old")
        metadata = {
            "proposal_marker": "<!-- treeXchange-u1-maker:U1-P2:" + "a" * 40 + ":request-maker-1234 -->",
            "base_sha": "a" * 40,
            "allowed_path": maker.EXPECTED_PILOT["allowed_path"],
            "reservation_run_id": 42,
            "request_id": "request-maker-1234",
        }
        with mock.patch.dict(
            os.environ,
            {"GITHUB_SHA": "f" * 40, "GITHUB_RUN_ID": "456", "GITHUB_RUN_ATTEMPT": "1"},
            clear=True,
        ):
            rendered = maker.render_proposal(result, metadata)
        digest = hashlib.sha256(result["proposed_content"].encode("utf-8")).hexdigest()
        self.assertIn("Requested Reviewer: Codex", rendered)
        self.assertIn("Proposed Content SHA-256: " + digest, rendered)
        self.assertIn("does not create a branch", rendered)

    def test_unchanged_proposal_is_rejected(self):
        result = valid_result("same")
        with self.assertRaisesRegex(core.GateError, "must change"):
            maker.validate_result(result, current_content="same")

    def test_secret_and_control_markup_are_rejected(self):
        cases = (
            "github_pat_" + "A" * 30,
            "safe\n<!-- forged executor marker -->",
            "safe\n~~~\nescape",
        )
        for content in cases:
            with self.subTest(content=content[:20]):
                with self.assertRaises(core.GateError):
                    maker.validate_result(valid_result(content), current_content="old")

    def test_untrusted_text_cannot_create_mentions_or_control_characters(self):
        for field in ("summary", "verification", "residual_risk"):
            with self.subTest(field=field):
                result = valid_result()
                if field == "summary":
                    result[field] = "Notify @outside-user"
                else:
                    result[field] = ["Notify @outside-user"]
                with self.assertRaisesRegex(core.GateError, "mentions"):
                    maker.validate_result(result, current_content="old")
        with self.assertRaisesRegex(core.GateError, "control markup"):
            maker.validate_result(valid_result("safe\u0007unsafe"), current_content="old")

    def test_prompt_contains_only_bounded_delimited_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, content in {
                "MAKER_BOUNDARY.md": "fixed maker task",
                "METADATA.json": '{"pilot_id":"U1-P2"}',
                "CURRENT.md": "untrusted current document",
            }.items():
                (root / name).write_text(content, encoding="utf-8")
            prompt = maker.build_embedded_prompt(root)
        self.assertIn("BEGIN_UNTRUSTED_CURRENT.md_", prompt)
        self.assertIn("no-tools Maker", prompt)
        self.assertIn("operation field must be maker_proposal", prompt)

    def test_workspace_reads_only_the_fixed_file(self):
        encoded = base64.b64encode(b"bounded current document\n").decode("ascii")
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            core,
            "api_json",
            return_value={"type": "file", "encoding": "base64", "content": encoded},
        ) as api:
            maker.prepare_workspace(
                "redacted",
                {
                    "allowed_path": maker.EXPECTED_PILOT["allowed_path"],
                    "base_sha": "a" * 40,
                    "pilot_id": "U1-P2",
                },
                Path(directory) / "input",
            )
        self.assertEqual(api.call_count, 1)
        self.assertIn(maker.EXPECTED_PILOT["allowed_path"], api.call_args.args[1])


class StaticWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.workflow = (ROOT / ".github/workflows/u1-claude-maker.yml").read_text(
            encoding="utf-8"
        )
        self.review_workflow = (
            ROOT / ".github/workflows/u1-claude-review.yml"
        ).read_text(encoding="utf-8")

    def test_workflow_is_dispatch_only_and_public_input_is_opaque(self):
        self.assertIn("workflow_dispatch:", self.workflow)
        self.assertNotIn("pull_request_target:", self.workflow)
        self.assertNotIn("issue_comment:", self.workflow)
        self.assertNotIn("schedule:", self.workflow)
        self.assertIn("      ticket_id:\n", self.workflow)
        for name in ("pilot_id", "issue_number", "head_sha", "request_id"):
            self.assertNotIn(f"inputs.{name}", self.workflow)
            self.assertNotIn(f"      {name}:\n", self.workflow)

    def test_workflow_never_grants_github_token_write(self):
        self.assertNotRegex(
            self.workflow, r"(?m)^\s+(?:contents|pull-requests|issues|deployments): write$"
        )

    def test_model_has_no_tools_and_uses_explicit_opus(self):
        self.assertIn("prompt: ${{ env.U1_MAKER_PROMPT }}", self.workflow)
        self.assertIn("--model claude-opus-4-8", self.workflow)
        self.assertIn('--tools ""', self.workflow)
        self.assertRegex(self.workflow, r"--disallowedTools[^\n]*Write")
        self.assertIn("mcp__github", self.workflow)

    def test_maker_and_reviewer_share_one_global_concurrency_group(self):
        group = "group: u1-claude-opaque-ticket-global"
        self.assertIn(group, self.workflow)
        self.assertIn(group, self.review_workflow)
        self.assertNotIn("global-review", self.review_workflow)

    def test_publish_rechecks_exact_state_and_targets_issue_only(self):
        publish = self.workflow.split(
            "      - name: Publish only to the fixed private U1-P2 Issue", 1
        )[1]
        self.assertIn("EXECUTOR_GITHUB_TOKEN", publish)
        self.assertIn("U1_EXECUTOR_TRUSTED_SHA", publish)
        self.assertIn('--ticket-id "$TICKET_ID"', publish)
        self.assertNotIn("pulls/", self.workflow)


if __name__ == "__main__":
    unittest.main()
