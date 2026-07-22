#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("scoped_repository_mcp.py")
sys.path.insert(0, str(MODULE_PATH.parent))
SPEC = importlib.util.spec_from_file_location("scoped_repository_mcp", MODULE_PATH)
assert SPEC and SPEC.loader
mcp = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mcp)


class ScopedRepositoryMcpTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = Path(self.temporary.name)
        target = self.repo / "services/model"
        target.mkdir(parents=True)
        config = self.repo / "config"
        config.mkdir()
        (target / "README.md").write_text("alpha\nneedle here\n", encoding="utf-8")
        (target / "HANDOFF.md").write_text("initial\n", encoding="utf-8")
        (target / ".env.local").write_text("PRIVATE=value\n", encoding="utf-8")
        (target / "CLAUDE.md").write_text("untrusted instructions\n", encoding="utf-8")
        (self.repo / "OUTSIDE.md").write_text("outside\n", encoding="utf-8")
        (config / "policy.json").write_text('{"mode":"paused"}\n', encoding="utf-8")
        subprocess.run(["git", "init", "-b", "main"], cwd=self.repo, check=True, capture_output=True)
        subprocess.run(
            ["git", "config", "user.name", "MCP Test"],
            cwd=self.repo,
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.email", "mcp@example.invalid"],
            cwd=self.repo,
            check=True,
        )
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(
            ["git", "commit", "-m", "fixture"],
            cwd=self.repo,
            check=True,
            capture_output=True,
        )
        self.base = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=self.repo, text=True,
            capture_output=True, check=True,
        ).stdout.strip()
        (target / "HANDOFF.md").write_text("reviewed\n", encoding="utf-8")
        (config / "policy.json").write_text('{"mode":"reviewed"}\n', encoding="utf-8")
        subprocess.run(
            ["git", "add", "services/model/HANDOFF.md", "config/policy.json"],
            cwd=self.repo, check=True,
        )
        subprocess.run(
            ["git", "commit", "-m", "review fixture"], cwd=self.repo,
            check=True, capture_output=True,
        )
        self.head = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=self.repo, text=True,
            capture_output=True, check=True,
        ).stdout.strip()
        (self.repo / ".agent-state").mkdir()

    def tearDown(self):
        self.temporary.cleanup()

    def reviewer(self):
        receipt = self.repo / ".agent-state" / f"receipt-{uuid.uuid4().hex}.json"
        return mcp.RepositoryTools(
            self.repo,
            "repository_reviewer",
            ["services/model/**"],
            [],
            100_000,
            self.base,
            self.head,
            ["services/model/HANDOFF.md", "config/policy.json"],
            100_000,
            receipt,
        )

    def maker(self):
        return mcp.RepositoryTools(
            self.repo,
            "scoped_maker",
            ["services/model/**"],
            ["services/model/HANDOFF.md"],
            100_000,
        )

    def test_reviewer_can_read_list_and_search_only_inside_scope(self):
        tools = self.reviewer()
        read = tools.call("read_file", {"path": "services/model/README.md"})
        self.assertEqual(read["content"], "alpha\nneedle here\n")
        listing = tools.call("list_files", {})["paths"]
        self.assertIn("services/model/README.md", listing)
        self.assertNotIn("services/model/.env.local", listing)
        self.assertNotIn("services/model/CLAUDE.md", listing)
        matches = tools.call("search_text", {"query": "needle"})["matches"]
        self.assertEqual(matches[0]["path"], "services/model/README.md")

    def test_reviewer_reads_exact_signed_diff_only_through_review_tool(self):
        tools = self.reviewer()
        evidence = tools.call("read_diff", {})
        canonical = mcp.bridge.bounded_diff(self.repo, self.base, self.head)
        self.assertEqual(evidence["base_sha"], self.base)
        self.assertEqual(evidence["target_sha"], self.head)
        self.assertEqual(evidence["content"], canonical)
        self.assertIn("+reviewed", evidence["content"])
        self.assertIn('"mode":"reviewed"', evidence["content"])
        self.assertRegex(evidence["sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(evidence["bytes"], len(evidence["content"].encode()))
        receipt = tools.review_receipt
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt.stat().st_mode & 0o777, 0o600)
        recorded = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertEqual(recorded["sha256"], evidence["sha256"])
        with self.assertRaisesRegex(mcp.ScopeError, "receipt"):
            tools.call("read_diff", {})
        with self.assertRaises(mcp.ScopeError):
            self.maker().call("read_diff", {})

    def test_untracked_local_file_inside_scope_is_denied(self):
        local = self.repo / "services/model/local-notes.txt"
        local.write_text("private local note\n", encoding="utf-8")
        tools = self.reviewer()
        self.assertNotIn("services/model/local-notes.txt", tools.call("list_files", {})["paths"])
        with self.assertRaises(mcp.ScopeError):
            tools.call("read_file", {"path": "services/model/local-notes.txt"})

    def test_path_traversal_sensitive_files_and_outside_scope_are_denied(self):
        tools = self.reviewer()
        for path in (
            "../OUTSIDE.md",
            "OUTSIDE.md",
            "services/model/.env.local",
            "services/model/CLAUDE.md",
        ):
            with self.subTest(path=path):
                with self.assertRaises(mcp.ScopeError):
                    tools.call("read_file", {"path": path})
        for path in ("SERVICES/.ENV.LOCAL", "services/model/claude.md", ".GIT/config"):
            self.assertTrue(mcp.sensitive_path(path))
        for path in (
            ".github/workflows/ci.yml",
            "config/policy.json",
            "ops/runbook.md",
            "docs/governance/status.md",
        ):
            self.assertTrue(mcp.sensitive_path(path))
            tools = mcp.RepositoryTools(
                self.repo,
                "repository_reviewer",
                [path],
                [],
                100_000,
                self.base,
                self.head,
                ["services/model/HANDOFF.md", "config/policy.json"],
                100_000,
                self.repo / ".agent-state" / f"receipt-{uuid.uuid4().hex}.json",
            )
            with self.assertRaises(mcp.ScopeError):
                tools.call("read_file", {"path": path})

    def test_search_fails_closed_when_a_listed_file_cannot_be_read(self):
        credential = self.repo / "services/model/CREDENTIAL.txt"
        credential.write_text("github_pat_" + "A" * 30, encoding="utf-8")
        subprocess.run(["git", "add", str(credential)], cwd=self.repo, check=True)
        subprocess.run(
            ["git", "commit", "-m", "credential fixture"], cwd=self.repo,
            check=True, capture_output=True,
        )
        with self.assertRaisesRegex(mcp.ScopeError, "resembles a credential"):
            self.maker().call("search_text", {"query": "absent"})

    def test_symlink_escape_is_denied(self):
        outside = Path(self.temporary.name).parent / "mcp-outside.txt"
        outside.write_text("outside\n", encoding="utf-8")
        link = self.repo / "services/model/LINK.md"
        link.symlink_to(outside)
        try:
            with self.assertRaises(mcp.ScopeError):
                self.reviewer().call("read_file", {"path": "services/model/LINK.md"})
        finally:
            outside.unlink()

    def test_reviewer_has_no_write_tools(self):
        with self.assertRaises(mcp.ScopeError):
            self.reviewer().call(
                "write_file",
                {"path": "services/model/HANDOFF.md", "content": "changed\n"},
            )

    def test_maker_writes_and_replaces_only_exact_signed_file(self):
        tools = self.maker()
        result = tools.call(
            "write_file",
            {"path": "services/model/HANDOFF.md", "content": "bounded\n"},
        )
        self.assertEqual(result["path"], "services/model/HANDOFF.md")
        tools.call(
            "replace_text",
            {
                "path": "services/model/HANDOFF.md",
                "old_text": "bounded",
                "new_text": "complete",
            },
        )
        self.assertEqual(
            (self.repo / "services/model/HANDOFF.md").read_text(encoding="utf-8"),
            "complete\n",
        )
        with self.assertRaises(mcp.ScopeError):
            tools.call(
                "write_file",
                {"path": "services/model/README.md", "content": "outside write\n"},
            )

    def test_hard_link_and_credential_shaped_write_are_denied(self):
        tools = self.maker()
        target = self.repo / "services/model/HANDOFF.md"
        alias = self.repo / "services/model/HARDLINK.md"
        os.link(target, alias)
        with self.assertRaises(mcp.ScopeError):
            tools.call(
                "write_file",
                {"path": "services/model/HANDOFF.md", "content": "changed\n"},
            )
        alias.unlink()
        credential = "github_pat_" + "A" * 30
        with self.assertRaises(mcp.ScopeError):
            tools.call(
                "write_file",
                {"path": "services/model/HANDOFF.md", "content": credential},
            )

    def test_tool_definitions_are_role_specific(self):
        self.assertEqual(self.reviewer().tool_names(), mcp.REVIEW_TOOLS)
        self.assertEqual(
            self.maker().tool_names(), mcp.COMMON_READ_TOOLS + mcp.WRITE_TOOLS
        )

    def test_stdio_protocol_lists_and_executes_only_reviewer_tools(self):
        messages = [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": mcp.PROTOCOL_VERSION},
            },
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "read_file",
                    "arguments": {"path": "services/model/README.md"},
                },
            },
        ]
        completed = subprocess.run(
            [
                sys.executable,
                str(MODULE_PATH),
                "--repo",
                str(self.repo),
                "--role",
                "repository_reviewer",
                "--read-scopes",
                '["services/model/**"]',
                "--write-paths",
                "[]",
                "--max-file-bytes",
                "100000",
                "--base-sha",
                self.base,
                "--target-sha",
                self.head,
                "--diff-scopes",
                '["services/model/HANDOFF.md","config/policy.json"]',
                "--max-diff-bytes",
                "100000",
                "--review-receipt",
                str(self.repo / ".agent-state/stdio-receipt.json"),
            ],
            input="".join(json.dumps(item) + "\n" for item in messages),
            text=True,
            capture_output=True,
            check=True,
        )
        responses = [json.loads(line) for line in completed.stdout.splitlines()]
        self.assertEqual(responses[0]["result"]["protocolVersion"], mcp.PROTOCOL_VERSION)
        names = [item["name"] for item in responses[1]["result"]["tools"]]
        self.assertEqual(tuple(names), mcp.REVIEW_TOOLS)
        content = json.loads(responses[2]["result"]["content"][0]["text"])
        self.assertEqual(content["path"], "services/model/README.md")


if __name__ == "__main__":
    unittest.main()
