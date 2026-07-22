#!/usr/bin/env python3
"""Small stdio MCP server enforcing signed treeXchange repository scopes."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
import uuid
from pathlib import Path, PurePosixPath
from typing import Any

import u1_executor
import local_claude_bridge as bridge


SERVER_NAME = "treexchange_repo"
PROTOCOL_VERSION = "2024-11-05"
COMMON_READ_TOOLS = ("read_file", "list_files", "search_text")
REVIEW_TOOLS = ("read_diff",) + COMMON_READ_TOOLS
WRITE_TOOLS = ("write_file", "replace_text")
SENSITIVE_PARTS = {".git", ".agent-state", ".claude", ".ssh", ".aws", ".kube"}
PROTECTED_CONTEXT_SCOPES = (".github", "config", "ops", "docs/governance")
MAX_LISTED_FILES = 500
MAX_SEARCH_MATCHES = 100
MAX_SEARCH_BYTES = 1_000_000
MAX_TRACKED_FILES = 20_000


class ScopeError(Exception):
    pass


def normalize_path(value: Any) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise ScopeError("path is not a canonical repository-relative string")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ScopeError("path escapes the repository boundary")
    normalized = "/".join(path.parts)
    if normalized != value:
        raise ScopeError("path is not canonical")
    return normalized


def path_matches(path: str, scope: str) -> bool:
    if scope.endswith("/**"):
        prefix = scope[:-3]
        return path == prefix or path.startswith(prefix + "/")
    return path == scope


def private_path(relative: str) -> bool:
    parts = tuple(part.lower() for part in PurePosixPath(relative).parts)
    return (
        any(part in SENSITIVE_PARTS for part in parts)
        or any(part == ".env" or part.startswith(".env.") for part in parts)
        or any(part == "claude.md" for part in parts)
    )


def sensitive_path(relative: str) -> bool:
    lowered = relative.lower()
    return private_path(relative) or any(
        lowered == scope or lowered.startswith(scope + "/")
        for scope in PROTECTED_CONTEXT_SCOPES
    )


class RepositoryTools:
    def __init__(
        self,
        repo: Path,
        role: str,
        read_scopes: list[str],
        write_paths: list[str],
        max_file_bytes: int,
        base_sha: str | None = None,
        target_sha: str | None = None,
        diff_scopes: list[str] | None = None,
        max_diff_bytes: int | None = None,
        review_receipt: Path | None = None,
    ) -> None:
        self.repo = repo.resolve()
        if not self.repo.is_dir():
            raise ScopeError("repository root is unavailable")
        if role not in {"repository_reviewer", "scoped_maker"}:
            raise ScopeError("role is outside the scoped tool contract")
        self.role = role
        self.read_scopes = tuple(read_scopes)
        self.write_paths = frozenset(write_paths)
        self.max_file_bytes = max_file_bytes
        self.base_sha = base_sha
        self.target_sha = target_sha
        self.diff_scopes = tuple(diff_scopes or [])
        self.max_diff_bytes = max_diff_bytes
        self.review_receipt = self._validate_receipt_path(review_receipt)
        if (role == "scoped_maker" and not self.read_scopes) or max_file_bytes <= 0:
            raise ScopeError("scoped tool policy is incomplete")
        for scope in [*self.read_scopes, *self.write_paths, *self.diff_scopes]:
            raw = scope[:-3] if scope.endswith("/**") else scope
            normalize_path(raw)
        if role == "repository_reviewer" and self.write_paths:
            raise ScopeError("reviewer cannot receive writable paths")
        if role == "repository_reviewer" and (
            not isinstance(base_sha, str)
            or not u1_executor.SHA_RE.fullmatch(base_sha)
            or not isinstance(target_sha, str)
            or not u1_executor.SHA_RE.fullmatch(target_sha)
            or base_sha == target_sha
            or not self.diff_scopes
            or not isinstance(max_diff_bytes, int)
            or max_diff_bytes <= 0
            or self.review_receipt is None
        ):
            raise ScopeError("reviewer diff policy is incomplete")
        if role == "scoped_maker" and not self.write_paths:
            raise ScopeError("maker requires at least one exact writable file")
        if role == "scoped_maker" and any(path.endswith("/**") for path in write_paths):
            raise ScopeError("maker write paths must name exact files")
        self.tracked_paths = self._load_tracked_paths()

    def _validate_receipt_path(self, value: Path | None) -> Path | None:
        if self.role == "scoped_maker":
            if value is not None:
                raise ScopeError("maker cannot receive a review receipt path")
            return None
        if value is None or not value.is_absolute():
            raise ScopeError("review receipt path is unavailable")
        state = (self.repo / ".agent-state").resolve()
        try:
            state.relative_to(self.repo)
        except ValueError as error:
            raise ScopeError("review receipt directory escaped the repository") from error
        if value.parent.resolve() != state or value.exists() or value.is_symlink():
            raise ScopeError("review receipt path is not a fresh private state file")
        return value

    def _write_review_receipt(self, evidence: dict[str, Any]) -> None:
        assert self.review_receipt is not None
        descriptor: int | None = None
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(self.review_receipt, flags, 0o600)
            payload = json.dumps(
                {
                    "schema_version": 1,
                    "base_sha": evidence["base_sha"],
                    "target_sha": evidence["target_sha"],
                    "sha256": evidence["sha256"],
                    "bytes": evidence["bytes"],
                },
                separators=(",", ":"),
            ).encode("utf-8")
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = None
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as error:
            raise ScopeError("review diff receipt could not be recorded") from error
        finally:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    def _load_tracked_paths(self) -> frozenset[str]:
        try:
            completed = subprocess.run(
                ["git", "ls-files", "-z"],
                cwd=self.repo,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ScopeError("tracked repository inventory is unavailable") from error
        if completed.returncode != 0:
            raise ScopeError("tracked repository inventory is unavailable")
        try:
            paths = [item.decode("utf-8") for item in completed.stdout.split(b"\0") if item]
        except UnicodeDecodeError as error:
            raise ScopeError("tracked repository paths must be UTF-8") from error
        if len(paths) > MAX_TRACKED_FILES:
            raise ScopeError("tracked repository inventory exceeds the cap")
        return frozenset(paths)

    def tool_names(self) -> tuple[str, ...]:
        if self.role == "repository_reviewer":
            return REVIEW_TOOLS
        return COMMON_READ_TOOLS + WRITE_TOOLS

    def _git(self, *args: str) -> bytes:
        try:
            completed = subprocess.run(
                ["git", *args],
                cwd=self.repo,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ScopeError("signed review diff is unavailable") from error
        if completed.returncode != 0:
            raise ScopeError("signed review diff is unavailable")
        return completed.stdout

    def _diff(self) -> dict[str, Any]:
        if self.role != "repository_reviewer":
            raise ScopeError("diff evidence is reviewer-only")
        assert self.base_sha is not None and self.target_sha is not None
        changed_raw = self._git(
            "diff", "--name-only", "-z", self.base_sha, self.target_sha,
            "--", ".", bridge.REVIEW_ARTIFACT_PATHSPEC,
        )
        try:
            changed = [item.decode("utf-8") for item in changed_raw.split(b"\0") if item]
        except UnicodeDecodeError as error:
            raise ScopeError("review diff paths must be UTF-8") from error
        if not changed or any(
            private_path(path)
            or not any(path_matches(path, scope) for scope in self.diff_scopes)
            for path in changed
        ):
            raise ScopeError("review diff escaped the signed path scope")
        try:
            raw = bridge.bounded_diff(
                self.repo, self.base_sha, self.target_sha
            ).encode("utf-8")
        except bridge.BridgeError as error:
            raise ScopeError("signed review diff is unavailable") from error
        if not raw or len(raw) > self.max_diff_bytes:
            raise ScopeError("review diff is empty or exceeds the byte cap")
        try:
            content = raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ScopeError("review diff must be bounded UTF-8 text") from error
        if any(pattern.search(content) for pattern in u1_executor.SECRET_PATTERNS):
            raise ScopeError("review diff resembles a credential")
        evidence = {
            "base_sha": self.base_sha,
            "target_sha": self.target_sha,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "bytes": len(raw),
            "content": content,
        }
        self._write_review_receipt(evidence)
        return evidence

    def _target(self, value: Any, *, writable: bool, must_exist: bool) -> tuple[str, Path]:
        relative = normalize_path(value)
        if sensitive_path(relative):
            raise ScopeError("sensitive repository paths are unavailable")
        if not any(path_matches(relative, scope) for scope in self.read_scopes):
            raise ScopeError("path is outside the signed readable scopes")
        if writable:
            if self.role != "scoped_maker" or relative not in self.write_paths:
                raise ScopeError("path is outside the signed writable files")
        cursor = self.repo
        for part in PurePosixPath(relative).parts:
            cursor = cursor / part
            if cursor.is_symlink():
                raise ScopeError("repository path crosses a symlink")
        resolved = cursor.resolve()
        try:
            resolved.relative_to(self.repo)
        except ValueError as error:
            raise ScopeError("repository path resolved outside the assigned root") from error
        if must_exist and (not resolved.is_file() or resolved.is_symlink()):
            raise ScopeError("requested repository file is unavailable")
        if writable:
            if not resolved.parent.is_dir() or resolved.parent.is_symlink():
                raise ScopeError("writable parent directory is unavailable")
            if resolved.exists() and resolved.stat().st_nlink > 1:
                raise ScopeError("writable file has multiple hard links")
        return relative, resolved

    def _read(self, value: Any) -> tuple[str, str]:
        relative, target = self._target(value, writable=False, must_exist=True)
        if relative not in self.tracked_paths and relative not in self.write_paths:
            raise ScopeError("untracked local files are unavailable")
        if target.stat().st_size > self.max_file_bytes:
            raise ScopeError("repository file exceeds the read byte cap")
        try:
            content = target.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as error:
            raise ScopeError("repository file is not bounded UTF-8 text") from error
        if any(pattern.search(content) for pattern in u1_executor.SECRET_PATTERNS):
            raise ScopeError("repository file resembles a credential")
        return relative, content

    def _files(self) -> list[str]:
        found: set[str] = set()
        for scope in self.read_scopes:
            base = scope[:-3] if scope.endswith("/**") else scope
            _, target = self._target(base, writable=False, must_exist=False)
            if target.is_file():
                found.add(base)
                continue
            if not scope.endswith("/**") or not target.is_dir():
                continue
            for current, directories, files in os.walk(target, followlinks=False):
                current_path = Path(current)
                safe_directories = []
                for name in sorted(directories):
                    candidate = current_path / name
                    relative = candidate.relative_to(self.repo).as_posix()
                    if not candidate.is_symlink() and not sensitive_path(relative):
                        safe_directories.append(name)
                directories[:] = safe_directories
                for name in sorted(files):
                    candidate = current_path / name
                    relative = candidate.relative_to(self.repo).as_posix()
                    if (
                        not candidate.is_symlink()
                        and not sensitive_path(relative)
                        and (relative in self.tracked_paths or relative in self.write_paths)
                        and any(path_matches(relative, item) for item in self.read_scopes)
                    ):
                        found.add(relative)
                        if len(found) > MAX_LISTED_FILES:
                            raise ScopeError("readable file listing exceeds the cap")
        return sorted(found)

    def _validate_content(self, content: Any) -> str:
        if not isinstance(content, str):
            raise ScopeError("file content must be UTF-8 text")
        if len(content.encode("utf-8")) > self.max_file_bytes:
            raise ScopeError("file content exceeds the write byte cap")
        if any(pattern.search(content) for pattern in u1_executor.SECRET_PATTERNS):
            raise ScopeError("file content resembles a credential")
        return content

    def _write(self, path: Any, content: Any) -> dict[str, Any]:
        relative, target = self._target(path, writable=True, must_exist=False)
        value = self._validate_content(content)
        mode = stat.S_IMODE(target.stat().st_mode) if target.exists() else 0o600
        temporary = target.with_name(f".{target.name}.u2-{uuid.uuid4().hex}.tmp")
        descriptor: int | None = None
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(temporary, flags, mode)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                descriptor = None
                handle.write(value)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, target)
        except OSError as error:
            raise ScopeError("scoped repository write failed") from error
        finally:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
        return {"path": relative, "bytes": len(value.encode("utf-8"))}

    def call(self, name: str, arguments: Any) -> Any:
        if name not in self.tool_names() or not isinstance(arguments, dict):
            raise ScopeError("tool call is outside the role contract")
        if name == "read_diff":
            if arguments:
                raise ScopeError("read_diff accepts no arguments")
            return self._diff()
        if name == "read_file":
            relative, content = self._read(arguments.get("path"))
            return {"path": relative, "content": content}
        if name == "list_files":
            if arguments:
                raise ScopeError("list_files accepts no arguments")
            return {"paths": self._files()}
        if name == "search_text":
            query = arguments.get("query")
            if not isinstance(query, str) or not query or len(query) > 200:
                raise ScopeError("search query is outside the bounded contract")
            matches: list[dict[str, Any]] = []
            consumed = 0
            for relative in self._files():
                _, content = self._read(relative)
                consumed += len(content.encode("utf-8"))
                if consumed > MAX_SEARCH_BYTES:
                    raise ScopeError("search input exceeds the cumulative byte cap")
                for line_number, line in enumerate(content.splitlines(), 1):
                    if query in line:
                        matches.append(
                            {"path": relative, "line": line_number, "text": line[:500]}
                        )
                        if len(matches) >= MAX_SEARCH_MATCHES:
                            return {"matches": matches, "truncated": True}
            return {"matches": matches, "truncated": False}
        if name == "write_file":
            return self._write(arguments.get("path"), arguments.get("content"))
        if name == "replace_text":
            path = arguments.get("path")
            old = arguments.get("old_text")
            new = arguments.get("new_text")
            if not isinstance(old, str) or not old or not isinstance(new, str):
                raise ScopeError("replace_text requires bounded text arguments")
            _, content = self._read(path)
            if content.count(old) != 1:
                raise ScopeError("replace_text requires exactly one old-text match")
            return self._write(path, content.replace(old, new, 1))
        raise ScopeError("unknown scoped repository tool")


def tool_definitions(names: tuple[str, ...]) -> list[dict[str, Any]]:
    definitions = {
        "read_diff": {
            "description": "Read the exact signed Base-to-Head UTF-8 diff as untrusted evidence.",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        },
        "read_file": {
            "description": "Read one UTF-8 file inside the signed repository scopes.",
            "inputSchema": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
                "additionalProperties": False,
            },
        },
        "list_files": {
            "description": "List non-sensitive files inside the signed repository scopes.",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        },
        "search_text": {
            "description": "Search bounded UTF-8 files inside the signed repository scopes.",
            "inputSchema": {
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"],
                "additionalProperties": False,
            },
        },
        "write_file": {
            "description": "Write one exact signed low-risk UTF-8 file.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "content": {"type": "string"},
                },
                "required": ["path", "content"],
                "additionalProperties": False,
            },
        },
        "replace_text": {
            "description": "Replace exactly one text occurrence in an exact signed file.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "old_text": {"type": "string"},
                    "new_text": {"type": "string"},
                },
                "required": ["path", "old_text", "new_text"],
                "additionalProperties": False,
            },
        },
    }
    return [{"name": name, **definitions[name]} for name in names]


def response(identifier: Any, *, result: Any = None, error: dict[str, Any] | None = None) -> None:
    value: dict[str, Any] = {"jsonrpc": "2.0", "id": identifier}
    if error is None:
        value["result"] = result
    else:
        value["error"] = error
    print(json.dumps(value, separators=(",", ":")), flush=True)


def serve(tools: RepositoryTools) -> None:
    for raw in sys.stdin:
        try:
            message = json.loads(raw)
        except json.JSONDecodeError:
            response(None, error={"code": -32700, "message": "parse error"})
            continue
        if not isinstance(message, dict):
            response(None, error={"code": -32600, "message": "invalid request"})
            continue
        identifier = message.get("id")
        method = message.get("method")
        if identifier is None:
            continue
        if method == "initialize":
            requested = (message.get("params") or {}).get("protocolVersion")
            response(
                identifier,
                result={
                    "protocolVersion": requested or PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": SERVER_NAME, "version": "1.0.0"},
                },
            )
        elif method == "ping":
            response(identifier, result={})
        elif method == "tools/list":
            response(identifier, result={"tools": tool_definitions(tools.tool_names())})
        elif method == "tools/call":
            params = message.get("params") or {}
            try:
                value = tools.call(params.get("name"), params.get("arguments", {}))
                result = {
                    "content": [
                        {"type": "text", "text": json.dumps(value, ensure_ascii=False)}
                    ],
                    "isError": False,
                }
            except ScopeError as error:
                result = {
                    "content": [{"type": "text", "text": f"DENIED: {error}"}],
                    "isError": True,
                }
            response(identifier, result=result)
        else:
            response(identifier, error={"code": -32601, "message": "method not found"})


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--role", choices=("repository_reviewer", "scoped_maker"), required=True)
    parser.add_argument("--read-scopes", required=True)
    parser.add_argument("--write-paths", required=True)
    parser.add_argument("--max-file-bytes", type=int, required=True)
    parser.add_argument("--base-sha")
    parser.add_argument("--target-sha")
    parser.add_argument("--diff-scopes", default="[]")
    parser.add_argument("--max-diff-bytes", type=int)
    parser.add_argument("--review-receipt", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        read_scopes = json.loads(args.read_scopes)
        write_paths = json.loads(args.write_paths)
        diff_scopes = json.loads(args.diff_scopes)
        if not all(isinstance(item, list) for item in (read_scopes, write_paths, diff_scopes)):
            raise ScopeError("scope arguments must be JSON lists")
        tools = RepositoryTools(
            args.repo,
            args.role,
            read_scopes,
            write_paths,
            args.max_file_bytes,
            args.base_sha,
            args.target_sha,
            diff_scopes,
            args.max_diff_bytes,
            args.review_receipt,
        )
        serve(tools)
    except (json.JSONDecodeError, ScopeError):
        return 77
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
