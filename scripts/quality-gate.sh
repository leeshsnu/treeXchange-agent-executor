#!/usr/bin/env bash
set -euo pipefail

export PYTHONPYCACHEPREFIX="${TMPDIR:-/tmp}/treexchange-executor-pycache"

python3 -m json.tool config/u1-executor.json >/dev/null
python3 -m json.tool config/u1-maker.json >/dev/null
python3 -m json.tool schemas/u1-review-output.schema.json >/dev/null
python3 -m json.tool schemas/u1-maker-output.schema.json >/dev/null
python3 -m json.tool reviews/2026-07-18-executor-pr1-claude-review.json >/dev/null
python3 -m py_compile \
  scripts/u1_executor.py \
  scripts/u1_maker.py \
  scripts/local_claude_bridge.py \
  scripts/test_u1_executor.py \
  scripts/test_u1_maker.py \
  scripts/test_local_claude_bridge.py
python3 -m unittest -v \
  scripts/test_u1_executor.py \
  scripts/test_u1_maker.py \
  scripts/test_local_claude_bridge.py
ruby -e 'require "yaml"; Dir[".github/workflows/*.{yml,yaml}"].each { |path| YAML.parse_file(path) }'
python3 scripts/u1_executor.py validate-config
python3 scripts/u1_maker.py validate-config

if grep -RInE 'uses:[[:space:]]+[^#[:space:]]+@(main|master|v[0-9]+|beta|latest)([[:space:]#]|$)' .github/workflows; then
  echo "workflow action references must use immutable SHAs" >&2
  exit 1
fi

if grep -RInE 'pull_request_target|issue_comment|schedule:' \
  .github/workflows/u1-claude-review.yml \
  .github/workflows/u1-claude-maker.yml; then
  echo "credential workflow must remain dispatch-only" >&2
  exit 1
fi

if grep -nE 'contents:[[:space:]]+write|pull-requests:[[:space:]]+write|issues:[[:space:]]+write|deployments:[[:space:]]+write' \
  .github/workflows/u1-claude-review.yml \
  .github/workflows/u1-claude-maker.yml; then
  echo "executor GITHUB_TOKEN must remain read-only" >&2
  exit 1
fi
