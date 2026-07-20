# Security boundary

## Credential ownership

Only the user may install, rotate, or remove credentials. Do not put tokens in
Issues, pull requests, files, logs, artifacts, repository variables, or chat.

The protected `u1-claude` environment will eventually contain:

- `CLAUDE_CODE_OAUTH_TOKEN`: the user's Claude Code credential.
- `SEASON2_REVIEW_TOKEN`: a fine-grained GitHub token restricted to
  `leeshsnu/treeXchange-season2`, with only repository contents read,
  metadata read, Actions read, Issues read/write, and Pull requests read.

The environment variable `U1_EXECUTOR_TRUSTED_SHA` must contain the exact full
commit approved by the user. It is an external binding, not a secret.

Do not configure these values while the activation packet is paused. Never use
the account-wide classic PAT or a token that can write contents, workflows,
administration, deployments, or pull requests.

## Protection requirements

Before activation:

1. Protect and lock `main`; disable force pushes and deletion.
2. Restrict the `u1-claude` environment to the protected `main` branch.
3. Keep `config/u1-executor.json` bound to one Season 2 policy SHA, two fixed
   pilots, a seven-day expiry, zero additional spend, and one-model concurrency.
4. Set `U1_EXECUTOR_TRUSTED_SHA` to the approved executor commit.
5. Install the two environment secrets independently through GitHub Settings.
6. Keep `control/pause` and `control/u1-pause` on the Season 2 control Issue
   until the final attended activation decision.
7. Verify that the repository does not define the `ACTIONS_STEP_DEBUG` secret
   and set `actions_step_debug_disabled_verified` only after that inspection.
8. The public dispatch currently exposes PR, Head SHA, reservation, and request
   identifiers as Actions event metadata. Keep
   `public_dispatch_metadata_accepted` false unless the user explicitly accepts
   this disclosure for a bounded pilot; an opaque private broker is preferred.

Any missing, inaccessible, stale, duplicate, or malformed state is a denial.

## Local bootstrap boundary

`scripts/local_claude_bridge.py` uses the user's existing local Claude Code
login for attended bootstrap reviews. It passes no file, shell, web, MCP, or
delegation tools to Claude. The exact Git diff is supplied as untrusted prompt
evidence, and only schema-valid output is persisted. A local ignored ledger
records call identity, reported usage, and verdict without storing prompt text.
The bridge verifies that the ledger is genuinely ignored by the reviewed Git
repository and serializes call reservations with an OS file lock.
If the CLI omits `structured_output`, only an exact single JSON object with no
duplicate keys that passes the same strict review schema is machine-valid.
Prose, Markdown, surrounding text, duplicate-key JSON or schema drift is
retained as feedback but forces the trusted verdict to `CHANGES_REQUESTED`.

The CLI's `total_cost_usd` value is recorded as reported usage; it must not be
treated as proof of an additional invoice or as proof that a subscription has
no limit. Unattended scheduling remains disabled until a hard cap and exact
activation state are independently verified.

The attended bridge cap is an executor safety policy, not an Anthropic account
limit: at most 6 calls per work-item review window, 2 new windows per work item
per UTC day, and 12 calls per repository per UTC day. Exhausting one window
blocks that Gate while unrelated authorized work can continue.

## Residual administrative risk

The repository owner is also its administrator. Branch and environment
protection prevents accidental workflow drift, but it cannot cryptographically
stop the same administrator from changing those settings. U1 therefore forbids
automatic merge and requires a user-approved exact SHA for executor changes.
