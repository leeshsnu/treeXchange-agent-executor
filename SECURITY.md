# Security boundary

## Credential ownership

Only the user may install, rotate, or remove credentials. Do not put tokens in
Issues, pull requests, files, logs, artifacts, repository variables, or chat.

The protected `u1-claude` environment contains two user-installed secrets whose
values are never readable through GitHub after creation:

- `CLAUDE_CODE_OAUTH_TOKEN`: the user's Claude Code credential.
- `SEASON2_REVIEW_TOKEN`: a fine-grained GitHub token restricted to
  `leeshsnu/treeXchange-season2`, with only repository contents read,
  metadata read, Actions read, Issues read/write, and Pull requests read.

The token name is retained for compatibility, but the bounded Maker lane uses
only its existing contents-read, Actions-read, and Issues-write permissions. It
must not be replaced with a token that can write contents or pull requests.

The environment variable `U1_EXECUTOR_TRUSTED_SHA` must contain the exact full
merged commit approved by the user. It is an external binding, not a secret,
and remains unset until that final commit exists and receives exact-SHA
approval.

Do not configure these values while the activation packet is paused. Never use
the account-wide classic PAT or a token that can write contents, workflows,
administration, deployments, or pull requests.

## Protection requirements

Before activation:

1. Protect and lock `main`; disable force pushes and deletion.
2. Restrict the `u1-claude` environment to the protected `main` branch.
3. Keep `config/u1-executor.json` bound to one Season 2 policy SHA and the two
   fixed review pilots. Keep `config/u1-maker.json` bound to the same exact SHA,
   fixed P2 Issue/path, a seven-day maximum window, zero additional spend,
   source-write disabled, and the same one-model concurrency group.
4. Set `U1_EXECUTOR_TRUSTED_SHA` to the approved executor commit.
5. Install the two environment secrets independently through GitHub Settings.
6. Keep `control/pause` and `control/u1-pause` on the Season 2 control Issue
   until the final attended activation decision.
7. Verify that the repository does not define the `ACTIONS_STEP_DEBUG` secret
   and set `actions_step_debug_disabled_verified` only after that inspection.
8. Verify that public dispatch exposes only the opaque numeric reservation
   ticket. Pilot, PR, Head SHA, request ID, and source paths must be recovered
   from the exact private reservation artifact inside the protected job. Set
   `opaque_dispatch_verified` true only after inspecting the approved executor
   SHA and its workflow inputs.

Any missing, inaccessible, stale, duplicate, or malformed state is a denial.

## Claude Maker proposal boundary

The P2 Maker workflow accepts only an opaque reservation ticket. It resolves
the fixed Issue, base SHA, branch name, and one allowed path from the private
reservation artifact after entering the protected environment. Claude receives
only the current bounded UTF-8 document, fixed Maker boundary, and metadata as
delimited untrusted evidence. All file, shell, GitHub, web, MCP, and delegation
tools are disabled.

Because this executor repository and its Action logs are public, private prompt
or model-output text must never cross a workflow expression. Both Claude lanes
write the bounded prompt to an owner-readable Runner file and pass only that
path to the pinned Claude base action. Full output is disabled. Trusted capture
reads the structured result from the fixed private Runner execution file, and
the cleanup step deletes the prompt, execution ledger, result, and rendered
comment. The credentialed action receives no GitHub token input.

The trusted publisher rejects oversized output, credential-shaped content,
hidden control markup, fence escape text, unchanged proposals, stale leases,
an existing pilot PR, duplicate tickets, duplicate proposal markers, pause
drift, and executor/source SHA drift. A valid proposal is posted only to private
Season 2 Issue `#10`, with its SHA-256 digest and run provenance. It cannot
write source or open a PR. Codex transport and exact-Head review remain separate
steps, and neither the proposal nor its publication authorizes merge.

The render step revalidates the proposal against the exact fetched current
document. Immediately before publication, the trusted publisher revalidates
both files, deterministically renders the expected comment again, and requires
byte-for-byte equality. The displayed content digest therefore covers the same
complete file content that is posted.

The review and Maker workflows share one GitHub concurrency group. GitHub may
replace an older pending run when another run enters the same group; this is a
bounded availability condition, not authorization to consume or reuse the
replaced run's opaque ticket. The replaced operation must receive a new live
reservation and attended dispatch.

## Local bootstrap boundary

`scripts/local_claude_bridge.py` uses the user's existing local Claude Code
login for attended bootstrap reviews. It passes no file, shell, web, MCP, or
delegation tools to Claude. The exact Git diff is supplied as untrusted prompt
evidence, and only schema-valid output is persisted. One owner-only ledger under
the repository's shared Git metadata records call identity, reported usage, and
verdict without storing prompt text. Every linked worktree resolves the same
ledger and OS lock; legacy worktree-local ledgers are included in cap checks and
migrated into the shared ledger before a new attempt is recorded.
Legacy ledgers must be owner-only regular files inside their exact worktree.
Pre-identifier legacy calls receive a deterministic source-position-and-content
identity. Identical old records remain distinct, still consume budget, and are
never silently discarded during migration.
Claude stderr is classified in memory into a fixed non-secret failure category;
raw stderr is neither printed nor persisted.
Before a call reservation is created, the bridge verifies that its host process
can create and remove an owner-only probe in the default Claude Code debug-state
directory. Claude Code requires that local state for startup and authentication.
Granting the wrapper access to its own Claude state is distinct from model tool
authority: the review child still receives no file, shell, web, MCP, plugin or
delegation tools. A denied local state directory fails as
`local_filesystem_denied` without consuming a model-call reservation.
Checked-in `reviews/*.json` outputs remain Git audit evidence but are excluded
from later model input; all implementation-bearing paths remain reviewable.
If the CLI omits `structured_output`, only an exact single JSON object with no
duplicate keys that passes the same strict review schema is machine-valid.
Prose, Markdown, surrounding text, duplicate-key JSON or schema drift is
retained as feedback but forces the trusted verdict to `CHANGES_REQUESTED`.

The CLI's `total_cost_usd` value is recorded as reported usage; it must not be
treated as proof of an additional invoice or as proof that a subscription has
no limit. Unattended scheduling remains disabled until a hard cap and exact
activation state are independently verified.

The attended bridge cap is an executor safety policy, not an Anthropic account
limit: at most 12 calls per work-item review window, 2 new windows per work item
per UTC day, and 24 calls per repository per UTC day. Exhausting one window
blocks that Gate while unrelated authorized work can continue. An exact diff
may consume at most one call per approved model, allowing a bounded Fable 5 and
Opus 4.8 cross-review while still denying repeated calls to either model.

## Proposed U2 local worker boundary

The proposed U2 local worker uses the user's Claude subscription OAuth on the
same logged-in Mac. It refuses Anthropic API-key, custom endpoint and alternate
cloud-provider overrides. A future long-lived `CLAUDE_CODE_OAUTH_TOKEN`, if the
user chooses to generate one with `claude setup-token`, must remain in macOS
Keychain or an equivalent owner-only local secret store. It must never be put in
the public repository, a request, output, ledger, log, Issue, PR or command
argument.

The deterministic controller authenticates each private work request with an
independent key named by `TREEXCHANGE_U2_CONTROLLER_KEY`. That key is not a model
credential and must also remain in an owner-only local secret store. The worker
removes it, GitHub tokens, proxy variables, extra CA bundles and unrelated
environment values before starting Claude. A request signature never authorizes
activation: the protected U2 config
must separately be `approved_active`, and the current checked-in state is
`proposed_paused` with `activation.enabled=false`. An active worker must also
match its running commit to the user's external `U2_EXECUTOR_TRUSTED_SHA`; every
signed request binds distinct pause-release and budget-reservation evidence.

Tool permission is role-specific and deny-first. The read-only Reviewer cannot
edit. The Maker can edit only signed, repository-relative low-risk paths in an
already-created clean `claude/` worktree. Neither profile receives Bash, web,
GitHub, MCP, plugin or subagent tools, and bypass/auto permission modes are
disabled. The CLI receives one available-tool list plus documented
repository-relative Read/Edit permission rules; no second command-line allow
surface is added. Claude never receives the controller key, a GitHub write
token, proxy routing, or additional CA-bundle overrides.
Activation requires a separate attended change and runtime permission probe
against harmless allowed and denied sentinel files for the installed Claude Code
version; static flag construction is not accepted as sufficient proof.

Permission rules are backed by machine-derived postconditions. After the model
returns, the wrapper rechecks the exact branch and commit, derives tracked and
untracked paths from Git, scans bounded UTF-8 content for credential patterns,
rejects symlinks and compares the actual path set to the signed scope and model
claim. Failure leaves the isolated worktree quarantined; it never triggers an
automatic reset, commit, push or publication. Reviewer writes, Maker path drift,
history drift and partial edits behind a `BLOCKED` status are all denial states.

The first U2 activation remains limited to low-risk Season 2 Maker work and
read-only review. The public executor repository itself is never writable by the
Claude Maker profile. Protected policy, governance, workflow, control-plane,
production, customer-data, deployment, spend and public-claim work remain
outside this lane and require their existing attended Gate.

## Residual administrative risk

The repository owner is also its administrator. Branch and environment
protection prevents accidental workflow drift, but it cannot cryptographically
stop the same administrator from changing those settings. U1 therefore forbids
automatic merge and requires a user-approved exact SHA for executor changes.
