# treeXchange Agent Executor

This public repository is the credential-bearing execution boundary for tightly
scoped treeXchange agent pilots. It contains no Season 2 source code and accepts
no caller-supplied prompt.

The executor supports two bounded U1 operations for
`leeshsnu/treeXchange-season2`: Claude exact-Head review of the fixed P1/P3
documentation pilots, and a proposed Claude Maker lane for P2. The Maker lane
can publish a validated full-file proposal only to the fixed private P2 Issue;
it cannot write source, create a branch or PR, or merge. Both workflows are
dispatch-only, share one global concurrency group, and are SHA-bound,
path-bound, and fail-closed. The Maker lane remains `proposed_paused` until its
exact implementation and activation packet receive separate approval.

## Trust boundary

- The executor fetches only one fixed file from the exact base and Head commits.
- Repository content, PR text, and model output are treated as untrusted data.
- Claude receives a fixed prompt containing only delimited sanitized evidence;
  it receives no file, shell, web, GitHub, MCP, or delegation tools.
- Every Claude invocation names its model explicitly. Standard implementation
  and review work uses Opus 4.8; advanced refinement, strategic insight, and
  design work uses Fable 5, with Opus 4.8 as its only fallback. It never
  inherits an account or CLI default.
- The unattended U1 exact-Head review is a standard review and therefore always
  uses Opus 4.8. Fable 5 is not used by this protected workflow. Profile routing
  is configured policy; protected-runtime availability must be verified before
  any future Fable workflow is activated.
- Claude cannot merge, push, deploy, clear pause, or claim general work.
- Model output is schema-validated before a trusted publisher posts it.
- Maker output is limited to one complete proposal for
  `services/model/HANDOFF_NEEDED.md`. It is posted only to private Issue `#10`
  with a content digest and executor provenance; a separate Codex transport
  must apply it and Codex must independently review the resulting exact Head.
- The Maker path deliberately reuses the read/Issues-only Season 2 token. No
  contents-write or pull-request-write credential is introduced.
- The executor never stores Season 2 source or review inputs as artifacts.
- Action logs are public, so private file contents and model output are never
  passed through workflow-expression values or printed. The pinned Claude base
  action receives only an owner-readable prompt-file path, suppresses full
  output, and the trusted executor reads structured output from the private
  Runner execution file before deleting all transient material.
- Public dispatch accepts only one opaque reservation ticket. Pilot, PR, Head,
  and request details are recovered from a bounded private reservation artifact
  only after the protected environment admits the job. The public ledger records
  that opaque ticket and rejects reuse; private reservation counters enforce the
  per-pilot limit across distinct tickets. Workflow-level global concurrency
  serializes executor runs so two copies cannot consume one ticket concurrently.

## Activation

Activation is intentionally attended. A user must approve an exact executor
commit and exact Season 2 policy commit, protect `main`, configure the
`u1-claude` environment, set its trusted-SHA variable to the final merged
executor commit, and install the two environment secrets described in
[SECURITY.md](SECURITY.md).

An `approved_active` packet is necessary but never sufficient. A dispatch still
fails before a model call unless the live environment SHA equals the exact
running commit, the activation window is current, the fixed Issue and source
bindings match, the private reservation is live, the usage ledger is within
budget, the global pause remains present, and the U1 kill switch has been
removed by the attended activation decision. The review and Maker packets use
one attended activation approval and must carry the same complete activation
object, final source SHA, executor SHA, window, and budget bindings.
No automatic merge is authorized.

## Attended local bridge

The repository also contains an attended bootstrap bridge for the user's
already-authenticated local Claude Code account. It reviews an exact Git commit
range from one of the two allowlisted treeXchange repositories. The bridge:

- sends the bounded diff through standard input instead of a command argument;
- starts Claude in non-interactive mode with built-in tools, MCP servers, and
  user/project settings disabled;
- refuses API-key, alternate cloud-provider, alternate config-directory, and
  custom-endpoint environment overrides so the local path uses the default
  Claude Code subscription login;
- verifies, before reserving a call, that the invoking host process can create
  and remove an owner-only probe in the default local debug-state directory used
  by the installed Claude Code CLI. This is a fail-fast host compatibility
  check, not a claim about every Claude Code installation, and it does not grant
  Claude any repository, shell, web, MCP, plugin, or delegation tool;
- routes standard implementation and review work to `claude-opus-4-8`, while
  advanced refinement, strategic insight, and design profiles use
  `claude-fable-5` with Opus 4.8 as their only fallback;
- records the selected task profile and model, and rejects a caller-supplied
  model that conflicts with the fixed profile;
- requires schema-valid output and never resumes a prior Claude session;
- captures Claude stderr only in memory and persists a fixed failure category,
  never the raw error text, so authentication and usage-limit failures remain
  diagnosable without copying credential-bearing output into logs;
- starts Claude with a shared minimal environment that retains only local
  subscription login and basic process variables. Repository tokens, controller
  keys, proxy routing and additional CA-bundle overrides are not inherited;
- rejects credential-like or oversized evidence;
- excludes checked-in `reviews/*.json` audit outputs from later model input so
  they cannot inflate or bias an independent follow-up review, while keeping
  implementation code, configuration, documentation and tests in scope;
- confines review output to the repository being reviewed and stores the call
  ledger under that repository's shared Git metadata, preventing private Season
  2 output from crossing into this public executor while making every linked
  worktree consume the same caps;
- keeps the shared call ledger owner-only, migrates pre-migration worktree-local
  calls into it before recording a new attempt, serializes
  reservations with an OS file lock, and refuses a duplicate
  model review of the same diff. One independent review per approved model is
  allowed for cross-model validation. Calls are bounded to 12 per work-item
  review window, 2 new windows per
  work item per UTC day, and 24 calls per repository per UTC day. Reaching a
  cap pauses only that review lane; it is not a Claude subscription limit.

This bridge proves real Codex-to-Claude invocation before the unattended GitHub
executor is activated. It does not merge, push, deploy, or clear pause controls.
If the installed Claude Code version omits `structured_output`, the bridge can
recover only a response that is exactly one JSON object, has no duplicate keys,
and passes the same strict review schema. Prose, Markdown, surrounding text,
duplicate-key JSON and schema drift are preserved as feedback but force
`CHANGES_REQUESTED`; unstructured output can never authorize continuation.

## Proposed U2 local role workers

`scripts/local_claude_worker.py` is a separate, still-paused foundation for the
local subscription-based U2 loop. It does not weaken or replace the no-tools U1
review bridge. It defines two explicit execution profiles:

- `repository_reviewer` receives only the trusted local `read_diff`,
  `read_file`, `list_files`, and `search_text` tools. The raw diff is never
  embedded in the authority-bearing prompt: `read_diff` derives it from the
  signed exact Base and Head through the same canonical bounded-diff generator
  used to compute the prompt digest and byte count, rechecks the signed
  changed-path scope and returns it as untrusted tool evidence. The trusted MCP
  writes an owner-only one-use receipt; the controller rejects the review unless
  that receipt machine-matches the signed Base, Head, digest and byte count.
  Claude's built-in file tools are disabled. Full-file context under workflow, config, operations and
  governance control paths remains unavailable; only exact signed diff hunks
  may include changes there. The local tool server enforces signed
  repository-relative scopes on every call; shell, network, third-party MCP,
  subagent and edit tools are unavailable, and any resulting worktree change
  quarantines the run.
- `scoped_maker` is available only for the private Season 2 repository. It may
  inspect signed scopes with the same three local tools and receives
  `write_file` and `replace_text` only for signed exact low-risk files. The
  server rejects traversal, sensitive paths, links, oversized or non-UTF-8
  content, credential-shaped content, and local untracked files before access.
  A fixed trusted `git ls-files` inventory allows repository-tracked context plus
  only the exact signed Maker targets. Shell, network, model-controlled Git,
  GitHub, third-party MCP, subagent and protected policy paths remain
  unavailable. The wrapper then independently rejects out-of-scope changes,
  symlinks, binary or oversized changes, credential-shaped content, commit or
  branch drift, incomplete `BLOCKED` edits, and model path claims that differ
  from machine-derived Git evidence.

Every work request is complete, expires within 24 hours, is HMAC-signed by the
deterministic controller, names one exact repository, branch, Base, target Head,
role, path set, model profile, turn cap and acceptance contract, and carries a
single-use nonce plus signed pause-release and budget-reservation evidence.
The nonce, request id and budget-reservation id are each consumed once in the
shared ledger. Requests and outputs stay owner-only under the target repository's
ignored `.agent-state` directory. The call ledger stays owner-only under the repository's
shared Git metadata so linked worktrees cannot create separate budgets. Legacy
calls receive stable source-position identities and are migrated into that
shared ledger, so identical old records stay distinct and deleting an obsolete
worktree cannot erase their budget use. The Claude child process receives only a
minimal environment; controller and GitHub credentials, proxy variables and
additional CA bundles are removed while the local subscription OAuth credential
may be inherited.

Every invocation reserved before Claude starts consumes its daily and window
budget even when the result is later failed or quarantined. Pre-call denials do
not consume a model call. This prevents a buggy or adversarial result from hiding
real usage; the fixed caps remain the spend backstop.

The worker no longer relies on Claude Code's built-in Read/Edit path-rule
precedence for repository isolation. The local MCP server is part of the pinned
executor source and its scope behavior is covered by direct traversal,
sensitive-file, untracked-file, symlink, hard-link, read-only-role and exact-write tests. The
checked-in worker nevertheless remains paused pending a separately reviewed
activation change.

The checked-in U2 config is `proposed_paused`, has no enabled roles, and carries
no approval identity or activation window. `verify-request` may prove that a
signed request and clean worktree are coherent, but `run` denies before a model
call until a separately reviewed packet enables a canonical reviewer-first role
set for at most seven days, an exact executor SHA is installed in
`U2_EXECUTOR_TRUSTED_SHA` and matches the running commit, and the controller key,
pause release, budget and activation packet are approved. Enabling the read-only
Reviewer does not implicitly enable the scoped Maker. The worker never
commits, pushes, opens a PR, merges, deploys or clears a pause. Those remain
deterministic controller responsibilities after machine-derived postconditions
pass.

## OMC collaboration lane

OMC is the trusted, human-readable collaboration runtime for planning,
delegation, and cross-model advice. `omc ask` preserves advisor output under
`.omc/artifacts/ask/`; `omc team` divides bounded work; and `omc ultragoal`
maintains a durable goal ledger. This lane may load the user's Claude settings
and OMC features, so it is used only with trusted repository instructions.

The no-tools bridge above is a separate isolation lane for adversarial review of
untrusted diffs. Disabling OMC there is deliberate containment, not the default
Codex-Claude collaboration design.
