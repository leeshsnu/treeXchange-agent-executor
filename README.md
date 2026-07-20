# treeXchange Agent Executor

This public repository is the credential-bearing execution boundary for tightly
scoped treeXchange agent pilots. It contains no Season 2 source code and accepts
no caller-supplied prompt.

The first supported operation is a Claude exact-Head review for the fixed U1
documentation pilots in `leeshsnu/treeXchange-season2`. The workflow is
dispatch-only, serial, SHA-bound, path-bound, and fail-closed. It remains inert
until a user approves and installs every activation value and credential.

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
- The executor never stores Season 2 source or review inputs as artifacts.
- Action logs are public, so private file contents and model output are never
  printed.
- Public dispatch accepts only one opaque reservation ticket. Pilot, PR, Head,
  and request details are recovered from a bounded private reservation artifact
  only after the protected environment admits the job. The public ledger records
  that opaque ticket and rejects reuse; private reservation counters enforce the
  per-pilot limit across distinct tickets. Workflow-level global concurrency
  serializes executor runs so two copies cannot consume one ticket concurrently.

## Activation

Activation is intentionally not automated. A user must approve an exact
executor commit and exact Season 2 policy commit, lock/protect `main`, configure
the `u1-claude` environment, set its trusted-SHA variable, and install the two
environment secrets described in [SECURITY.md](SECURITY.md).

Until then, `config/u1-executor.json` is `proposed_paused`, and every dispatch
stops before any credential or model call is used.

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
- routes standard implementation and review work to `claude-opus-4-8`, while
  advanced refinement, strategic insight, and design profiles use
  `claude-fable-5` with Opus 4.8 as their only fallback;
- records the selected task profile and model, and rejects a caller-supplied
  model that conflicts with the fixed profile;
- requires schema-valid output and never resumes a prior Claude session;
- rejects credential-like or oversized evidence;
- excludes checked-in `reviews/*.json` audit outputs from later model input so
  they cannot inflate or bias an independent follow-up review, while keeping
  implementation code, configuration, documentation and tests in scope;
- confines the review output and ignored ledger to the repository being
  reviewed, preventing a private Season 2 review from crossing into this public
  executor repository;
- keeps a private, ignored call ledger, records failed attempts before invoking
  Claude, serializes reservations with an OS file lock, and refuses duplicate
  diffs. Calls are bounded to 6 per work-item review window, 2 new windows per
  work item per UTC day, and 12 calls per repository per UTC day. Reaching a
  cap pauses only that review lane; it is not a Claude subscription limit.

This bridge proves real Codex-to-Claude invocation before the unattended GitHub
executor is activated. It does not merge, push, deploy, or clear pause controls.
If the installed Claude Code version omits `structured_output`, the bridge can
recover only a response that is exactly one JSON object, has no duplicate keys,
and passes the same strict review schema. Prose, Markdown, surrounding text,
duplicate-key JSON and schema drift are preserved as feedback but force
`CHANGES_REQUESTED`; unstructured output can never authorize continuation.

## OMC collaboration lane

OMC is the trusted, human-readable collaboration runtime for planning,
delegation, and cross-model advice. `omc ask` preserves advisor output under
`.omc/artifacts/ask/`; `omc team` divides bounded work; and `omc ultragoal`
maintains a durable goal ledger. This lane may load the user's Claude settings
and OMC features, so it is used only with trusted repository instructions.

The no-tools bridge above is a separate isolation lane for adversarial review of
untrusted diffs. Disabling OMC there is deliberate containment, not the default
Codex-Claude collaboration design.
