# PR #5 cross-model adjudication

Reviewed range: `9f98582a7f88fe049e232e0d246bea6bba2d5d3a..1983612f5e06896714d168774e34e55ecc1788e3`

Status: `CHANGES_REQUESTED — remediation implemented; new exact Head requires re-review`

## Independent results

- Fable 5 returned JSON text that exceeded the trusted summary bound and was
  therefore retained as unstructured feedback with an automatic
  `CHANGES_REQUESTED` verdict. It reported one open P2 and three open P3s.
- Opus 4.8 returned schema-valid JSON with `CHANGES_REQUESTED`. It reported two
  open P2s and three open P3s.

Both calls used the local no-tools bridge, the same exact diff digest
`8a2ea3bc675c0a2b3a7485abb8c931e21bcf512f60fdbba9da8355345a3480ad`, and
separate fixed model identities. No merge, dispatch, pause change, activation,
source write, or deployment followed from either result.

## Codex disposition

### Accepted and remediated

1. Render and publish did not reapply the current-document binding. Render now
   revalidates against the bounded current file, and publish revalidates and
   deterministically re-renders the complete comment before requiring
   byte-for-byte equality.
2. Publish trusted marker and Base SHA checks without independently proving that
   the displayed digest covered the posted fenced content. Exact deterministic
   re-render comparison now binds the digest, content, metadata, and executor
   provenance together.
3. The per-model duplicate relaxation relied on the CLI routing path for its
   allowlist. Call reservation now independently rejects any model outside the
   Fable 5 / Opus 4.8 allowlist.
4. The inline Maker schema had no drift test. A test now compares it with the
   versioned JSON schema.
5. Shared GitHub concurrency may replace an older pending run. SECURITY now
   records this bounded availability behavior and requires a new live
   reservation for a replacement dispatch.
6. README claimed independent activation packets although the implementation
   requires one identical activation object. The documentation now matches the
   single attended activation approval contract.

### Closed after evidence check

1. Fable's P2 environment-file injection concern depended on the unchanged
   shared `append_github_env` implementation being absent from the supplied
   change diff. That implementation derives a content-specific delimiter and
   fails closed if it occurs in the value. A Maker-facing forced-collision test
   now proves the rejection in the remediation diff.
2. Triple backticks cannot escape the tilde fence used by the rendered comment.
   Tilde fence markers and HTML-control markers remain forbidden in proposed
   content.
3. Queue starvation is an availability concern, not an authorization bypass;
   the global group deliberately serializes the only two model workflows and
   the operation budget remains bounded.

## Verification

- Full quality gate: 87 tests passed.
- Maker result validation, rendering, publication binding, model allowlisting,
  schema synchronization, paused defaults, opaque tickets, budgets, immutable
  actions, read-only GitHub token, and YAML/JSON validity were exercised.
- This adjudication does not approve the remediation Head. Fable 5 and Opus 4.8
  must independently review its new exact SHA before merge consideration.
