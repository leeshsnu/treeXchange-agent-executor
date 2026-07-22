# PR #5 final-window cross-model adjudication

Reviewed range: `9f98582a7f88fe049e232e0d246bea6bba2d5d3a..d6dfe4a1e25ce224ded666686f12ba63cb4ca15f`

Status: `CHANGES_REQUESTED — public-log confidentiality remediation implemented; new exact Head requires re-review`

## Independent results

- Fable 5 returned schema-valid `CHANGES_REQUESTED` with one open P1: the
  private Season 2 prompt and unvalidated model output could cross public GitHub
  Action-log expression surfaces.
- Opus 4.8 returned schema-valid `APPROVE` with no open P0, P1, or P2 finding.
- Both reviews were bound to exact diff digest
  `77735fdc406496c8be721d854f211670e9eb2170e53c3fd2ec38eabb202b32a6`.

The Fable P1 overrides the Opus approval until independently closed. No merge,
activation, dispatch, pause change, source write, or deployment followed.

## Codex evidence and disposition

The executor repository was verified as public. The exact pinned
`anthropics/claude-code-action` source was inspected at commit
`3553f84341b92da26052e28acf1aa898f9511f32`:

- the top-level action logs its complete context prompt;
- it transports that prompt through an action input and process environment;
- disabling the report and full output does not suppress that explicit prompt
  log;
- the pinned `base-action` supports `prompt_file`, reads the file privately,
  logs only its path, suppresses full message output, and writes the SDK message
  ledger to the fixed Runner execution file.

Fable's P1 is therefore accepted. Opus's requirement-coverage statement that
private content is never printed was incorrect for the reviewed Head.

## Remediation

1. Both review and Maker workflows now use the same commit's pinned
   `claude-code-action/base-action` entrypoint.
2. The bounded prompt is written once to an owner-readable Runner file. Only
   the fixed file path crosses the action input boundary.
3. The Claude action receives no GitHub token input.
4. Structured output no longer crosses a step-level environment expression.
   Trusted code reads exactly one successful result object from the bounded
   private Runner execution ledger.
5. Cleanup removes prompt inputs, execution ledger, validated result, and
   rendered comment on every outcome.
6. Static tests and the quality gate reject any future prompt environment
   expression or structured-output environment expression.

## Verification

- Exact pinned top-level and base-action sources were inspected through the
  GitHub API.
- Private prompt creation enforces create-once behavior and mode `0600`.
- Execution-ledger parsing rejects malformed, oversized, unsuccessful, missing,
  or duplicate result messages.
- Both workflows remain dispatch-only, no-tools, immutable-SHA pinned, and
  read-only for their default GitHub token.
- Full quality gate: 87 tests passed.
- This record does not approve the remediation Head. A new bounded review
  window and exact-Head approval are required for another model review pair.
