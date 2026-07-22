# PR #5 remediation re-review adjudication

Reviewed range: `9f98582a7f88fe049e232e0d246bea6bba2d5d3a..bc1ec3688fe02cef1adce82998a7d63b947a0f72`

Status: `CHANGES_REQUESTED — non-ASCII publication fix implemented; new exact Head requires re-review`

## Independent results

- The local session record confirms that the elevated review ran on
  `claude-fable-5`. Its JSON text was retained as unstructured feedback and
  forced to `CHANGES_REQUESTED`. It found one open P2 availability defect.
- The local session record confirms that the standard review ran on
  `claude-opus-4-8`. Its response said `APPROVE`, but it reproduced forbidden
  hidden-markup delimiter text inside a finding. The trusted parser therefore
  retained it as unstructured feedback and forced `CHANGES_REQUESTED`.

Both calls reviewed exact diff digest
`95704fe8d48e8b907f7eebfc0c76f75f43c898cc1f6b0b31708bf8d6f784c2a5`.
No merge, activation, dispatch, pause change, source write, or deployment
followed from either response.

## Codex disposition

### Accepted and remediated

1. Fable correctly found that `hmac.compare_digest` rejects non-ASCII `str`
   inputs. Because the fixed Season 2 target contains Korean, publication would
   always fail closed. The trusted publisher now compares UTF-8 byte sequences,
   and the adversarial render/tamper/unchanged tests now use Korean content.
2. Both models produced otherwise useful JSON but included raw hidden-markup
   delimiters while discussing defenses. The local review prompt now requires
   reviewers to describe such patterns without reproducing the blocked literal
   forms, preserving the parser's existing injection defense.

### Closed after evidence check

1. Summary, verification, and residual-risk fields already pass through
   `core.clean_text`, which rejects hidden markup and structured-field
   injection. They are also single-line normalized and mention-filtered.
2. A paused Maker packet may coexist with an active review packet by design.
   The paused Maker cannot reach credentials or a model call; once Maker is
   activated, `validate_review_binding` requires the complete activation object
   and budgets to match.
3. Incomplete or unexpected GitHub run pagination intentionally denies the
   operation. This is bounded availability behavior, not a budget bypass.
4. Shared concurrency replacement and odd manual-dispatch denial remain
   documented fail-closed availability conditions.

## Verification

- The non-ASCII `compare_digest` failure was reproduced locally before the fix.
- Targeted Maker and bridge tests pass.
- Full quality gate: 87 tests passed.
- This adjudication does not approve the new remediation Head. One final Fable
  5 and Opus 4.8 review pair is required before merge consideration.
