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
3. Keep `config/u1-executor.json` bound to one Season 2 policy SHA, three fixed
   pilots, a seven-day expiry, zero additional spend, and one-model concurrency.
4. Set `U1_EXECUTOR_TRUSTED_SHA` to the approved executor commit.
5. Install the two environment secrets independently through GitHub Settings.
6. Keep `control/pause` and `control/u1-pause` on the Season 2 control Issue
   until the final attended activation decision.

Any missing, inaccessible, stale, duplicate, or malformed state is a denial.

## Residual administrative risk

The repository owner is also its administrator. Branch and environment
protection prevents accidental workflow drift, but it cannot cryptographically
stop the same administrator from changing those settings. U1 therefore forbids
automatic merge and requires a user-approved exact SHA for executor changes.
