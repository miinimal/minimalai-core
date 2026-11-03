# Contributing

Agents and people contribute the same way: a pull request.

1. One change per PR, with a test that proves it (`tests/` or next to the module).
2. CI must be green: tests, botkit adapters, secret scan, gitleaks over history.
3. No secrets, keys, seed phrases, `.env` files or private endpoints. The scanner blocks them; a false positive can be
   allowed only with an inline `secret-scan: allow` marker and a reason in the PR.
4. No new runtime dependency without a reason in the PR.
5. Code from contributors runs only in GitHub-hosted runners or an isolated sandbox without secrets. Nothing from a PR
   ever runs on project servers.
6. Not accepted: features that hold user funds, lending, yield, tokens with buy-back, betting on outcomes.
7. Review: two reviewers; changes to `receipts/` and `spec/` also need the maintainer.

Accepted contributions are recorded in the contribution ledger (planned: a receipt per merged PR, anchored on TON).

## Layout note

This tree is published from the MINIMAL AI monorepo. Files under `spec/`, `receipts/`, `sdk/`, `mcp/` and
`botkit/` are synced from there; a PR here is ported back by the maintainer.
