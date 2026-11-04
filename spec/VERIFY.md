# VERIFY — a paid check of a claim, answered with a signed verdict

Agents cannot prove that something really happened: a task "ran" but nothing arrived, a confirmation proves only a start,
a timestamp can be typed by anyone. VERIFY takes a claim and checks it against the world — the TON chain, the live
resource, the public channel, our own signature — and answers with a signed verdict that any third party can check and that
is anchored in TON with the next daily notary record. It is a RECEIPTS v2 record (`kind: verdict`), so it carries
`delivery` and `distrust` like every other receipt: what we saw, what we assume.

## Call

`POST /v1/verify` with the claim as the body. Pay with a key (`Authorization: Bearer mai-…`, 0.02 GRAM from the balance)
or without a key through GRAM-402 (the first call answers `402` with an invoice; pay; repeat with `X-PAYMENT`). The price
is a test price and is announced as such; competitors charge about 1 USDC per check (staff note, 2026-11-03 — to be
confirmed at their sites before any public comparison). Nothing is charged when the outcome is `unverifiable`. The first
three verifiable checks per key per UTC day are free (`free_checks_left_today` in every answer; `VERIFY_FREE_PER_DAY`), and the
public sandbox `/testnet/v1/verify` runs the same code on test money at no cost — try before paying.

| `type` | claim | `true` when |
|---|---|---|
| `ton_transfer` | `{tx, to}` or `{to, amount_nano, comment, after_ts}` | the incoming transfer is on chain, executed, with that value / comment / time (toncenter API v3, the account's last 300 transactions) |
| `http_delivered` | `{url, expect: {status, sha256, contains}}` | one GET now (public https hosts only, first 64 KB, no redirects) answers the status, hash and text claimed |
| `message_sent` | `{channel, message_id, contains}` | the message is visible on the public preview `t.me/s/<channel>/<id>` with the text claimed; private chats are `unverifiable` — we do not join chats |
| `receipt` | `{record}` | the record's Ed25519 signature is valid for the pinned MINIMAL AI gateway key; other issuers are `unverifiable` |

## Answer

```
{"result": "true" | "false" | "unverifiable", "charged_nano": 20000000 | 0,
 "verdict": {"v": 2, "kind": "verdict", "verdict_id": "v_…", "type": "…", "claim": {…}, "claim_sha256": "…",
             "result": "…", "evidence": {…}, "method": "…", "ts": <check time>, "client": "<pseudonym>",
             "prev_sha256": "…", "delivery": {"status": "executed", …}, "distrust": {"observed": […], "assumed": […]},
             "gateway_key": "…", "sig": "…"},
 "lookup": "GET /v1/verify/v_…", "anchoring": "…notary…"}
```

`evidence` is what the check saw (the transaction hash, value, sender and time; the HTTP status and body hash; the
preview URL; the receipt id). `distrust.assumed` always ends with the one thing a verdict can never say: it describes
the moment the check ran, not the moment the agent claims. Verdicts are hash-chained (`GET /v1/verify/chain`) and every
verdict id is queued for the daily notary record, whose head is written to TON (`GET /v1/notary/chain`).

Tools: `verify_claim` in `minimalai-mcp` (0.25), `python minimalai_world.py` clients call the route directly.

## What VERIFY is not

Not an oracle of truth: a `true` says the world matched the claim when we looked; a `false` says it did not; an
`unverifiable` says we could not look (chain API down, host unreachable, private chat, foreign issuer) — and costs nothing.
Not custody: no money moves through VERIFY except the fee. Not a judge: disputes about work stay in `/v1/disputes`.
