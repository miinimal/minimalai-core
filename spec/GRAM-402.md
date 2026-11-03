# GRAM-402: pay-per-request for AI agents on TON

Status: draft v0.1 (2026-11-02). Reference implementation: `gateway/pay402.py` (MINIMAL AI gateway).
Author: Aleksandr Shcherbakov (@miinimal).

## Goal

An AI agent that holds only a TON wallet can call a paid AI endpoint and get an answer: no signup, no API key, no
human, no card. Payment is a plain GRAM transfer. The answer comes with a signed receipt and, on COCOON, with the
TEE attestation evidence of the network that computed it.

## Relation to x402

GRAM-402 uses the HTTP 402 message shapes of [x402](https://docs.x402.org) (`accepts`, `X-PAYMENT`,
`X-PAYMENT-RESPONSE`) with a TON-native scheme `ton-transfer`, so x402-aware clients only need a new scheme handler.
Differences from the x402 `exact` scheme:

- no facilitator: the server verifies the transfer on TON directly;
- the payment is a standard wallet transfer with a text comment, which any TON wallet can send (no signed
  authorization object, no custom contract);
- the amount is an upper bound; the overpayment stays as credit on an account bound to the payer's wallet.

## Flow

```
agent                                   server (payTo = server wallet)
  | POST /v1/chat/completions (no auth)   |
  |-------------------------------------->|
  |   402 {accepts:[ton-transfer ...]}    |  invoice (public) + secret (private), amount, expiry
  |<--------------------------------------|
  | GRAM transfer to payTo, comment "mai:<invoice>"   (on TON)
  | POST /v1/chat/completions             |
  |   X-PAYMENT: base64 {payload:{invoice,secret}}    |
  |-------------------------------------->|  find transfer on chain, check comment, amount, secret,
  |   200 answer + receipt                |  tx not used before; credit paid amount; run; charge cost
  |   X-PAYMENT-RESPONSE: base64 {...}    |
  |<--------------------------------------|
```

## Paying the network fee

The payee must receive at least the invoice amount. Send the transfer with the network fee paid on top of the value
(wallet send mode 1, "pay fees separately"). If the fee is taken out
of the value, the transfer arrives short and does not settle the invoice. A short transfer is not lost: the server
credits what arrived to an account bound to the payer's wallet and answers `402` with `"error": "underpaid: ..."` and an
`underpaid` object (`api_key`, `credit_nano`, `tx_hash`, `payer`); the invoice is closed.

## 402 response

```json
{
  "x402Version": 1,
  "error": "payment required",
  "accepts": [{
    "scheme": "ton-transfer",
    "network": "ton-testnet",
    "asset": "GRAM",
    "maxAmountRequired": "10000000",
    "payTo": "0QDIl6cScCeTVp5GLmbbxh8blQLvRXd-0J4T1fVsz7uEVQ_U",
    "resource": "/v1/chat/completions",
    "mimeType": "application/json",
    "maxTimeoutSeconds": 1800,
    "extra": {"invoice": "9f1c2a7b3d4e5f60", "secret": "<private>", "comment": "mai:9f1c2a7b3d4e5f60",
              "expiresAt": 1793619000, "decimals": 9}
  }]
}
```

- `network`: `ton-mainnet` or `ton-testnet`.
- `maxAmountRequired`: nano-GRAM, upper bound for this request (prompt size and `max_tokens` at the server's price).
- `extra.comment`: the exact text comment of the transfer.
- `extra.secret`: returned only to the requester; never put it on chain.

`extra.failureTerms` states, before payment, what happens on each failure: transfer seen after expiry, underpayment,
overpayment, a request that fails after payment, a retried payment (idempotent), the AI being unavailable, withdrawal
of unused credit and disputes. `extra.termsSha256` is the SHA-256 of that object (canonical JSON); the settlement
(`X-PAYMENT-RESPONSE`) repeats it as `terms_sha256`, and marks a repeated claim with `replay: true`.

## Payment

A transfer of at least `maxAmountRequired` nano-GRAM to `payTo` with text comment `extra.comment`, sent before
`expiresAt`. Any wallet version works. The sender address becomes the account owner (`payer`).

## Retry with X-PAYMENT

```
X-PAYMENT: base64({"x402Version":1,"scheme":"ton-transfer","network":"ton-testnet",
                   "payload":{"invoice":"9f1c2a7b3d4e5f60","secret":"<private>"}})
```

Plain JSON is accepted too. Server answers:

| Status | Meaning |
|---|---|
| 200 | settled and answered; `X-PAYMENT-RESPONSE` and `minimalai.payment` carry the settlement |
| 402 + `Retry-After: 5` | transfer not visible on chain yet; repeat the same request |
| 402 | wrong secret, expired, underpaid, or the transaction already settled another invoice |
| 4xx/5xx + `minimalai.payment` | settled, but the request itself failed; credit is kept, use the returned `api_key` |

## Settlement (X-PAYMENT-RESPONSE)

```json
{"success": true, "scheme": "ton-transfer", "network": "ton-testnet", "transaction": "<tx hash>",
 "payer": "0:...", "paid_nano": 30000000, "charged_nano": 1200, "credit_left_nano": 29998800,
 "api_key": "mai-..."}
```

`api_key` is shown once. It spends the remaining credit as a normal `Authorization: Bearer` key.

## Security rules

1. The comment is public on chain, so the invoice id never settles alone: the secret is required. This blocks
   front-running by observers of the chain.
2. A transaction hash settles at most one invoice; an invoice settles once (atomic status change, unique transaction
   hash in the database).
2a. Settlement is idempotent. Repeating the same `X-PAYMENT` (lost response, timeout, two workers retrying at once)
   returns the first settlement: the same transaction, payer and `api_key`. Nothing is credited twice; the repeated
   request is served from the credit already paid. For an underpaid invoice the retry returns the same credited key.
   The key is stored sealed with the invoice secret, which only the agent holds; the server keeps only its SHA-256.
3. Aborted or failed incoming transactions are ignored.
4. Only transfers to `payTo` with the exact comment and at least the quoted amount count.
5. A failed request after settlement never loses the payment: the credit and its key are returned with the error.

## Receipts and confidentiality

Every answer carries a receipt signed with the server's Ed25519 key (published at `/.well-known/minimalai.json`):
request hash, response hash, model, route, time and, on COCOON mainnet, the latest RA-TLS evidence of the proxy
(TDX quote bound to its TLS key, image hash on the root contract allowlist). For GRAM-402 requests the signed
receipt also carries `payment: {network, transaction, payer, charged_nano}`, so the on-chain transfer, the request
and the answer are bound by one signature. Verify with `POST /v1/receipts/verify`.
On the community testnet TEE is not enforced, and receipts state `tee_attested: false`.

## Clients

Python, stdlib only: `sdk/python/gram402.py`. The wallet is a callback, so any TON wallet library works:

```python
from gram402 import Gram402Client
cli = Gram402Client("https://gateway.example", pay=lambda to, nano, comment: wallet.transfer(to, nano, comment),
                    max_nano=50_000_000)
print(cli.chat({"model": "Qwen/Qwen3-8B", "messages": [{"role": "user", "content": "hi"}]}))
```

It pays on 402, retries until the transfer is on chain, keeps the returned key for the remaining credit and pays
again when the credit runs out. `max_nano` caps the price of one request. TypeScript reference agent:
`ops/cocoon-testnet/agent_demo.ts` (@ton/ton wallet).

TypeScript, no dependencies: `sdk/typescript/gram402.ts` (same behaviour as the Python client; test: `sdk/typescript/test.sh`).

MCP (minimalai-mcp): `pay_quote` returns the invoice and a `ton://transfer` link for any wallet, `pay_claim` returns
the answer with the signed receipt once the transfer is on chain, `agent_passport` reads a passport. No key needed.

## Agent passport

`GET /v1/agents/{wallet}/passport` returns a signed, public track record of an agent by its TON wallet (raw or
user-friendly form): number and total of GRAM-402 settlements (each is an on-chain transfer), first and last seen,
accepted marketplace tasks done with the wallet's accounts, and a level (`unknown`, `new`, `active`, `trusted`).
Signed with the same Ed25519 key as receipts; verify the same way. `GET /v1/agents/{wallet}/badge.svg` renders it
as a badge. Prompts, answers and per-request usage are never exposed.

## Facilitator (for other APIs)

Any API can accept GRAM-402 without running chain code: the facilitator at MINIMAL AI issues the invoice, finds the
transfer and confirms it is genuine and unused. Payments go straight to the merchant's own wallet (no custody).

1. Merchant gets a key (`POST /v1/agents/onboard`) and tops it up for fees.
2. On an unpaid request, the merchant's server calls `POST /v1/facilitator/invoices {pay_to, amount_nano, resource}`
   and replies HTTP 402 with the returned `x402` body. The transfer comment is `f402:<invoice>`.
3. When the agent retries with `X-PAYMENT`, the server calls `POST /v1/facilitator/settle {payment: <header>}`;
   on `success` it serves the request and returns `X-PAYMENT-RESPONSE` = `x_payment_response`.
   `POST /v1/facilitator/verify` checks without consuming.

Balance rail: an agent with a MINIMAL AI key may pay a facilitator invoice from its key balance instead of a chain
transfer: `POST /v1/facilitator/pay {invoice, secret}` moves the amount to the merchant key at once (the withdrawable
part stays withdrawable, credit-only GRAM stays credit-only), returns `x_payment` for the retry, and the merchant
settles it like any payment (`rail: balance`, transaction `internal:<invoice>`). A merchant cannot pay its own invoice.
Invoices advertise it in `extra.payFromBalance`; `Gram402Client(balance_key=...)` uses it and falls back to the wallet.

Fee: max(0.001 GRAM, 0.5 %) per settled payment, reserved from the merchant's key when the invoice is created and
released if the invoice expires unpaid (one grace hour after expiry for late confirmations). Terms:
`GET /v1/facilitator`. A transaction settles at most one invoice; invoices are bound to the merchant key that made them.
Merchant helper: `sdk/python/gram402_merchant.py` (`Merchant` calls, and `paywall(app, merchant, {path: nano})` for any
ASGI app: 402 with the invoice, settle once, `402` + `Retry-After` while the transfer is not visible yet). Agents call any
GRAM-402 endpoint with `Gram402Client.call(url)`.

## Bazaar listings

`POST /v1/bazaar/listings` lists an endpoint after a probe: an unpaid request must answer 402 with a `ton-transfer`
accept paying the listed wallet and proving control: the invoice was issued by the lister's facilitator key, or the accept
carries `extra.bazaar` = the `bazaar_token` returned to the lister. Whoever proves control of an endpoint holds its listing
(no squatting). Ranking: distinct payers in 30 days, then paid calls.

## Paying from a TON Agentic Wallet

TON Agentic Wallets (docs.ton.org/onboarding/ai/wallets; developer preview, 2026) give an AI agent a wallet contract of its
own: an SBT (TEP-85) item with "full Wallet V5 functionality", owned by a person, operated by the agent's key, funded with
what the person is willing to risk. For GRAM-402 nothing changes: the invoice is paid by an ordinary internal transfer that
carries the invoice id in the text comment, and the facilitator does not care which contract sent it. From the agent's side
(the `@ton/mcp` tools or `@ton/walletkit`): read the `402` body, take `accepts[].address`, `amount_nano` and `comment`, send
one transfer with that comment — `send_raw_transaction` when the plain `send_ton` tool does not take a comment — then
repeat the request with the `X-PAYMENT` header as described above.

Status (2026-11-03): the flow is written from the published contract and tool descriptions; the proof — an agentic wallet
paying a GRAM-402 invoice on the public testnet — is scheduled (R1) and this paragraph will carry the transaction link when
it lands. The official collection exists on mainnet only (`EQByQ19qvWxW7VibSbGEgZiYMqilHY5y1a_eeSL2VaXhfy07`), so the
testnet proof uses a collection deployed from the same open source (github.com/the-ton-tech/agentic-wallet-contract).

## Next (v0.2)

- top-up of an existing account: comment `mai:k:<account id>`, no new key;
- wallet-signed requests instead of the key (TON Connect `ton_proof` style), so the wallet itself is the credential;
- npm and PyPI packages for the clients above.
