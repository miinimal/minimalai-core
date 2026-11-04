# Checks — a signed "is this clean?" before an agent acts

Status: v0.1 (2026-11-04). Issuer: MINIMALCULT. Record format: RECEIPTS v2, `kind: check`, ids `chk_…`, hybrid signature
(Ed25519 + ML-DSA-65, see RECEIPTS-v1 "Post-quantum hybrid signature").

## Why

Before an agent installs an MCP server, installs a package or pays an address, it needs facts it can show later: what this
thing was, since when it is known, what changed and when, and whether the bytes it is about to run are the bytes others saw.
The record (`/v1/records`) holds that history, sealed hourly and anchored in independent networks. A check answers one
question from it and signs the answer, so the agent (and its owner, auditor or a dispute) can prove what it knew at the moment
it acted.

## Call

```
POST /v1/checks   {"type": "mcp_server", "target": "io.github.github/github-mcp-server"}
GET  /v1/checks/{id}
GET  /base/checks?type=&target=   (paid in USDC on Base through x402; listed in the x402 Bazaar)
```

```
curl -s https://ai.minimalcult.org/v1/checks -H 'content-type: application/json' \
  -d '{"type":"package","target":"pypi:mcp","version":"1.20.0","sha256":"<sha256 of the file you are about to install>"}'
```

The answer is a `check` object: `id`, `created` (RFC 3339), `type`, `target`, `status`, `flags`, `facts`, `changes`,
`record_head`, `price` (`{"amount": 5000000, "currency": "gram", "unit": "nano"}` or `{"amount": 10000, "currency": "usdc"}`),
`signed_record`. Errors: `{"error": {"type", "code", "message", "next_step", "doc_url"}}`. The older `/v1/check` answers the
same with `Deprecation` and `Link` headers (kept at least 12 months).

| type | target | facts |
|---|---|---|
| `mcp_server` | official MCP Registry name, or `mcp:<name>` (alias `mcp_tool`) | witnessed since, versions, registry status, changes of the last 30 days (with diff links), the latest tool list of the public endpoint, package hashes behind the latest version |
| `package` | `npm:<name>` or `pypi:<name>`; `version`; the hash you are about to install (`sha256` of a PyPI file, `integrity` or `shasum` of an npm tarball) | the recorded hashes for that version and whether yours matches |
| `url` | https URL of an MCP remote | the witnessed server that published it and its facts |
| `ton_address` | TON address | OFAC SDN digital-currency list match and the list date |
| `model_endpoint` | — | planned (Witness Certificate) |

## Answer

`status` is a fact class, never a judgement of intent:

- `witnessed` — known to the record, nothing moved in the last 30 days;
- `changed_recently` — known, something moved in the last 30 days (`changes`);
- `hash_mismatch` — the hash you gave differs from every hash recorded for that version (`flags` severity `red`);
- `not_witnessed` — not in the record (yet); no history is not a verdict;
- `sanctions_listed` / `not_listed` — for `ton_address`;
- `unverifiable` — the source of facts is not available right now (never charged).

`flags` are facts with a severity (`info`, `warn`, `red`). `check` is the signed record: the query, the status, flags, facts,
changes, `record_head` (the witness batch head at the time of the check), the price, a pseudonymous client id and
`prev_sha256` (checks form a chain). Every fact that comes from the record carries its observation `seq`, `leaf` and a
`proof` link: record → leaf → Merkle path → signed batch → anchors (OpenTimestamps, RFC 3161, Rekor; daily TON and EAS).

## Price

The first 100 checks a day per key (or per address without a key) are free. Above that: a test price from the key balance,
or GRAM-402 without a key (402 invoice → pay → repeat with `X-PAYMENT`; the payment above the price stays as credit).
`"pay": true` asks for a paid check within the free threshold. x402 USDC on Base: `/base/checks`, $0.01 per check.

## Verify a check without us

1. Ed25519 over the canonical record without `sig`, key `receipt_key_ed25519` of `/.well-known/minimalai.json`.
2. ML-DSA-65 in `pq` over the canonical record without `sig` and `pq`, key `receipt_key_mldsa65`; `pq_key` = its sha256.
3. For each fact with a `proof` link: fold the Merkle path to the batch root, hash the batch record to its head, check the head
   in any anchor.
