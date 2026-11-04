# Statements — the record as it stood at a moment, signed

Status: v0.1 (2026-11-04). Issuer: MINIMALCULT. Format: RECEIPTS v2, `kind: statement`, ids `stm_…`, hybrid signature
(Ed25519 + ML-DSA-65). License of statements and facts: CC BY 4.0.

## Why

Disputes, audits and incident reviews ask one question: what did this tool look like at that moment? A statement answers it
from the anchored record and can be checked by anyone, years later, without MINIMALCULT.

## Calls

```
GET /v1/records/{id}?as_of=2026-11-05T00:00:00Z                     free: the state at that moment
GET /v1/records/{id}/statements?as_of=2026-11-05T00:00:00Z          paid: issue a signed statement (JSON; format=pdf for a PDF)
GET /v1/records/{id}/statements/{stm_id}[?format=pdf]               the issued statement again
POST /v1/checks {"type": "...", "target": "...", "as_of": "..."}    a check as it would have answered at that moment
GET /base/statements?record=<id>&as_of=<time>                       the same statement paid in USDC on Base (x402)
```

`id` is a `rec_…` id or a source id (`mcp:<registry name>`, `npm:<name>`, `pypi:<name>`). `as_of` is RFC 3339 with a zone.
Before the first observation of the record the answer is `not_on_record_at_as_of` with the date of the first observation,
and nothing is charged.

## Content

`record`, `source_id`, `name`, `as_of`, `created`, `on_record_since`, `latest_version`, `versions_known`, `registry_status`,
and `facts`: for each kind (registry entry, registry status, package artifact, tool descriptions) the latest fact observed at
or before `as_of`, with its `id` (`ver_…`), `version`, `observed_at`, `digest`, the canonical `observation`, its `leaf`, the
`merkle_path`, and the `batch` (record, head, signature, anchors). A fact observed within the last hour may not be sealed yet:
`sealed: false`, `unsealed_facts` counts them, and the statement's own signature is then the only proof of that fact.

## Verify without us

```
pip install "cryptography>=50"
python -m minimalcult verify statement.json --key <receipt_key_ed25519> --pq-key <receipt_key_mldsa65>
```

The tool (sdk/python/minimalcult) checks the hybrid signature; each leaf (sha256 of the canonical observation); each Merkle
path to the batch root; each batch head (sha256 of the canonical batch record) and its hybrid signature; and that every fact
was observed at or before `as_of`. Each batch head is anchored in Bitcoin (OpenTimestamps), an RFC 3161 TSA and Sigstore
Rekor; the proof files are public at the `proof_url` of each anchor.

## Price

0.05 GRAM (key balance or GRAM-402) or 0.10 USD in USDC on Base (x402). Viewing the state at a moment is free.
