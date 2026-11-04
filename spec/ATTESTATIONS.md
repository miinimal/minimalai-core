# Attestations — anchoring other logs, services and receipts in the MINIMALCULT record

Status: draft 1, 2026-11-04. Author: Aleksandr Shcherbakov (@miinimal), MINIMALCULT. License: CC BY 4.0.
Implementation: `gateway/attest.py`, `gateway/attest_formats.py`, `gateway/att_logs.py`, `gateway/witness.py`
(`drain_attestations`, `read_logs`); offline verifier: `python -m minimalcult verify` (`sdk/python/minimalcult`).

## 1. Purpose

A log that signs its own heads proves what it says, not when the world could see it. MINIMALCULT is an independent
notary under such logs: it does not judge content and writes no verdicts; it records that a writer presented a payload
(or that MINIMALCULT itself read a public head) at a time, seals that record every hour with a hybrid signature
(Ed25519 + ML-DSA-65) and a Merkle tree, and anchors each seal in OpenTimestamps (Bitcoin), an RFC 3161 TSA and Sigstore
Rekor every hour, and in TON and EAS on Base daily. Anyone can check the result without MINIMALCULT's servers.

No new receipt protocol is introduced. MINIMALCULT accepts the formats already in use and stores each one as it was
presented (or only its hash), next to its own envelope.

## 2. Record types

Every record states its type:

- `assertion` — a registered writer states it; MINIMALCULT checked the writer's signature and, where the format has one,
  the log's or issuer's own signature;
- `observation` — MINIMALCULT read it from a public source on its own ("MINIMALCULT observed this signed head at this
  time"). An observation is never presented as the source's own submission.

## 3. Writers

`POST /v1/writers` with `name`, `method` and its claim; optional `contact` (private, used only for notices) and
`conflicts_of_interest` (public). The writer starts as `pending`; `POST /v1/writers/{id}/verify` runs the proof:

| method | claim | proof |
|---|---|---|
| `domain` | `domain` | `https://<domain>/.well-known/minimalcult-writer.json` |
| `github` | `github_url` (raw.githubusercontent.com or gist.githubusercontent.com) | the file at that URL; identity is the GitHub owner in the URL |
| `web_bot_auth` | `host` | a key of `https://<host>/.well-known/http-message-signatures-directory` signs the text `minimalcult-writer:<writer id>` (send `keyid`, `signature` base64url) |
| `erc8004` | `agent_id` | field `minimalcult_writer_doc` of the ERC-8004 registration file at the identity token's `tokenURI` |

Writer document:

```json
{"minimalcult_writer": "wrt_…",
 "keys": [{"kid": "k1", "kty": "OKP", "crv": "Ed25519", "x": "<base64url public key>"}],
 "logs": [{"origin": "<checkpoint origin line>", "key": "<note vkey or PEM>"}],
 "addresses": ["0x… (EIP-712 receipt signers, optional)"]}
```

One identity is one writer. The public page `/record/writers/{id}` shows the name, identity, method, the date of
verification, the number of attestations and the declared conflicts of interest.

Quarantine: a pending writer may submit up to 20 attestations per 24 hours; they are not recorded or shown. On
verification each one's writer signature is checked against the published keys: valid ones are released, others are
rejected. Quarantined attestations older than 7 days are rejected. A verified writer may submit 5,000 per 24 hours.

## 4. Submitting

`POST /v1/attestations`:

| field | |
|---|---|
| `writer_id` | `wrt_…` |
| `subject` | the log's origin line or its public URL (the record object is `log:` + host and path in lower case) |
| `payload_type` | `checkpoint`, `rfc9162_checkpoint`, `rfc6962_sth`, `sigstore_bundle`, `x402_receipt`, `sha256` |
| `payload` / `payload_hash` | the payload as published (note text; JSON objects), or the SHA-256 for `sha256` |
| `writer_key_ref`, `writer_signature` | `kid` of the writer document; base64url Ed25519 over the signed part |
| `log_key` | for checkpoints and tree heads, unless the writer document lists the log |
| `artifact_sha256`, `sigstore_identity`, `sigstore_issuer` | for Sigstore bundles |
| `client_operation_id` | chosen by the client before the first attempt; repeats return the first attestation |
| `store_payload` | keep receipts and bundles as presented (log heads are always kept: they are public) |
| `fields` | optional envelope fields (section 6) |

Signed part: canonical JSON (keys sorted, no spaces, UTF-8) of
`{"writer_id", "subject", "payload_type", "payload_sha256", "fields", "client_operation_id"}`, absent optional values as
`null`. `payload_sha256` is SHA-256 of the note text as UTF-8, of a JSON payload in canonical form, or the given hash.

Payload checks:

- `checkpoint`, `rfc9162_checkpoint` — C2SP signed note; Ed25519 note keys (`name+hash+base64`) or ECDSA P-256 PEM keys
  (the Sigstore Rekor convention); the body must be a C2SP checkpoint (origin, size, base64 root, extensions);
- `rfc6962_sth` — get-sth JSON; `TreeHeadSignature` over version, type, timestamp, size and root (RFC 6962 section 3.5);
  SHA-256 with ECDSA or RSA, or Ed25519;
- `sigstore_bundle` — standard verification with sigstore-python against the public-good trust root: certificate chain,
  transparency log inclusion, signature over `artifact_sha256`, signer identity and OIDC issuer;
- `x402_receipt` — the receipt of the x402 offer-receipt extension: JWS (EdDSA, ES256, ES256K) whose `kid` resolves in a
  `did:web` document on the host of `resourceUrl`, or EIP-712 (domain `x402 receipt`, version 1, chain id 1) whose
  recovered signer is listed in the writer document's `addresses`;
- `sha256` — no content check: only the fact that this writer presented this digest at this time.

Statuses: `quarantined` → `received` → `recorded` (an observation of the record) → `sealed` (in a signed, anchored
batch). Errors follow `{"error": {type, code, message, next_step, doc_url}}`.

## 5. Envelope and proof

The recorded fact is the envelope:

```json
{"v": 1, "type": "attestation", "id": "att_…", "record_type": "assertion", "writer": "wrt_…", "writer_identity": "domain:…",
 "subject": "…", "payload_type": "checkpoint", "payload_sha256": "…", "payload": "<as presented or null>",
 "verified": {"check": "signed_note", "origin": "…", "tree_size": 24, "root_hash": "…", "log_key": "…", "log_key_id": "…"},
 "fields": null, "client_operation_id": "…", "writer_key_ref": "k1", "writer_signature": "…", "received_at": "2026-11-04T23:00:00Z"}
```

`GET /v1/attestations/{id}/proof` returns the envelope and the fact proof (observation, leaf, Merkle path, batch record,
head, hybrid batch signature, anchors). `python -m minimalcult verify proof.json --key <Ed25519 hex> --pq-key
<ML-DSA-65 hex>` checks: SHA-256 of the canonical envelope equals the observation digest; the leaf, the Merkle path, the
head and the batch signature; and, for checkpoints and tree heads, the log's own signature again with the key carried in
the envelope. Anchors are listed with their proof files.

## 6. Optional envelope fields

Proposed by participants of public Moltbook discussions on 2026-11-04 (threads "A receipt should say which question it
answered", "When a payment succeeds but delivery cannot, who owns the repair?", "What would you test before an agent pays
a new vendor?", "My run log says delivered…"). Per-field attribution is confirmed with the authors before this text is
published in minimalcult/record-spec.

| field | meaning |
|---|---|
| `question` | the decision predicate the payload answers: `subject`, `effect`, `scope`, `evidence_cutoff` |
| `consequence_class` | `authorize`, `block` or `inform`; a record marked `inform` is never upgraded |
| `reconciled_at` | when the writer checked the evidence against the system of record |
| `authority_version` | the policy or authority version the writer applied |
| `void_if` | the condition that makes the record void |
| `client_operation_id` | top-level field (section 4): minted by the client before the first attempt |

## 7. Read mode

MINIMALCULT reads the signed heads of public logs on its own (`gateway/att_logs.py`, keys pinned from each operator's own
published source), once per hourly run, within each log's terms. Each head is recorded as an `observation`. Where the log
serves consistency proofs, the new head is checked against the previous one (RFC 9162 section 2.1.4.2) and the result is
part of the envelope (`consistency.status`: `verified`, `not_available`, `same_head`, `new_origin`).

If two heads are inconsistent (a failed proof, the same size with a different root, a smaller tree), the head is not
recorded; the case goes to a private table with a 72-hour right of reply for the log's operator; after that only the
plain fact may be published, without labels. Logs read on 2026-11-04: Sigstore Rekor (signed note, ECDSA P-256,
consistency proofs) and the Go checksum database (signed note, Ed25519; consistency through tiles is not read).

## 8. Neutrality

The same terms for every writer; records are only appended; MINIMALCULT keeps hashes and minimal metadata, payloads only
when public or when the writer asks; it never issues a verdict about a writer's content; conflicts of interest are public
on the writer's page. Anchoring is free for writers.
