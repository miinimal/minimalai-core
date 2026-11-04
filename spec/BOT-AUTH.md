# Signed agents — Web Bot Auth at MINIMAL AI

Version 2026-11-04 (block G-1). Standard: HTTP Message Signatures (RFC 9421), Web Bot Auth profile
(draft-meunier-web-bot-auth-architecture → draft-ietf-webbotauth-httpsig-protocol; Cloudflare "Verified bots: Web Bot Auth").
Visa's Trusted Agent Protocol builds on the same signatures. What is written here was checked against the draft's own test
vector on 2026-11-04: the keyid in the examples is the JWK thumbprint of the RFC 9421 B.1.4 Ed25519 key, and the signature
verifies over the base below.

## What an agent sends
```
Signature-Agent: "https://bot.example"
Signature-Input: sig1=("@authority" "signature-agent");created=1762200000;expires=1762200060;keyid="<thumbprint>";alg="ed25519";nonce="<random>";tag="web-bot-auth"
Signature: sig1=:<base64 Ed25519 signature>:
```
Signature base (RFC 9421), signed with the agent's Ed25519 key:
```
"@authority": ai.minimalcult.org
"signature-agent": "https://bot.example"
"@signature-params": ("@authority" "signature-agent");created=…;expires=…;keyid="…";alg="ed25519";nonce="…";tag="web-bot-auth"
```
The newer drafts write `Signature-Agent` as a dictionary (`agent2="https://bot.example";type=directory`) and cover it as
`"signature-agent";key="agent2"`; both forms are accepted. `keyid` is the RFC 8037 thumbprint: base64url of
sha256(`{"crv":"Ed25519","kty":"OKP","x":"<x>"}`). The key is published at
`https://bot.example/.well-known/http-message-signatures-directory` as a JWKS (`{"keys":[{"kty":"OKP","crv":"Ed25519","x":"…"}]}`).

## What we check
tag `web-bot-auth`; `created`, `expires`, `keyid` present; `expires − created ≤ 24 h`, five minutes of clock skew; `@authority`
or `@target-uri` covered; `Signature-Agent`, when present, covered; no `req`, `bs`, `sf`, `name` parameters and no
`@query-params`/`@status` (the same limits Cloudflare applies); the key from the signer's directory (cached one hour) whose
thumbprint equals `keyid`; the Ed25519 signature over the base; the nonce once within its validity.

## What it gives
`GET /v1/whoami` (free) returns `verified`, `agent` (the signer's host), `keyid`, `reason` — an agent checks its signing before
relying on it. Verified signers are counted per day (`/admin/botauth`). Nothing is granted on the signature yet: it is a
recognised identity ("this request came from bot.example"), to be joined with the passport in the next part of block G.
Code: `gateway/botauth.py` (mirrored in the open core as `passport/botauth.py`), test `gateway/test_botauth.py`.
