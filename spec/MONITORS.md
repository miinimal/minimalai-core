# Monitors — a signed webhook when a record moves

Status: v0.1 (2026-11-04). Issuer: MINIMALCULT. Ids: `mon_…` (monitor), `evt_…` (event).

## Create

```
curl -s https://ai.minimalcult.org/v1/monitors -H 'content-type: application/json' \
  -d '{"record":"mcp:io.github.github/github-mcp-server","url":"https://example.com/webhook"}'
```

The answer holds the monitor and its `secret` (`whsec_…`), shown once. Without a key the monitor belongs to your address and is
managed with `X-Monitor-Secret`; with a key, `GET /v1/monitors` lists yours. MCP clients: tool `monitor_create` at
`https://ai.minimalcult.org/mcp`. `DELETE /v1/monitors/{id}` stops it.

## Events

`POST` to your URL, JSON:

```
{"id": "evt_…", "object": "event", "type": "monitor.triggered", "created": "2026-11-05T01:00:12Z", "monitor": "mon_…",
 "record": "rec_…", "source_id": "mcp:…", "change_type": "description_changed", "what": "tool descriptions changed",
 "version": "1.1.0", "fact": "ver_…", "changed_at": "2026-11-05T00:41:03Z",
 "diff": "https://ai.minimalcult.org/v1/witness/diff?seq=…", "record_url": "…", "statement_url": "…/statements?as_of=…"}
```

`change_type`: `version_published`, `description_changed` (manifest or public tool descriptions), `removed` (registry status
deprecated or deleted), `flagged`. Events are sent for facts already sealed in an hourly batch, right after the cycle that
sealed them, and only for changes made after the monitor was created.

## Signature

Header `MINIMALCULT-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256 of "<t>.<raw body>" with the secret>`; reject a `t` older
than 5 minutes. Header `MINIMALCULT-Event-Id` deduplicates retries. Python:

```
import hmac, hashlib
t, v1 = dict(p.split("=", 1) for p in header.split(","))["t"], dict(p.split("=", 1) for p in header.split(","))["v1"]
ok = hmac.compare_digest(hmac.new(secret.encode(), f"{t}.".encode() + body, hashlib.sha256).hexdigest(), v1)
```

## Delivery

Any 2xx is a delivery. Otherwise retries after 1, 5 and 30 minutes, 2, 6, 12 and 24 hours; a monitor whose URL failed 20 events
in a row is paused. Webhook hosts must be public https; redirects are not followed.

## Without a webhook

`GET /v1/records/{id}/changes` (JSON) and `GET /v1/records/{id}/changes.rss` (RSS 2.0).

## Price

Three monitors per key or address are free. More: 1 USD per monitor per 30 days, USDC on Base through x402 at
`GET /base/monitors?record=<id>&url=<webhook>`.
