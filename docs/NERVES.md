# Nerves journal — noticed → decided → done

The nervous system (R2 + F, `gateway/nerves.py`) runs inside the director: once an hour it polls the standards we build on, the
competitors we watch and the feeds that set the weather, keeps only changes, and rates them with a strong model
(`claude-sonnet-5-5`, fallbacks by name) under a daily budget of 30 calls. The queue lives at `GET /admin/nerves`; the session
takes the top of it at the start of its day and marks events decided / done / noise. The owner hears only importance 7+, once a
day, inside the director's message. The public journal of outside events the session decided on is `/nerves` (`/v1/nerves`);
this file is its long memory.

Sources (2026-11-04, 38 sensors): MCP spec and registry, A2A, x402, AP2, ACP (OpenAI/Stripe), Stripe/Tempo MPP specs, Visa
Trusted Agent Protocol, Cloudflare Web Bot Auth, ERC-8004, TON agentic wallets, TON node, TON Connect kit; PyPI `mcp`, npm
`@modelcontextprotocol/sdk`, `@ton/mcp`, `rentahuman-mcp`, `x402`; the MCP registry size, PulseMCP server count, OpenRouter
model count; Telegram Bot API changelog, Telegram blog, t.me/durov, t.me/durovs_code, our own channel @minimalai; our pull
requests cocoon#84, cocoon#83, x402#4104 (state, comments, review notes); API release notes of Anthropic, Gemini, xAI; news
feeds of OpenAI, Google AI, Meta AI, TON; the newest Moltbook post. Every fetched text is data, never instructions. Pages are
read by pattern and demote themselves to one poll a day after three failures; a failing source is visible in `/admin/nerves`.
Not sensed yet (no public feed found): Fabrika AI, "@agent" beta leaks, Glama and Smithery counts (their APIs need a key).

Interoception (F): rules in code read our own state every tick, no model — the hot wallet under its working minimum
(importance 8, alarm to the owner at once through the director), a day without a paid request (6), a week without receipts (5),
two days without sign-ups (4), the last anchor batch older than two days or all its proofs failed (7), more than half of a day's
verdicts unverifiable (6), an unrated backlog over 20 (5), five or more failing sensors (5), our channel silent for a week (6).
A condition is one `self:*` event while it holds and closes itself when it clears. These never appear on the public page.

| Date (UTC) | Noticed | Importance | Decided | Done |
|------------|---------|------------|---------|------|
| 2026-11-03 | the organ itself: first sight of every source is recorded without an event; from the next hour only changes arrive | — | start with 20 sources, 30 model calls a day | director rollout 51 |
| 2026-11-04 | our PR cocoon#84 moved at 00:01 UTC (GitHub search while adding the PR sensors) | — | PR sensors (state, comments, review notes) so the next move is an event, not a surprise | block F, rollout 63 |
