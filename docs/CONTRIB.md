# Contribution organ (J10) — how we send work upstream

Version 2026-11-04. Scope: pull requests and standard proposals in other people's large projects — TelegramMessenger/cocoon,
ton-blockchain (core, TON Connect, Agentic Wallets SDK), ton-blockchain/TEPs, x402-foundation/x402, MCP, A2A, ERC-8004, open
agents (OpenClaw, teleton-agent, goose). Only open information, no second accounts, no volume.

## Process
1. Sense — the nervous system watches every PR we opened (state, comments, review notes, commits) and the targets' releases;
   a change is an event rated by a strong model; the panel is `GET /admin/contrib`.
2. Choose — a candidate enters the queue (`POST /admin/contrib/candidates`) with the repository, the idea and why the
   maintainer would want it. Statuses: idea → researching → prepared → opened → merged | declined | dropped.
3. Prepare — in our fork, in the project's style, with its tests passing and, where it touches us, a run on our polygon.
   Quality gate before opening: no duplicate (search issues and PRs), CONTRIBUTING followed, licence compatible, small and
   understandable; any doubt → the owner's review queue.
4. Open — from the account miinimal, at most 1–2 PRs a week per repository (the panel refuses a third); the text states the
   problem, the change, and what was measured — nothing promotional.
5. Follow — answer within a day; after about seven days of silence one polite reminder (the panel lists `reminders_due`);
   approvals from accounts without write access do not count as acceptance.
6. Record — only a merged PR or an accepted TEP goes to the decisions journal, /backers and a post, and only as the fact.
   Knowledge about the project (who reviews, what they value) goes to the map of relationships.

## Open today (2026-11-04)
TelegramMessenger/cocoon #80, #81, #82, #83, #84; TelegramMessenger/cocoon-contracts #8; x402-foundation/x402 #4104 (draft,
waits for the owner's GPG signature). None merged yet; none is presented as an achievement.
