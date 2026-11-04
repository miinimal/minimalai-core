# Map of relationships (J2)

Started 2026-11-04 from the ecosystems we actually touch (the staff's starting list of partners was not received by this
session; add it here when it arrives). One line per counterpart: what of theirs we build on, where we meet them, what is
open between us, and the next step. Only facts; no invented contacts. Knowledge learned from pull requests and reviews
(who reviews, what they value) goes here, per the contribution process (docs/CONTRIB.md).

| Counterpart | What we build on | Where we meet | Open between us (2026-11-04) | Next step |
|---|---|---|---|---|
| Telegram — Cocoon (TelegramMessenger/cocoon, cocoon-contracts) | confidential compute for our answers; our worker node | PRs #80–#84, cocoon-contracts #8; our explorer miinimal.github.io/cocoon-explorer | five PRs open, none merged; #84 measured 24/0 → 12/12 on testnet | answer reviews within a day; no new PRs until they move (J10) |
| TON Tech (the-ton-tech/agentic-wallet-contract) | Agentic Wallets: an agent pays our 402 from its own wallet | testnet run 030: wallet kQAKG0SS… paid invoice be5c4063… | nothing open | candidate: an end-to-end 402 example for their repository (contrib queue) |
| TON Foundation (ton-blockchain/TEPs, ton, ton-connect/kit) | the chain, TON Connect, naming (*.minimalcult.ton) | sensors on releases; City Hall contract in testnet | no TEP yet | two TEP candidates: receipts for agent work; 402 from Agentic Wallets |
| x402 Foundation / Coinbase (x402-foundation/x402, CDP) | the 402 message shapes; USDC on Base through CDP | Draft PR #4104 (native TON in the exact scheme); CDP account; Base Sepolia faucet | PR waits for signed commits and two reviewer comments; CDP keys not yet in basepay.env | owner: GPG + keys; session: answer the comments once the owner can post |
| Anthropic (MCP, registry, API) | MCP server minimalai-mcp; the analysis model of the nervous system; the fallback chain | official MCP Registry entry io.github.miinimal/minimalai-mcp (0.24 active, 0.25 to republish); PyPI | registry republish for 0.25 is a manual workflow_dispatch | republish; keep the server current |
| Google (A2A) | agent card and JSON-RPC at /a2a | /.well-known/agent-card.json, grade A on their validator | — | candidate: an A2A sample with paid skills (contrib queue) |
| ERC-8004 (erc-8004/erc-8004-contracts) | identity and reputation registries on Base | world identity agentId 10562; feedback tx 0x39efc0…4586 (Base Sepolia) | mainnet not yet | candidate: reference feedback writer in their docs |
| Cloudflare (web-bot-auth) | Web Bot Auth: signed agents | /v1/whoami verifies their profile; sensor on the repository | — | list ourselves as a verifier once their directory of verifiers exists |
| Visa (trusted-agent-protocol) | the same HTTP signatures, Visa's profile | sensor on the repository | profile not implemented | read the spec; implement when a merchant flow needs it |
| Stripe / Tempo (tempoxyz/mpp-specs) | Machine Payments Protocol | sensor on the specs repository | — | watch; compare with GRAM-402 states |
| OpenAI / Stripe (agentic-commerce-protocol) | ACP: checkout between agents and merchants | sensor on the repository | — | watch; map our receipts to their order objects when relevant |
| Sigstore (rekor) | the Rekor transparency log anchors our daily root | logIndex 3685368225 (batch ab_611f1e58684d) | v2 migration when v1 refuses | watch rekor-tiles |
| Ethereum Attestation Service (Base) | daily root attested on chain | schema registered, attestation 0xf4b49317… | mainnet later | — |
| OpenTimestamps, FreeTSA | Bitcoin and RFC 3161 anchors | daily batches attested | — | — |
| Moltbook | the agents' social network; our agent minimalai_tg | profile verified; read-only sensor on new posts | app key for the API — owner | — |
| Block (goose) | agent framework with an extension directory | grant application sent (goose) | — | candidate: list minimalai-mcp as an extension |
| PulseMCP, Glama, Smithery | catalogs where agents choose tools | — | listings need the owner's GitHub sign-in | docs/AUTHORITY.md steps |
| DigitalOcean | the server MINIMALCULTBOT; Startups program | customer | credits application — owner | GRANTS.md calendar |
| Spaceship | the domain minimalcult.org | API key in the runner's secrets | DNS records for GSC/Bing/GitHub — tokens from the owner | add records through the API when tokens arrive |
| Devpost, Gitcoin, ETHGlobal, @contest | hackathons and grants | sensors (V5) | — | GRANTS.md calendar |
