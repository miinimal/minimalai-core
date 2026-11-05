"""Read mode of Attestations (block ATT): public logs MINIMALCULT reads on its own, without their authors' participation.

Each head read is recorded as an observation ("MINIMALCULT observed this signed head at this time"), never as the log's
assertion. Keys are pinned here from the log operator's own published source (checked on 2026-11-04), not fetched on
every read. Reading is polite: one head request per log per hourly run, plus one consistency proof where the log serves one.
A consistency failure is never published at once: it goes to the private table att_divergences with a 72-hour right of
reply (master prompt part III section 5); only the plain fact may be published after that.
Competitor logs (mcp-transparency-log, HISTOR, Plumbline, AxioRank) are added in block DEMO after their formats and terms
are read in full.
Author: Aleksandr Shcherbakov (@miinimal) - MINIMALCULT. License: Apache-2.0 (open core).
"""

LOGS = [
    {
        "id": "rekor.sigstore.dev",
        "name": "Sigstore Rekor (public-good transparency log)",
        "format": "rekor_v1",   # GET /api/v1/log -> signedTreeHead (signed note, ECDSA P-256), treeID; consistency via /api/v1/log/proof
        "head_url": "https://rekor.sigstore.dev/api/v1/log",
        "proof_url": "https://rekor.sigstore.dev/api/v1/log/proof?firstSize={first}&lastSize={second}&treeID={tree_id}",
        # source: GET https://rekor.sigstore.dev/api/v1/log/publicKey (2026-11-04)
        "key": "-----BEGIN PUBLIC KEY-----\n"
               "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwr\n"
               "kBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==\n"
               "-----END PUBLIC KEY-----\n",
        "terms": "public API of the Sigstore public-good instance; one request per hour",
    },
    {
        "id": "sum.golang.org",
        "name": "Go checksum database",
        "format": "note",       # GET /latest -> signed note (Ed25519); consistency would need tiles: not read
        "head_url": "https://sum.golang.org/latest",
        # source: src/cmd/go/internal/modfetch/key.go in github.com/golang/go (2026-11-04)
        "key": "sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8",
        "terms": "public checksum database; one request per hour",
    },
]

# Recipients of the anchoring offer (block DEMO). Formats, keys and terms read in full on 2026-11-04:
# docs/research/READ_MODE_LOGS_2026-11-04.md. AxioRank is not read: its robots.txt disallows /api/ and its terms forbid
# use for a competing product; its tools log publishes no head. Plumbline is not read: HQ decision 2026-11-04 — never named
# publicly, and an observation in the public record would name it (docs/hq/2026-11-04_answer_read_mode.md).
LOGS += [
    {
        "id": "histor.modelmarket.dev",
        "name": "HISTOR",
        "format": "note",       # C2SP checkpoint; consistency proofs served as {"first", "second", "proof": [hex]}
        "head_url": "https://histor.modelmarket.dev/checkpoint",
        "proof_url": "https://histor.modelmarket.dev/api/v1/log/proof/consistency?first={first}&second={second}",
        "proof_field": "proof",
        # source: GET https://histor.modelmarket.dev/api/v1/issuer, checkpoint.vkey (2026-11-04; pinned on first contact per its spec)
        "key": "histor.modelmarket.dev/log+ad3ca066+AfXpkWqXVW93sChXnhKsNzvGLTFAAredl1jLlEjbr4wU",
        "terms": "public unauthenticated API; data CC BY 4.0 with attribution HISTOR (histor.modelmarket.dev); clear User-Agent",
    },
    {
        "id": "github.com/yassinht/mcp-transparency-log",
        "name": "mcp-transparency-log",
        "format": "observatory_head",   # one signed head per UTC day; no proof API (leaves published, not read here)
        "head_url": "https://raw.githubusercontent.com/yassinht/mcp-transparency-log/main/heads/{date}.txt",
        "every_s": 6 * 3600,
        # source: heads/key.pub in the repository and its README (2026-11-04)
        "key": "4DNVWgqiY5HKiGH3PFcKt5O+fn9EmdoTNvj4aYbwQ4E=",
        "terms": "no licence published; head changes once a day; read four times a day",
    },
    {
        "id": "api.mcpcensus.com",
        "name": "MCP Census",
        "format": "census_changes",     # unsigned feed: our own sha256 of the page and its newest event id; payloads not kept
        "head_url": "https://api.mcpcensus.com/v1/changes?since={since}&limit=200",
        "headers": {"X-Census-Client": "minimalcult-record"},
        "terms": "automated access within published limits with a clear User-Agent and X-Census-Client; no resale of raw data",
    },
]
