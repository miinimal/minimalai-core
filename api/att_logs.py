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
