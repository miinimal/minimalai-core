"""Web Bot Auth (block G-1): recognise agents that sign their requests with HTTP Message Signatures (RFC 9421) the way
Cloudflare's Web Bot Auth profile describes (draft-meunier-web-bot-auth-architecture; Cloudflare "Verified bots: Web Bot
Auth", read 2026-11-04). Visa's Trusted Agent Protocol builds on the same signatures; the verifier below is the common part.

A signed request carries three headers:
  Signature-Agent: "https://signer.example"            (sf-string; newer drafts: a dictionary  agent="https://…";type=directory)
  Signature-Input: sig1=("@authority" "signature-agent");created=…;expires=…;keyid=<JWK thumbprint>;alg="ed25519";nonce="…";tag="web-bot-auth"
  Signature:       sig1=:<base64 Ed25519 signature>:
The signature covers the RFC 9421 signature base: one line per covered component, then the "@signature-params" line. The
key comes from the signer's directory https://<agent>/.well-known/http-message-signatures-directory (a JWKS); keyid MUST
equal the RFC 7638/8037 thumbprint of the key (sha256 of {"crv","kty","x"} in that order, base64url). Checked offline against
the draft's own test vector (keyid poqkLGiymh… = thumbprint of the RFC 9421 B.1.4 Ed25519 key; the signature verifies).

What we do with it: GET /v1/whoami tells the caller what we saw (free); a verified signer is counted per day (/admin/botauth)
and may be used by routes as a soft identity ("this request came from signer.example"). Nothing is granted on it yet —
block G decides what a recognised agent earns. Limits (as Cloudflare's): no `req`, `bs`, `sf`, `@query-params`, `@status`;
expires - created ≤ 24 h; a nonce is accepted once within its validity. Every fetched directory is somebody else's text: data.
Author: Aleksandr Shcherbakov (@miinimal) - MINIMALCULT.
"""
import base64
import hashlib
import json
import re
import time
import urllib.request

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

TAG = "web-bot-auth"
MAX_LIFETIME = 24 * 3600
SKEW = 300
FORBIDDEN_PARAMS = {"req", "bs", "sf", "name"}
FORBIDDEN_COMPONENTS = {"@query-params", "@status"}
SCHEMA = """
CREATE TABLE IF NOT EXISTS botauth_dirs(host TEXT PRIMARY KEY, jwks TEXT, ts INTEGER);
CREATE TABLE IF NOT EXISTS botauth_nonces(nonce TEXT PRIMARY KEY, exp INTEGER);
CREATE TABLE IF NOT EXISTS botauth_seen(day TEXT, agent TEXT, verified INTEGER, n INTEGER, PRIMARY KEY(day, agent, verified));
"""
_INPUT = re.compile(r'^\s*([A-Za-z0-9_*.-]+)\s*=\s*\((.*?)\)\s*(.*)$', re.S)
_ITEM = re.compile(r'"([^"]+)"((?:;[A-Za-z0-9_*.-]+(?:=(?:"[^"]*"|[^;\s]+))?)*)')
_PARAM = re.compile(r';([A-Za-z0-9_*.-]+)(?:=("[^"]*"|[^;\s]+))?')


def thumbprint(x):
    """RFC 8037 A.3 / RFC 7638: base64url(sha256({"crv":"Ed25519","kty":"OKP","x":x})) with the members in that order."""
    j = json.dumps({"crv": "Ed25519", "kty": "OKP", "x": x}, separators=(",", ":"), sort_keys=True).encode()
    return base64.urlsafe_b64encode(hashlib.sha256(j).digest()).rstrip(b"=").decode()


def _unq(v):
    return v[1:-1] if v and len(v) >= 2 and v[0] == '"' and v[-1] == '"' else v


def parse_input(value):
    """One Signature-Input member -> (label, [(component, {params})], {params}, raw_inner) — raw_inner is reused verbatim in the base."""
    m = _INPUT.match(value or "")
    if not m:
        raise ValueError("Signature-Input is not label=(...);params")
    label, inner, tail = m.group(1), m.group(2), m.group(3)
    comps = [(c, {k: _unq(v) for k, v in _PARAM.findall(ps)}) for c, ps in _ITEM.findall(inner)]
    params = {k: _unq(v) for k, v in _PARAM.findall(tail)}
    return label, comps, params, f"({inner}){tail.strip()}"


def parse_signature(value, label):
    m = re.search(rf'(?:^|,)\s*{re.escape(label)}\s*=\s*:([A-Za-z0-9+/=]+):', value or "")
    if not m:
        raise ValueError("no Signature for label " + label)
    return base64.b64decode(m.group(1))


def parse_agent(value):
    """Signature-Agent as sf-string ("https://a.test") or dictionary (k="https://a.test";type=directory) -> {key or '': url}."""
    v = (value or "").strip()
    if not v:
        return {}
    if v.startswith('"'):
        return {"": _unq(v.split(";")[0].strip())}
    out = {}
    for member in v.split(","):
        k, _, rest = member.strip().partition("=")
        out[k.strip()] = _unq(rest.split(";")[0].strip())
    return out


def signature_base(comps, raw_inner, authority, headers, method="GET", target_uri=None, path=None):
    lines = []
    for name, ps in comps:
        if name in FORBIDDEN_COMPONENTS or set(ps) & FORBIDDEN_PARAMS:
            raise ValueError("unsupported covered component " + name)
        if name == "@authority":
            val = authority
        elif name == "@method":
            val = method.upper()
        elif name == "@target-uri":
            val = target_uri or ""
        elif name == "@path":
            val = path or "/"
        elif name.startswith("@"):
            raise ValueError("unsupported derived component " + name)
        else:
            hv = headers.get(name)
            if hv is None:
                raise ValueError("covered header missing: " + name)
            if "key" in ps:                                   # a dictionary member: its serialized value
                members = parse_agent(hv) if name == "signature-agent" else {}
                if ps["key"] not in members:
                    raise ValueError("dictionary member missing: " + ps["key"])
                val = f'"{members[ps["key"]]}"'
            else:
                val = " ".join(hv.split())
        ident = f'"{name}"' + "".join(f';{k}="{v}"' if v is not None and v != "" else f";{k}" for k, v in ps.items())
        lines.append(f"{ident}: {val}")
    lines.append(f'"@signature-params": {raw_inner}')
    return "\n".join(lines)


def fetch_directory(host, get=None):
    url = f"https://{host}/.well-known/http-message-signatures-directory"
    if get:
        return json.loads(get(url))
    req = urllib.request.Request(url, headers={"Accept": "application/http-message-signatures-directory+json, application/json", "User-Agent": "minimalai-botauth/1 (+https://minimalcult.org)"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read(200_000))


def directory_key(c, host, keyid, now, get=None, ttl=3600):
    """The Ed25519 public key whose thumbprint is keyid, from the cached or fresh directory of host."""
    row = c.execute("SELECT jwks, ts FROM botauth_dirs WHERE host=?", (host,)).fetchone() if c else None
    jwks = None
    if row and now - row["ts"] < ttl:
        jwks = json.loads(row["jwks"])
    if jwks is None or not _find(jwks, keyid):
        jwks = fetch_directory(host, get)
        if c:
            c.execute("INSERT INTO botauth_dirs(host, jwks, ts) VALUES(?,?,?) ON CONFLICT(host) DO UPDATE SET jwks=excluded.jwks, ts=excluded.ts", (host, json.dumps(jwks), now))
    k = _find(jwks, keyid)
    if not k:
        raise ValueError("keyid not in the signer's directory")
    if k.get("nbf") and now < int(k["nbf"]) or k.get("exp") and now > int(k["exp"]):
        raise ValueError("directory key outside its validity")
    return Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(k["x"] + "=" * (-len(k["x"]) % 4)))


def _find(jwks, keyid):
    keys = jwks.get("keys") if isinstance(jwks, dict) else None
    if isinstance(keys, dict):
        keys = [keys]
    for k in keys or []:
        if k.get("kty") == "OKP" and k.get("crv") == "Ed25519" and k.get("x") and thumbprint(k["x"]) == keyid:
            return k
    return None


def verify(headers, authority, c=None, now=None, get=None, method="GET", target_uri=None, path=None):
    """headers: lower-cased name -> value. Returns a dict: verified (bool), agent (host or None), keyid, label, reason."""
    now = now or int(time.time())
    h = {k.lower(): v for k, v in headers.items()}
    out = {"verified": False, "agent": None, "keyid": None, "label": None, "reason": None}
    if "signature-input" not in h or "signature" not in h:
        out["reason"] = "no signature"; return out
    try:
        label, comps, params, raw_inner = parse_input(h["signature-input"])
        out["label"] = label; out["keyid"] = params.get("keyid")
        if params.get("tag") != TAG:
            raise ValueError("tag is not web-bot-auth")
        if params.get("alg", "ed25519") != "ed25519":
            raise ValueError("only ed25519 is verified here")
        for p in ("created", "expires", "keyid"):
            if p not in params:
                raise ValueError("missing parameter " + p)
        created, expires = int(params["created"]), int(params["expires"])
        if created > now + SKEW or expires < now - SKEW or expires - created > MAX_LIFETIME:
            raise ValueError("signature outside its validity window")
        names = [n for n, _ in comps]
        if "@authority" not in names and "@target-uri" not in names:
            raise ValueError("neither @authority nor @target-uri is covered")
        agents = parse_agent(h.get("signature-agent"))
        if not agents:
            raise ValueError("Signature-Agent missing")
        if "signature-agent" not in names:
            raise ValueError("Signature-Agent present but not covered")
        key_member = next((ps.get("key") for n, ps in comps if n == "signature-agent"), None)
        agent_url = agents.get(key_member or "", next(iter(agents.values())))
        if not agent_url.startswith("https://"):
            raise ValueError("Signature-Agent must be an https URL")
        host = agent_url[8:].split("/")[0].lower()
        out["agent"] = host
        if c is not None:
            c.executescript(SCHEMA)
            nonce = params.get("nonce")
            if nonce:
                c.execute("DELETE FROM botauth_nonces WHERE exp<?", (now,))
                if c.execute("SELECT 1 FROM botauth_nonces WHERE nonce=?", (hashlib.sha256(nonce.encode()).hexdigest(),)).fetchone():
                    raise ValueError("nonce already used")
        pub = directory_key(c, host, params["keyid"], now, get)
        base = signature_base(comps, raw_inner, authority, h, method, target_uri, path)
        pub.verify(parse_signature(h["signature"], label), base.encode())
        if c is not None and params.get("nonce"):
            c.execute("INSERT OR IGNORE INTO botauth_nonces VALUES(?,?)", (hashlib.sha256(params["nonce"].encode()).hexdigest(), expires + SKEW))
        out["verified"] = True
    except InvalidSignature:
        out["reason"] = "signature does not verify"
    except (ValueError, KeyError, TypeError, OSError) as e:
        out["reason"] = str(e)[:160]
    except Exception as e:  # noqa: BLE001
        out["reason"] = "directory unreachable: " + str(e)[:120]
    if c is not None and out["agent"]:
        c.execute("INSERT INTO botauth_seen(day, agent, verified, n) VALUES(?,?,?,1) ON CONFLICT(day, agent, verified) DO UPDATE SET n=n+1",
                  (time.strftime("%Y-%m-%d", time.gmtime(now)), out["agent"], int(out["verified"])))
    return out


def setup(app, db, admin):
    from fastapi import Header, Request
    with db() as c:
        c.executescript(SCHEMA)

    @app.get("/v1/whoami")
    def whoami(request: Request):
        """Free: what we see of the caller — a Web Bot Auth signature (verified against the signer's directory) or nothing.
        Agents use it to check their signing before they rely on it."""
        host = (request.headers.get("host") or "").split(":")[0].lower()
        with db() as c:
            r = verify(dict(request.headers), host, c, method=request.method, target_uri=str(request.url), path=request.url.path)
        passport = None
        if r["verified"]:
            with db() as c:
                if "signer" in [x[1] for x in c.execute("PRAGMA table_info(passports)")]:
                    p = c.execute("SELECT id, name FROM passports WHERE signer=?", (r["agent"],)).fetchone()
                    passport = {"id": p["id"], "name": p["name"], "url": f"https://ai.minimalcult.org/v1/passport/{p['id']}"} if p else None
        return {**r, "passport": passport, "authority": host, "standard": "RFC 9421 HTTP Message Signatures, Web Bot Auth profile (tag web-bot-auth)",
                "how": "sign @authority and signature-agent with your Ed25519 key, publish it at https://<your host>/.well-known/http-message-signatures-directory; keyid = JWK thumbprint"}

    @app.post("/v1/passport/{id_}/signer")
    async def link_signer(id_: str, request: Request):
        """G-2: bind a Web Bot Auth signer to a passport, both ways at once. The request itself must carry a verified Web Bot Auth
        signature (proves control of the signer's key), and the body carries `sig` = the passport key's Ed25519 signature over
        `minimalai-signer:<passport id>:<signer host>` (proves control of the passport). After that the passport shows the signer,
        and a signed request from that host is this passport's request."""
        import base64 as _b64
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey as _Pub
        from fastapi import HTTPException
        b = await request.json()
        id_ = id_.lower()[:32]
        host = (request.headers.get("host") or "").split(":")[0].lower()
        with db() as c:
            v = verify(dict(request.headers), host, c, method=request.method, target_uri=str(request.url), path=request.url.path)
            if not v["verified"]:
                raise HTTPException(401, "this request must itself be signed per Web Bot Auth: " + str(v["reason"]))
            row = c.execute("SELECT * FROM passports WHERE id=?", (id_,)).fetchone()
            if not row:
                raise HTTPException(404, "no such passport")
            try:
                _Pub.from_public_bytes(bytes.fromhex(row["pubkey"])).verify(_b64.b64decode(str(b.get("sig") or "")), f"minimalai-signer:{id_}:{v['agent']}".encode())
            except Exception:  # noqa: BLE001
                raise HTTPException(401, f"sign 'minimalai-signer:{id_}:{v['agent']}' with the passport key")
            cols = [r[1] for r in c.execute("PRAGMA table_info(passports)")]
            if "signer" not in cols:
                c.execute("ALTER TABLE passports ADD COLUMN signer TEXT"); c.execute("ALTER TABLE passports ADD COLUMN signer_ts INTEGER")
            c.execute("UPDATE passports SET signer=?, signer_ts=? WHERE id=?", (v["agent"], int(time.time()), id_))
        return {"passport": id_, "signer": v["agent"], "keyid": v["keyid"], "bound": True,
                "meaning": "requests signed by this host are this passport's requests; the passport record now carries the signer"}

    @app.get("/admin/botauth")
    def seen(authorization: str = Header(None), days: int = 28):
        admin(authorization)
        with db() as c:
            rows = c.execute("SELECT day, agent, verified, n FROM botauth_seen WHERE day>=? ORDER BY day DESC, n DESC", (time.strftime("%Y-%m-%d", time.gmtime(time.time() - days * 86400)),)).fetchall()
            dirs = c.execute("SELECT host, ts FROM botauth_dirs ORDER BY ts DESC").fetchall()
        return {"days": days, "seen": [dict(r) for r in rows], "directories_cached": [dict(r) for r in dirs]}
