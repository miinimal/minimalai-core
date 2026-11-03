"""Secret scanner for the open core. No dependencies; exits 1 on any finding.

    python tools/secret_scan.py [path ...]   # default: the directory above tools/

Catches: private key blocks, Telegram bot tokens, Anthropic/OpenAI/GitHub/AWS/Google/Slack keys, hard-coded
secret/password/token/mnemonic assignments, 24-word seed phrases, and files that must never be published (.env, *.pem,
*.key). A line can be allowed only with an inline marker `secret-scan: allow` and a reason in review.
"""
import os
import re
import sys

PATTERNS = {
    "private key block": re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----"),
    "telegram bot token": re.compile(r"\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b"),
    "anthropic key": re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}"),
    "openai key": re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9]{32,}"),
    "github token": re.compile(r"\b(?:ghp|gho|ghs|ghu|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}"),
    "aws key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "google key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "slack token": re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    "hard-coded secret": re.compile(
        r"""(?i)\b[\w-]*(?:secret|password|passwd|api_?key|token|mnemonic|seed)[\w-]*\s*[:=]\s*["'][A-Za-z0-9+/_=-]{16,}["']"""),
    "seed phrase": re.compile(r"\b(?:[a-z]{3,8} ){23}[a-z]{3,8}\b"),
}
FORBIDDEN_NAMES = re.compile(r"(?:^\.env(?:\..*)?$|\.pem$|\.key$|\.p12$|id_rsa|id_ed25519)")
SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "dist", "build"}
ALLOW = "secret-scan: allow"


def scan_text(text):
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        if ALLOW in line:
            continue
        for name, rx in PATTERNS.items():
            if rx.search(line):
                out.append((n, name))
    return out


def scan(root):
    findings = []
    for d, dirs, files in os.walk(root):
        dirs[:] = [x for x in dirs if x not in SKIP_DIRS]
        for f in files:
            p = os.path.join(d, f)
            rel = os.path.relpath(p, root)
            if FORBIDDEN_NAMES.search(f) and f != ".env.example":
                findings.append((rel, 0, "forbidden file"))
                continue
            try:
                text = open(p, encoding="utf-8").read()
            except (UnicodeDecodeError, OSError):
                continue
            findings += [(rel, n, name) for n, name in scan_text(text)]
    return findings


def main(argv):
    roots = argv or [os.path.dirname(os.path.dirname(os.path.abspath(__file__)))]
    findings = [f for r in roots for f in scan(r)]
    for rel, n, name in findings:
        print(f"{rel}:{n}: {name}")
    print(f"secret scan: {len(findings)} finding(s)")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
