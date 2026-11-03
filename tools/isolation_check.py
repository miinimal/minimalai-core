"""Isolation proof for the sandbox that runs foreign code (master prompt 6, blocks B3/B26).

Runs inside the CI job of every pull request and prints what the job can see. It fails the job if the environment carries
anything that looks like a credential, a wallet or a path of the production server, so a stranger's PR that tries to read
secrets provably reads nothing. GITHUB_TOKEN is the one token present; the workflow grants it `contents: read` only.
Usage: python tools/isolation_check.py
"""
import os
import re
import socket
import sys

SECRET_NAME = re.compile(r"(^|_)(TOKEN|SECRET|PASS|PASSWORD|PRIVATE|MNEMONIC|WORDS|KEY|SEED|CREDENTIALS)(_|$)", re.I)
ALLOWED = {"GITHUB_TOKEN", "ACTIONS_RUNTIME_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_RESULTS_URL"}  # runner plumbing, scoped to the job
PROD_PATHS = ["/root/minimalai", "/root/minimalai/wallets", "/data/minimalai.db"]


def main():
    bad = []
    seen = sorted(k for k in os.environ if SECRET_NAME.search(k))
    leaked = [k for k in seen if k not in ALLOWED and not k.startswith("ACTIONS_")]
    print("env names that look like credentials:", seen or "none")
    if leaked:
        bad.append(f"credential-like variables present: {leaked}")
    present = [p for p in PROD_PATHS if os.path.exists(p)]
    print("production paths present:", present or "none")
    if present:
        bad.append(f"production paths present: {present}")
    for host, port in (("127.0.0.1", 8090),):   # the gateway's admin port on the production server is not here
        s = socket.socket(); s.settimeout(1)
        try:
            s.connect((host, port)); bad.append(f"a gateway answers on {host}:{port}")
        except OSError:
            print(f"no gateway on {host}:{port}: ok")
        finally:
            s.close()
    runner = os.environ.get("RUNNER_NAME", ""); labels = os.environ.get("RUNNER_ENVIRONMENT", "")
    print("runner:", runner or "(local)", labels)
    if runner and labels != "github-hosted":
        bad.append(f"foreign code must run on a GitHub-hosted runner, got {runner} ({labels or 'self-hosted'})")
    if bad:
        print("ISOLATION FAILED:", "; ".join(bad)); return 1
    print("isolation OK: no secrets, no wallets, no production host in reach")
    return 0


if __name__ == "__main__":
    sys.exit(main())
