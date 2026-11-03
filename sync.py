"""Sync the open core tree (core/) from its sources in the private monorepo.

core/ is published as-is (git subtree) to the public repo miinimal/minimalai-core. Files listed in MANIFEST are
copies of their sources here; everything else in core/ (README, LICENSE, tests, tools, CI) is authored in core/.

    python core/sync.py          # copy sources into core/
    python core/sync.py --check  # exit 1 if any copy drifted from its source (used by tests)
"""
import filecmp
import os
import shutil
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORE = os.path.join(ROOT, "core")

# (source path in monorepo, destination path in core/). Only code with no secrets, keys or money parameters.
MANIFEST = [
    ("docs/protocol/GRAM-402.md", "spec/GRAM-402.md"),
    ("docs/protocol/RECEIPTS-v1.md", "spec/RECEIPTS-v1.md"),
    ("docs/protocol/WORK-ORDERS-v1.md", "spec/WORK-ORDERS-v1.md"),
    ("docs/protocol/CUSTODY.md", "spec/CUSTODY.md"),
    ("docs/protocol/ERC-8004.md", "spec/ERC-8004.md"),
    ("gateway/erc8004.py", "passport/erc8004.py"),
    ("gateway/receipts.py", "receipts/issuer.py"),
    ("sdk/python/minimalai_receipt.py", "receipts/verify.py"),
    ("sdk/python/gram402.py", "sdk/python/gram402.py"),
    ("sdk/python/gram402_merchant.py", "sdk/python/gram402_merchant.py"),
    ("sdk/python/minimalai_registry.py", "sdk/python/minimalai_registry.py"),
    ("sdk/python/minimalai_world.py", "sdk/python/minimalai_world.py"),
    ("sdk/python/minimalai_agent.py", "sdk/python/minimalai_agent.py"),
    ("sdk/typescript/minimalai_world.ts", "sdk/typescript/minimalai_world.ts"),
    ("sdk/typescript/circle.test.ts", "sdk/typescript/circle.test.ts"),
    ("sdk/typescript/gram402.ts", "sdk/typescript/gram402.ts"),
    ("sdk/typescript/gram402_merchant.ts", "sdk/typescript/gram402_merchant.ts"),
    ("sdk/typescript/minimalai_registry.ts", "sdk/typescript/minimalai_registry.ts"),
    ("oracle-contract/contracts/escrow.fc", "contracts/contracts/escrow.fc"),
    ("oracle-contract/contracts/stdlib.fc", "contracts/contracts/stdlib.fc"),
    ("oracle-contract/escrow.test.js", "contracts/escrow.test.js"),
    ("oracle-contract/contracts/mayor.fc", "contracts/contracts/mayor.fc"),
    ("oracle-contract/mayor.test.js", "contracts/mayor.test.js"),
    ("oracle-contract/contracts/number_collection.fc", "contracts/contracts/number_collection.fc"),
    ("oracle-contract/contracts/number_item.fc", "contracts/contracts/number_item.fc"),
    ("oracle-contract/numbers.test.js", "contracts/numbers.test.js"),
    ("oracle-contract/contracts/stake.fc", "contracts/contracts/stake.fc"),
    ("oracle-contract/stake.test.js", "contracts/stake.test.js"),
    ("gateway/stake.py", "escrow/stake.py"),
    ("gateway/stake_code.b64", "escrow/stake_code.b64"),
    ("gateway/city.py", "city/city.py"),
    ("gateway/mayor_code.b64", "city/mayor_code.b64"),
    ("gateway/number_item_code.b64", "city/number_item_code.b64"),
    ("gateway/number_collection_code.b64", "city/number_collection_code.b64"),
    ("oracle-contract/numbers_fixture.js", "contracts/numbers_fixture.js"),
    ("oracle-contract/agentic.test.js", "contracts/agentic.test.js"),
    ("oracle-contract/agentic/agentic_wallet.code.b64", "contracts/agentic/agentic_wallet.code.b64"),
    ("oracle-contract/agentic/agentic_collection.code.b64", "contracts/agentic/agentic_collection.code.b64"),
    ("gateway/escrow.py", "escrow/offer.py"),
    ("gateway/sanctions.py", "escrow/sanctions.py"),
    ("gateway/escrow_code.b64", "escrow/escrow_code.b64"),
    ("gateway/passport2.py", "passport/passport2.py"),
    ("gateway/square.py", "square/square.py"),
    ("gateway/agentpage.py", "square/agentpage.py"),
    ("gateway/ui.py", "square/ui.py"),
    ("gateway/citynum.py", "city/citynum.py"),
    ("gateway/districts.py", "districts/districts.py"),
    ("gateway/review.py", "review/review.py"),
    ("gateway/grants.py", "grants/grants.py"),
    ("gateway/arbitration.py", "grants/arbitration.py"),
    ("mcp/README.md", "mcp/README.md"),
    ("mcp/pyproject.toml", "mcp/pyproject.toml"),
    ("mcp/server.json", "mcp/server.json"),
    ("mcp/src/minimalai_mcp/__init__.py", "mcp/src/minimalai_mcp/__init__.py"),
    ("mcp/src/minimalai_mcp/server.py", "mcp/src/minimalai_mcp/server.py"),
    ("botkit/README.md", "botkit/README.md"),
    ("botkit/pyproject.toml", "botkit/pyproject.toml"),
    ("botkit/src/minimalai_bot/__init__.py", "botkit/src/minimalai_bot/__init__.py"),
    ("botkit/src/minimalai_bot/core.py", "botkit/src/minimalai_bot/core.py"),
    ("botkit/src/minimalai_bot/aiogram_kit.py", "botkit/src/minimalai_bot/aiogram_kit.py"),
    ("botkit/src/minimalai_bot/ptb_kit.py", "botkit/src/minimalai_bot/ptb_kit.py"),
    ("botkit/tests/test_adapters.py", "botkit/tests/test_adapters.py"),
]


def drift():
    return [d for s, d in MANIFEST
            if not os.path.exists(os.path.join(CORE, d)) or not filecmp.cmp(os.path.join(ROOT, s), os.path.join(CORE, d), shallow=False)]


def main(argv):
    if "--check" in argv:
        bad = drift()
        for d in bad:
            print("drift:", d)
        return 1 if bad else 0
    for s, d in MANIFEST:
        dst = os.path.join(CORE, d)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copyfile(os.path.join(ROOT, s), dst)
    print(f"synced {len(MANIFEST)} files")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
