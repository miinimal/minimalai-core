"""In the monorepo: core/ copies must match their sources. In the published repo the sources are absent: skipped."""
import os
import subprocess
import sys

import pytest

CORE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SYNC = os.path.join(CORE, "sync.py")


@pytest.mark.skipif(not os.path.exists(os.path.join(CORE, "..", "gateway", "receipts.py")), reason="published tree")
def test_core_matches_sources():
    assert subprocess.run([sys.executable, SYNC, "--check"]).returncode == 0
