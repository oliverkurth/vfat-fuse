import os
import subprocess

import pytest

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.abspath(os.path.join(THIS_DIR, "..", "src"))
BINDIR = os.path.realpath(os.path.join(THIS_DIR, "..", "build"))
TEST_SECURITY_BIN = os.path.join(BINDIR, "test-security")


@pytest.fixture(scope="module")
def build_test_security():
    subprocess.run(["make", "test"], cwd=SRC_DIR, check=True)
    return TEST_SECURITY_BIN


def test_security_regressions(build_test_security):
    """
    Runs src/test_security.c, a small ASan/UBSan-instrumented unit test
    binary that regression-tests the security fixes for the issues listed
    in REVIEW.md (fat.c parses untrusted on-disk FAT structures).
    """
    result = subprocess.run(
        [build_test_security],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, (
        f"test-security failed (rc={result.returncode}):\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
