import concurrent.futures
import os
import subprocess
import time

import pytest


BINDIR = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "build"))
FAT_FUSE = os.path.join(BINDIR, "vfat-fuse")

MNT_DIR = os.path.join(os.getcwd(), "pytest-mnt-concurrency")
IMAGE_FILE = os.path.join(os.getcwd(), "pytest-vfat-concurrency.img")


def _find_daemon_pid():
    result = subprocess.run(
        ["pgrep", "-f", f"vfat-fuse.*{os.path.basename(IMAGE_FILE)}"],
        capture_output=True, text=True,
    )
    pids = [int(p) for p in result.stdout.split()]
    assert len(pids) == 1, f"expected exactly one matching daemon, got {pids}"
    return pids[0]


def _thread_count(pid):
    return len(os.listdir(f"/proc/{pid}/task"))


@pytest.fixture
def mounted_without_dash_s():
    subprocess.run(["dd", "if=/dev/zero", f"of={IMAGE_FILE}", "bs=1048576", "count=16", "conv=sparse"], check=True)
    subprocess.run(["mkfs.vfat", IMAGE_FILE], check=True)
    os.makedirs(MNT_DIR, exist_ok=True)

    # deliberately NOT passing -s: this is what a normal user invocation
    # looks like, and is exactly the case REVIEW.md #8 flagged as unsafe
    subprocess.run([FAT_FUSE, IMAGE_FILE, MNT_DIR], check=True)
    time.sleep(0.2)

    yield _find_daemon_pid()

    subprocess.run(["fusermount", "-u", MNT_DIR], check=True)
    time.sleep(0.1)
    os.rmdir(MNT_DIR)


def _client_workload(worker_id):
    for i in range(30):
        path = os.path.join(MNT_DIR, f"worker{worker_id}-{i}.txt")
        with open(path, "w") as f:
            f.write(f"worker {worker_id} iteration {i}\n" * 4)
        with open(path, "r") as f:
            f.read()
        os.remove(path)


def test_daemon_stays_singlethreaded_under_concurrent_load(mounted_without_dash_s):
    """
    fatfuse doesn't have fine-grained locking around its shared directory
    tree, so it must run single-threaded even when the user doesn't pass
    -s explicitly (REVIEW.md #8). Confirm that holds under real concurrent
    client load, not just at idle.
    """
    pid = mounted_without_dash_s
    max_threads = _thread_count(pid)

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(_client_workload, i) for i in range(8)]
        while not all(f.done() for f in futures):
            max_threads = max(max_threads, _thread_count(pid))
            time.sleep(0.01)
        for f in futures:
            f.result()

    max_threads = max(max_threads, _thread_count(pid))
    assert max_threads == 1, (
        f"fatfuse daemon (pid {pid}) used {max_threads} threads under "
        f"concurrent load; expected exactly 1 (single-threaded)"
    )
