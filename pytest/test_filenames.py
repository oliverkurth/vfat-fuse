import os
import pytest
import stat
import subprocess
import time


BINDIR=os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "build"))
FAT_FUSE=os.path.join(BINDIR, "vfat-fuse")

MNT_DIR=os.path.join(os.getcwd(), "pytest-mnt")


@pytest.fixture(scope='module', autouse=True)
def setup_test():
    pwd = os.getcwd()
    size_mb = 32
    image_file = os.path.join(pwd, f"pytest-vfat-{size_mb}.img")

    subprocess.run(["dd", "if=/dev/zero", f"of={image_file}", "bs=1048576", f"count={size_mb}", "conv=sparse"], check=True)
    subprocess.run(["mkfs.vfat", image_file], check=True)

    os.makedirs(MNT_DIR, exist_ok=True)

    subprocess.run([FAT_FUSE, "-s", image_file, MNT_DIR], check=True)
#    process = subprocess.Popen([FAT_FUSE, "-f", image_file, MNT_DIR])

    yield

    subprocess.run(["fusermount", "-u", MNT_DIR], check=True)
    time.sleep(0.1)

    subprocess.run(["fsck.vfat", "-n", image_file], check=True)

    os.rmdir(MNT_DIR)


def write_file(filename, text):
    with open(filename, "wt") as f:
        f.write(text)


@pytest.mark.parametrize("basename", ["alongname", "alongname.ext", "short", "short.ext"])
def test_names(basename):
    basename = "alongname.ext"

    for i in range(1,10):
        filepath = os.path.join(MNT_DIR, f"{basename}{i}")
        write_file(filepath, f"{filepath}\n")

    for i in range(1,10):
        filepath = os.path.join(MNT_DIR, f"{basename}{i}")
        assert os.path.exists(filepath)
