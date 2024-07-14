import os
import pytest
import shutil
import stat
import subprocess
import time

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.abspath(os.path.join(THIS_DIR, "..", "src"))
TOP_DIR = os.path.abspath(os.path.join(THIS_DIR, ".."))

BINDIR=os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "build"))
FAT_FUSE=os.path.join(BINDIR, "vfat-fuse")

MNT_DIR=os.path.join(os.getcwd(), "pytest-mnt")

# 4 MB should test FAT12
# 12, 32MB should test FAT16, using bootsector.total_sectors16 or bootsector.total_sectors32 respectively
# 1024 MB should be FAT32
# not testing FAT32 until setting free clusters in fsinfo is fixed
pytestmark = pytest.mark.parametrize("size_mb", ["4", "32"], scope='module')


def start_fusefat(size_mb):
    pwd = os.getcwd()
    image_file = os.path.join(pwd, f"pytest-vfat-{size_mb}.img")
    subprocess.run([FAT_FUSE, "-s", image_file, MNT_DIR], check=True)


def stop_fusefat(size_mb):
    subprocess.run(["fusermount", "-u", MNT_DIR], check=True)
    time.sleep(0.1)


def check_image(size_mb):
    pwd = os.getcwd()
    image_file = os.path.join(pwd, f"pytest-vfat-{size_mb}.img")
    subprocess.run(["fsck.vfat", "-n", image_file], check=True)


@pytest.fixture(scope='module', autouse=True)
def setup_test(size_mb):
    pwd = os.getcwd()
    image_file = os.path.join(pwd, f"pytest-vfat-{size_mb}.img")

    subprocess.run(["dd", "if=/dev/zero", f"of={image_file}", "bs=1048576", f"count={size_mb}", "conv=sparse"], check=True)
    subprocess.run(["mkfs.vfat", image_file], check=True)

    os.makedirs(MNT_DIR, exist_ok=True)

    yield

    try:
        stop_fusefat(size_mb)
    except subprocess.CalledProcessError:
        pass

    shutil.rmtree(MNT_DIR)


def test_make(size_mb):
    src_dir = os.path.join(MNT_DIR, "src")

    start_fusefat(size_mb)
    shutil.copytree(SRC_DIR, src_dir)

    subprocess.run(["make", "clean"], cwd=src_dir)
    subprocess.run(["make"], cwd=src_dir)

    stop_fusefat(size_mb)

    check_image(size_mb)


def test_tar(size_mb):
    start_fusefat(size_mb)

    subprocess.run(["tar", "zcf", os.path.join(MNT_DIR, "src.tgz"), "src"], cwd=TOP_DIR)
    subprocess.run(["tar", "xf", os.path.join(MNT_DIR, "src.tgz")], cwd=MNT_DIR)

    stop_fusefat(size_mb)

    check_image(size_mb)


def test_dd_sha512sum(size_mb):
    dirpath = os.path.join(MNT_DIR, "dd-sha512sum")

    start_fusefat(size_mb)
    os.makedirs(dirpath, exist_ok=True)
    image_file = "random.bin"
    subprocess.run(["dd", "if=/dev/random", f"of={image_file}", "bs=1024", "count=1024"], check=True)
    subprocess.run(["sha512sum", image_file], check=True)

    stop_fusefat(size_mb)

    check_image(size_mb)


# FAT does not understand sparse, but this tests seeking beyond end of file
def test_dd_sparse(size_mb):
    dirpath = os.path.join(MNT_DIR, "dd-sparse")

    start_fusefat(size_mb)
    os.makedirs(dirpath, exist_ok=True)
    image_file = "random.bin"
    subprocess.run(["dd", "if=/dev/zero", f"of={image_file}", "bs=1024", "count=1024", "conv=sparse"], check=True)
    subprocess.run(["sha512sum", image_file], check=True)

    stop_fusefat(size_mb)

    check_image(size_mb)
