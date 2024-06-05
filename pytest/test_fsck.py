import os
import pytest
import shutil
import stat
import subprocess
import time


BINDIR=os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "build"))
FAT_FUSE=os.path.join(BINDIR, "fat-fuse")

MNT_DIR=os.path.join(os.getcwd(), "pytest-mnt")

# 4 MB should test FAT12
# 12, 32MB should test FAT16, using bootsector.total_sectors16 or bootsector.total_sectors32 respectively
# 1024 MB should be FAT32
# not testing FAT32 until setting free clusters in fsinfo is fixed
pytestmark = pytest.mark.parametrize("size_mb", ["4", "16", "32"], scope='module')


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


def test_mkdir_rmdir(size_mb):
    dirpath = os.path.join(MNT_DIR, "newdir")

    start_fusefat(size_mb)
    os.makedirs(dirpath, exist_ok=True)
    assert os.path.isdir(dirpath)

    os.rmdir(dirpath)
    assert not os.path.exists(dirpath)
    stop_fusefat(size_mb)
    check_image(size_mb)


def test_mkdir_rmdir_subdirs(size_mb):
    dirpath_parent = os.path.join(MNT_DIR, "nested")
    dirpath = os.path.join(dirpath_parent, "subdir")

    start_fusefat(size_mb)
    os.makedirs(dirpath, exist_ok=True)
    assert os.path.isdir(dirpath)
    os.rmdir(dirpath)
    os.rmdir(dirpath_parent)
    assert not os.path.exists(dirpath_parent)
    stop_fusefat(size_mb)
    check_image(size_mb)


def test_write_file(size_mb):
    basename = "created.txt"
    text = "something\n"

    start_fusefat(size_mb)
    filename = os.path.join(MNT_DIR, basename)
    with open(filename, "wt") as f:
        f.write(text)
    assert os.path.exists(filename)

    with open(filename, "rt") as f:
        content = f.read()

    assert content == text
    stop_fusefat(size_mb)
    check_image(size_mb)


def test_write_file_subdir(size_mb):
    dirpath = os.path.join(MNT_DIR, "write-subdir")
    basename = "created.txt"
    text = "something\n"

    start_fusefat(size_mb)
    os.makedirs(dirpath, exist_ok=True)
    filename = os.path.join(dirpath, basename)
    with open(filename, "wt") as f:
        f.write(text)
    assert os.path.exists(filename)

    with open(filename, "rt") as f:
        content = f.read()

    assert content == text
    stop_fusefat(size_mb)
    check_image(size_mb)


def test_chmod(size_mb):
    basename = "chmod.txt"
    text = "something to test chmod"

    start_fusefat(size_mb)
    filename = os.path.join(MNT_DIR, basename)
    with open(filename, "w") as f:
        f.write(text)

    st = os.stat(filename)
    mode = st.st_mode & ~stat.S_IWUSR
    os.chmod(filename, mode)
    st = os.stat(filename)
    assert not (st.st_mode & stat.S_IWUSR)
    stop_fusefat(size_mb)
    check_image(size_mb)


def test_unlink(size_mb):
    basename = "unlink.txt"
    text = "something to delete"

    start_fusefat(size_mb)
    filename = os.path.join(MNT_DIR, basename)
    with open(filename, "w") as f:
        f.write(text)
    assert os.path.exists(filename)
    os.remove(filename)
    assert not os.path.exists(filename)
    stop_fusefat(size_mb)
    check_image(size_mb)


def test_rename(size_mb):
    oldpath = os.path.join(MNT_DIR, "oldname.txt")
    newpath = os.path.join(MNT_DIR, "newname.txt")
    content = "something to rename"

    start_fusefat(size_mb)
    with open(oldpath, "wt") as f:
        f.write(content)
    assert os.path.exists(oldpath)

    os.rename(oldpath, newpath)
    assert not os.path.exists(oldpath)
    assert os.path.exists(newpath)
    with open(newpath, "rt") as f:
        content_read = f.read()

    assert content == content_read
    stop_fusefat(size_mb)
    check_image(size_mb)


def test_many_files(size_mb):
    dirpath = os.path.join(MNT_DIR, "many")
    count = 10
    text = "foo"

    start_fusefat(size_mb)
    os.makedirs(dirpath, exist_ok=True)
    for i in range(1, count):
        filepath = f"{dirpath}/file{i}"
        with open(filepath, "w") as f:
            f.write(text)
        assert os.path.exists(filepath)

    stop_fusefat(size_mb)
    check_image(size_mb)
