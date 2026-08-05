import errno
import os
import subprocess
import time

import pytest


BINDIR = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "build"))
FAT_FUSE = os.path.join(BINDIR, "vfat-fuse")

MNT_DIR = os.path.join(os.getcwd(), "pytest-mnt")


@pytest.fixture(scope="module", autouse=True)
def setup_test():
    pwd = os.getcwd()
    size_mb = 32
    image_file = os.path.join(pwd, f"pytest-vfat-{size_mb}.img")

    subprocess.run(["dd", "if=/dev/zero", f"of={image_file}", "bs=1048576", f"count={size_mb}", "conv=sparse"], check=True)
    subprocess.run(["mkfs.vfat", image_file], check=True)

    os.makedirs(MNT_DIR, exist_ok=True)

    subprocess.run([FAT_FUSE, "-s", image_file, MNT_DIR], check=True)

    yield

    subprocess.run(["fusermount", "-u", MNT_DIR], check=True)
    time.sleep(0.1)

    os.rmdir(MNT_DIR)


def write_file(filename, text):
    with open(filename, "wt") as f:
        f.write(text)


def test_rename_overwrites_existing_file():
    """plain rename(2) (flags == 0) must replace an existing destination,
    matching POSIX - this is what every `mv src dst` where dst exists
    relies on."""
    src = os.path.join(MNT_DIR, "overwrite-src.txt")
    dst = os.path.join(MNT_DIR, "overwrite-dst.txt")

    write_file(src, "from src")
    write_file(dst, "from dst (should be replaced)")

    os.rename(src, dst)

    assert not os.path.exists(src)
    assert os.path.exists(dst)
    with open(dst, "rt") as f:
        assert f.read() == "from src"


def test_rename_file_onto_empty_directory_fails():
    src = os.path.join(MNT_DIR, "file-onto-dir-src.txt")
    dst = os.path.join(MNT_DIR, "file-onto-dir-dst")

    write_file(src, "a file")
    os.makedirs(dst, exist_ok=True)

    with pytest.raises(IsADirectoryError):
        os.rename(src, dst)

    assert os.path.exists(src)
    assert os.path.isdir(dst)


def test_rename_directory_onto_file_fails():
    src = os.path.join(MNT_DIR, "dir-onto-file-src")
    dst = os.path.join(MNT_DIR, "dir-onto-file-dst.txt")

    os.makedirs(src, exist_ok=True)
    write_file(dst, "a file")

    with pytest.raises(NotADirectoryError):
        os.rename(src, dst)

    assert os.path.isdir(src)
    assert os.path.exists(dst)


def test_rename_directory_onto_nonempty_directory_fails():
    src = os.path.join(MNT_DIR, "dir-onto-nonempty-src")
    dst = os.path.join(MNT_DIR, "dir-onto-nonempty-dst")

    os.makedirs(src, exist_ok=True)
    os.makedirs(dst, exist_ok=True)
    write_file(os.path.join(dst, "inhabitant.txt"), "still here")

    with pytest.raises(OSError) as exc_info:
        os.rename(src, dst)
    assert exc_info.value.errno == errno.ENOTEMPTY

    assert os.path.isdir(src)
    assert os.path.exists(os.path.join(dst, "inhabitant.txt"))


def test_rename_directory_onto_empty_directory_succeeds():
    src = os.path.join(MNT_DIR, "dir-onto-empty-src")
    dst = os.path.join(MNT_DIR, "dir-onto-empty-dst")

    os.makedirs(src, exist_ok=True)
    write_file(os.path.join(src, "keep.txt"), "keep me")
    os.makedirs(dst, exist_ok=True)

    os.rename(src, dst)

    assert not os.path.exists(src)
    assert os.path.isdir(dst)
    assert os.path.exists(os.path.join(dst, "keep.txt"))
