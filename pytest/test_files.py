import os
import pytest
import stat
import subprocess
import time


BINDIR=os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "build"))
FAT_FUSE=os.path.join(BINDIR, "vfat-fuse")

MNT_DIR=os.path.join(os.getcwd(), "pytest-mnt")

# 4 MB should test FAT12
# 12, 32MB should test FAT16, using bootsector.total_sectors16 or bootsector.total_sectors32 respectively
# 1024 MB should be FAT32
pytestmark = pytest.mark.parametrize("size_mb", ["4", "16", "32", "1024"], scope='module')


@pytest.fixture(scope='module', autouse=True)
def setup_test(size_mb):
    pwd = os.getcwd()
    image_file = os.path.join(pwd, f"pytest-vfat-{size_mb}.img")

    subprocess.run(["dd", "if=/dev/zero", f"of={image_file}", "bs=1048576", f"count={size_mb}", "conv=sparse"], check=True)
    subprocess.run(["mkfs.vfat", image_file], check=True)

    os.makedirs(MNT_DIR, exist_ok=True)

    subprocess.run([FAT_FUSE, "-s", image_file, MNT_DIR], check=True)
#    process = subprocess.Popen([FAT_FUSE, "-f", image_file, MNT_DIR])

    yield

    subprocess.run(["fusermount", "-u", MNT_DIR], check=True)
    time.sleep(0.1)

    os.rmdir(MNT_DIR)


def write_file(filename, text):
    with open(filename, "wt") as f:
        f.write(text)


def test_mkdir_rmdir():
    dirpath = os.path.join(MNT_DIR, "newdir")
    os.makedirs(dirpath, exist_ok=True)

    assert os.path.isdir(dirpath)

    os.rmdir(dirpath)
    assert not os.path.exists(dirpath)


def test_mkdir_rmdir_subdirs():
    dirpath_parent = os.path.join(MNT_DIR, "nested")
    dirpath = os.path.join(dirpath_parent, "subdir")
    os.makedirs(dirpath, exist_ok=True)

    assert os.path.isdir(dirpath)

    os.rmdir(dirpath)
    assert not os.path.exists(dirpath)

    os.rmdir(dirpath_parent)
    assert not os.path.exists(dirpath_parent)


def test_write_file():
    basename = "created.txt"
    text = "something\n"

    filename = os.path.join(MNT_DIR, basename)
    with open(filename, "wt") as f:
        f.write(text)

    assert os.path.exists(filename)

    with open(filename, "rt") as f:
        content = f.read()

    assert content == text


def test_write_filesubdir():
    basename = "created.txt"
    dirpath = os.path.join(MNT_DIR, "write-subdir")
    os.makedirs(dirpath, exist_ok=True)
    text = "something\n"

    filename = os.path.join(MNT_DIR, basename)
    with open(filename, "wt") as f:
        f.write(text)

    assert os.path.exists(filename)

    with open(filename, "rt") as f:
        content = f.read()

    assert content == text


# test file with cluster count > 2^16 assuming cluster size is 4096
def test_write_hugefile(size_mb):
    size = 4096 * 2**16 + 333
    if (int(size_mb) * 2**20 < size):
        pytest.skip("skipping because file system too small")

    basename = "hugefile.bin"
    content = os.urandom(size)

    filename = os.path.join(MNT_DIR, basename)

    with open(filename, "wb") as f:
        f.write(content)

    assert os.path.exists(filename)

    with open(filename, "rb") as f:
        content_read = f.read()

    assert content == content_read


def test_write_bigfile():
    basename = "bigfile.bin"
    content = os.urandom(5*4096+333)

    filename = os.path.join(MNT_DIR, basename)

    with open(filename, "wb") as f:
        f.write(content)

    assert os.path.exists(filename)

    with open(filename, "rb") as f:
        content_read = f.read()

    assert content == content_read


# write chunks
def test_pwrite():
    basename = "pwrite.bin"
    content = os.urandom(5*3333)
    count = 5
    size = 3333

    filename = os.path.join(MNT_DIR, basename)
    with open(filename, "wb") as f:
        for p in range(0, count*size, size):
            f.seek(p)
            f.write(content[p:p+size])

    with open(filename, "rb") as f:
        content_read = f.read()

    assert len(content) == len(content_read)
    assert content == content_read


# write chunks backwards, chunks smaller than a cluster
def test_pwrite_backwards():
    basename = "pwrite.bin"
    content = os.urandom(5*3333)
    count = 5
    size = 3333

    filename = os.path.join(MNT_DIR, basename)
    with open(filename, "wb") as f:
        for p in range(count*size, 0, -size):
            f.seek(p-size)
            f.write(content[p-size:p])

    with open(filename, "rb") as f:
        content_read = f.read()

    assert len(content) == len(content_read)
    assert content == content_read


# write chunks backwards, chunks bigger than a cluster
def test_pwrite_backwards_bigchunks():
    basename = "pwrite.bin"
    content = os.urandom(5*3333)
    count = 5
    size = 6666

    filename = os.path.join(MNT_DIR, basename)
    with open(filename, "wb") as f:
        for p in range(count*size, 0, -size):
            f.seek(p-size)
            f.write(content[p-size:p])

    with open(filename, "rb") as f:
        content_read = f.read()

    assert len(content) == len(content_read)
    assert content == content_read


def test_attributes():
    basename = "attr.txt"
    text = "something to test attrs"
    now = time.time()

    filename = os.path.join(MNT_DIR, basename)
    with open(filename, "w") as f:
        f.write(text)

    stat = os.stat(filename)
    assert stat.st_uid == os.getuid()

    difftime = stat.st_mtime - int(now)
    assert difftime >= -1

    difftime = stat.st_ctime - int(now)
    assert difftime >= -1


def test_chmod():
    basename = "chmod.txt"
    text = "something to test chmod"

    filename = os.path.join(MNT_DIR, basename)
    with open(filename, "w") as f:
        f.write(text)

    st = os.stat(filename)
    mode = st.st_mode & ~stat.S_IWUSR
    os.chmod(filename, mode)

    st = os.stat(filename)
    assert not (st.st_mode & stat.S_IWUSR)

    mode = st.st_mode | stat.S_IWUSR
    os.chmod(filename, mode)

    st = os.stat(filename)
    assert st.st_mode & stat.S_IWUSR


def test_unlink():
    basename = "unlink.txt"
    text = "something to delete"

    filename = os.path.join(MNT_DIR, basename)
    with open(filename, "w") as f:
        f.write(text)
    assert os.path.exists(filename)

    os.remove(filename)
    assert not os.path.exists(filename)


def test_rename():
    oldpath = os.path.join(MNT_DIR, "oldname.txt")
    newpath = os.path.join(MNT_DIR, "newname.txt")
    content = "something to rename"

    with open(oldpath, "wt") as f:
        f.write(content)
    assert os.path.exists(oldpath)

    os.rename(oldpath, newpath)
    assert not os.path.exists(oldpath)
    assert os.path.exists(newpath)

    with open(newpath, "rt") as f:
        content_read = f.read()

    assert content == content_read


def test_move():
    olddir = os.path.join(MNT_DIR, "olddir")
    newdir = os.path.join(MNT_DIR, "newdir")
    oldpath = os.path.join(olddir, "oldname.txt")
    newpath = os.path.join(newdir, "newname.txt")

    content = "something to rename"

    os.makedirs(olddir)
    os.makedirs(newdir)

    with open(oldpath, "wt") as f:
        f.write(content)
    assert os.path.exists(oldpath)

    os.rename(oldpath, newpath)
    assert not os.path.exists(oldpath)
    assert os.path.exists(newpath)

    with open(newpath, "rt") as f:
        content_read = f.read()

    assert content == content_read


def test_statfs():
    filename = os.path.join(MNT_DIR, "statvfs.txt")
    write_file(filename, "something from client")
    os.statvfs(filename)


def test_many_files():
    dirpath = os.path.join(MNT_DIR, "many")
    os.makedirs(dirpath, exist_ok=True)
    count = 1000
    text = "foo"

    for i in range(1, count):
        filepath = f"{dirpath}/FILE{i}"
        with open(filepath, "w") as f:
            f.write(text)

    for i in range(1, count):
        filepath = f"{dirpath}/FILE{i}"
        assert os.path.exists(filepath)
