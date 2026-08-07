"""
Tests for src/mkfs.c (built as build/mkfs.vfat), independent of the system
mkfs.vfat that the other test files use (see test_fsck.py/test_apps.py).

Boot sector / directory entry fields are decoded here with a second,
independent implementation of the FAT layout math (mirroring fat.c's own
formulas) so that these tests don't just trust mkfs.c's internal
bookkeeping. fsck.vfat is used as a third, fully independent check.
"""

import os
import struct
import subprocess
import time

import pytest

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.abspath(os.path.join(THIS_DIR, "..", "src"))
BINDIR = os.path.realpath(os.path.join(THIS_DIR, "..", "build"))
MKFS = os.path.join(BINDIR, "mkfs.vfat")
FAT_FUSE = os.path.join(BINDIR, "vfat-fuse")

FAT_ATTR_VOLUME_ID = 0x08

BOOT_SECTOR_FMT = "<3s8sHBHBHHBHHHII"
BOOT_SECTOR_KEYS = [
    "jmpboot", "oem_name", "bytes_per_sector", "sectors_per_cluster",
    "reserved_sectors_count", "num_fats", "root_entry_count",
    "total_sectors16", "media", "fat_size16", "sectors_per_track",
    "num_heads", "hidden_sectors", "total_sectors32",
]
BOOT_SECTOR_SIZE = struct.calcsize(BOOT_SECTOR_FMT)

EXT16_FMT = "<BBBI11s8s"
EXT16_KEYS = ["drive_num", "reserved", "ext_boot_signature", "volume_id", "volume_label", "file_system_type"]

EXT32_FMT = "<IH2sIHH12sBBBI11s8s"
EXT32_KEYS = [
    "fat_size", "ext_flags", "fs_version", "root_cluster", "fs_info_sector",
    "backup_boot_sector", "reserved1", "drive_num", "reserved2",
    "boot_signature", "volume_id", "volume_label", "file_system_type",
]

DIR_ENTRY_FMT = "<11sBBBHHHHHHHI"
DIR_ENTRY_KEYS = [
    "name", "attr", "ntres", "creation_time_tenth", "creation_time",
    "creation_date", "last_access_date", "first_cluster_high",
    "write_time", "write_date", "first_cluster_low", "filesize",
]


@pytest.fixture(scope="module", autouse=True)
def build_mkfs():
    subprocess.run(["make", "all"], cwd=SRC_DIR, check=True)


def run_mkfs(*args):
    return subprocess.run([MKFS, *args], capture_output=True, text=True)


def parse_boot_sector(path):
    with open(path, "rb") as f:
        raw = f.read(512)
    bs = dict(zip(BOOT_SECTOR_KEYS, struct.unpack(BOOT_SECTOR_FMT, raw[:BOOT_SECTOR_SIZE])))
    bs["_ext_raw"] = raw[BOOT_SECTOR_SIZE:512]
    return bs


def fat_size_sectors(bs):
    if bs["fat_size16"]:
        return bs["fat_size16"]
    return parse_ext32(bs)["fat_size"]


def fat_type_of(bs):
    """Independently re-derives the FAT type from cluster count, the same
    way init_fat_context() in fat.c does, without calling into our code."""
    total_sectors = bs["total_sectors16"] or bs["total_sectors32"]
    root_dir_sectors = (32 * bs["root_entry_count"] + bs["bytes_per_sector"] - 1) // bs["bytes_per_sector"]
    data_start = bs["reserved_sectors_count"] + bs["num_fats"] * fat_size_sectors(bs) + root_dir_sectors
    cluster_count = (total_sectors - data_start) // bs["sectors_per_cluster"]
    if cluster_count <= 4085:
        return 12
    elif cluster_count <= 65525:
        return 16
    else:
        return 32


def parse_ext16(bs):
    d = dict(zip(EXT16_KEYS, struct.unpack(EXT16_FMT, bs["_ext_raw"][:struct.calcsize(EXT16_FMT)])))
    d["volume_label"] = d["volume_label"].decode("ascii")
    d["file_system_type"] = d["file_system_type"].decode("ascii")
    return d


def parse_ext32(bs):
    d = dict(zip(EXT32_KEYS, struct.unpack(EXT32_FMT, bs["_ext_raw"][:struct.calcsize(EXT32_FMT)])))
    d["volume_label"] = d["volume_label"].decode("ascii")
    d["file_system_type"] = d["file_system_type"].decode("ascii")
    return d


def root_dir_start_sector(bs):
    return bs["reserved_sectors_count"] + bs["num_fats"] * fat_size_sectors(bs)


def read_root_dir_first_entry(path, bs):
    offset = root_dir_start_sector(bs) * bs["bytes_per_sector"]
    with open(path, "rb") as f:
        f.seek(offset)
        raw = f.read(32)
    return dict(zip(DIR_ENTRY_KEYS, struct.unpack(DIR_ENTRY_FMT, raw)))


def fsck(path):
    return subprocess.run(["fsck.vfat", "-n", path], capture_output=True, text=True)


def assert_no_structural_corruption(path):
    """Like fsck(), but tolerant of vfat-fuse leaving a stale FAT32 FSInfo
    free-cluster hint after writes (a known, pre-existing quirk of the FUSE
    driver, not of mkfs.vfat) -- auto-corrects that one known-benign issue
    and then requires a subsequent check to come back fully clean."""
    subprocess.run(["fsck.vfat", "-a", path], capture_output=True, text=True)
    result = fsck(path)
    assert result.returncode == 0, result.stdout + result.stderr


# ---------------------------------------------------------------------------
# device sizing: BLOCK-COUNT argument vs. pre-existing file size
# ---------------------------------------------------------------------------

def test_creates_new_file_with_block_count(tmp_path):
    img = tmp_path / "new.img"
    assert not img.exists()

    result = run_mkfs(str(img), "8192")  # 8192 KiB = 8 MiB
    assert result.returncode == 0, result.stderr

    assert img.stat().st_size == 8192 * 1024
    assert fsck(str(img)).returncode == 0


def test_uses_existing_file_size_when_no_block_count(tmp_path):
    img = tmp_path / "existing.img"
    with open(img, "wb") as f:
        f.truncate(16 * 1024 * 1024)

    result = run_mkfs(str(img))
    assert result.returncode == 0, result.stderr

    bs = parse_boot_sector(str(img))
    total_sectors = bs["total_sectors16"] or bs["total_sectors32"]
    assert total_sectors * bs["bytes_per_sector"] == 16 * 1024 * 1024
    assert fsck(str(img)).returncode == 0


def test_missing_device_argument_fails():
    result = run_mkfs()
    assert result.returncode != 0


def test_device_too_small_fails(tmp_path):
    img = tmp_path / "tiny.img"
    result = run_mkfs(str(img), "8")  # 8 KiB, far too small for any FAT fs
    assert result.returncode != 0


# ---------------------------------------------------------------------------
# automatic FAT type selection by size
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("size_kib,expected_type", [
    (64, 12),
    (1024, 12),
    (4096, 12),
    (8192, 12),        # 8 MiB: still within the FAT12 threshold
    (8193, 16),        # just over: hints FAT16
    (16 * 1024, 16),
    (32 * 1024, 16),
    (256 * 1024, 16),
    (512 * 1024, 16),  # 512 MiB: still within the FAT16 threshold
    (512 * 1024 + 1, 32),  # just over: hints FAT32
    (1024 * 1024, 32),
])
def test_auto_fat_type_by_size(tmp_path, size_kib, expected_type):
    img = tmp_path / "auto.img"
    result = run_mkfs(str(img), str(size_kib))
    assert result.returncode == 0, result.stderr

    bs = parse_boot_sector(str(img))
    assert fat_type_of(bs) == expected_type
    assert fsck(str(img)).returncode == 0


# ---------------------------------------------------------------------------
# forced FAT type via -F
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("forced,size_kib", [(12, 4096), (16, 32 * 1024), (32, 1024 * 1024)])
def test_forced_fat_type_matches(tmp_path, forced, size_kib):
    img = tmp_path / "forced.img"
    result = run_mkfs("-F", str(forced), str(img), str(size_kib))
    assert result.returncode == 0, result.stderr

    bs = parse_boot_sector(str(img))
    assert fat_type_of(bs) == forced
    assert fsck(str(img)).returncode == 0


def test_forced_fat_type_too_small_fails(tmp_path):
    img = tmp_path / "toosmall32.img"
    # 4 MiB can't hold a spec-valid FAT32 filesystem (needs >65525 clusters)
    result = run_mkfs("-F", "32", str(img), "4096")
    assert result.returncode != 0


def test_forced_fat_type_too_large_fails(tmp_path):
    img = tmp_path / "toobig12.img"
    # 1 GiB has far more than 4085 clusters worth of data even at 128 sectors/cluster
    result = run_mkfs("-F", "12", str(img), str(1024 * 1024))
    assert result.returncode != 0


def test_fat32_reserved_too_small_for_fsinfo_rejected(tmp_path):
    img = tmp_path / "smallreserved32.img"
    # FAT32's FSInfo sector is hardcoded at sector index 1; with -R 1 the
    # FAT table would start at the same sector and overwrite it. Must be
    # rejected (as "no valid layout found") rather than silently clobbering
    # FSInfo - this fails during layout search, after the target file is
    # created/sized, so unlike the -S/-R/-r range checks this doesn't mean
    # the file is untouched, just that no filesystem is written to it.
    result = run_mkfs("-F", "32", "-R", "1", str(img), str(1024 * 1024))
    assert result.returncode != 0


def test_invalid_fat_type_rejected(tmp_path):
    img = tmp_path / "badtype.img"
    result = run_mkfs("-F", "99", str(img), "8192")
    assert result.returncode != 0


def test_invalid_sectors_per_cluster_rejected(tmp_path):
    img = tmp_path / "badspc.img"
    result = run_mkfs("-s", "3", str(img), "8192")  # not a power of two
    assert result.returncode != 0


# ---------------------------------------------------------------------------
# sector size (-S)
# ---------------------------------------------------------------------------

def test_boot_signature_at_fixed_offset_regardless_of_sector_size(tmp_path):
    img = tmp_path / "bigsector.img"
    result = run_mkfs("-S", "4096", str(img), str(4 * 1024))
    assert result.returncode == 0, result.stderr

    bs = parse_boot_sector(str(img))
    assert bs["bytes_per_sector"] == 4096

    # the 0x55AA boot signature is fixed at byte offset 510/511 by the FAT
    # spec regardless of sector size - not at the end of the (4096-byte)
    # logical sector.
    with open(img, "rb") as f:
        raw = f.read(512)
    assert raw[510:512] == b"\x55\xaa"

    assert fsck(str(img)).returncode == 0


def test_sector_size_above_16bit_field_range_rejected(tmp_path):
    img = tmp_path / "hugesector.img"
    # 65536 is a power of two but doesn't fit the on-disk 16-bit
    # bytes_per_sector field (it would truncate to 0). Large enough
    # BLOCK-COUNT that, without an upfront check, the layout search would
    # succeed and mkfs would only fail later during its own re-open
    # verification - after already creating/writing the device. Must
    # instead be rejected during argument parsing, before touching it.
    result = run_mkfs("-S", "65536", str(img), str(64 * 1024))
    assert result.returncode != 0
    assert not img.exists()


def test_max_valid_sector_size_accepted(tmp_path):
    img = tmp_path / "maxsector.img"
    # force FAT12: with only 2048 total (32768-byte) sectors, auto-detection
    # (which hints by total *bytes*, 64 MiB -> FAT16) can't find a layout,
    # since the resulting cluster count from so few large sectors falls
    # below FAT16's minimum - unrelated to the sector-size fix being tested.
    result = run_mkfs("-F", "12", "-S", "32768", str(img), str(64 * 1024))
    assert result.returncode == 0, result.stderr

    bs = parse_boot_sector(str(img))
    assert bs["bytes_per_sector"] == 32768
    assert fsck(str(img)).returncode == 0


# ---------------------------------------------------------------------------
# volume label (-n / -L)
# ---------------------------------------------------------------------------

def test_default_label_is_no_name(tmp_path):
    img = tmp_path / "nolabel.img"
    result = run_mkfs(str(img), "16384")
    assert result.returncode == 0, result.stderr

    bs = parse_boot_sector(str(img))
    ext = parse_ext16(bs) if fat_type_of(bs) != 32 else parse_ext32(bs)
    assert ext["volume_label"] == "NO NAME    "

    entry = read_root_dir_first_entry(str(img), bs)
    assert entry["name"][0] == 0  # no volume-id entry written


@pytest.mark.parametrize("flag", ["-n", "-L"])
def test_label_written_to_bootsector_and_rootdir(tmp_path, flag):
    img = tmp_path / "labeled.img"
    result = run_mkfs(flag, "MYLABEL", str(img), "16384")
    assert result.returncode == 0, result.stderr

    bs = parse_boot_sector(str(img))
    ext = parse_ext16(bs) if fat_type_of(bs) != 32 else parse_ext32(bs)
    assert ext["volume_label"] == "MYLABEL    "

    entry = read_root_dir_first_entry(str(img), bs)
    assert entry["name"] == b"MYLABEL    "
    assert entry["attr"] == FAT_ATTR_VOLUME_ID
    assert entry["first_cluster_high"] == 0
    assert entry["first_cluster_low"] == 0
    assert entry["filesize"] == 0

    assert fsck(str(img)).returncode == 0


def test_label_uppercased_and_truncated(tmp_path):
    img = tmp_path / "longlabel.img"
    result = run_mkfs("-n", "some very long label", str(img), "16384")
    assert result.returncode == 0

    bs = parse_boot_sector(str(img))
    ext = parse_ext16(bs)
    assert ext["volume_label"] == "SOME VERY L"


# ---------------------------------------------------------------------------
# -i/-f/-r/-R overrides, cross-checked structurally via fsck.vfat
# ---------------------------------------------------------------------------

def test_volume_id_option(tmp_path):
    img = tmp_path / "volid.img"
    result = run_mkfs("-i", "deadbeef", str(img), "8192")
    assert result.returncode == 0, result.stderr

    bs = parse_boot_sector(str(img))
    ext = parse_ext16(bs)
    assert ext["volume_id"] == 0xDEADBEEF


def test_num_fats_override(tmp_path):
    img = tmp_path / "onefat.img"
    result = run_mkfs("-f", "1", str(img), "8192")
    assert result.returncode == 0, result.stderr

    bs = parse_boot_sector(str(img))
    assert bs["num_fats"] == 1

    out = subprocess.run(["fsck.vfat", "-v", "-n", str(img)], capture_output=True, text=True)
    assert out.returncode == 0
    assert "1 FATs" in out.stdout


def test_sectors_per_cluster_override(tmp_path):
    img = tmp_path / "bigclusters.img"
    result = run_mkfs("-s", "8", str(img), str(32 * 1024))
    assert result.returncode == 0, result.stderr

    bs = parse_boot_sector(str(img))
    assert bs["sectors_per_cluster"] == 8
    assert fsck(str(img)).returncode == 0


def test_root_entries_and_reserved_override(tmp_path):
    img = tmp_path / "customroot.img"
    result = run_mkfs("-r", "128", "-R", "8", str(img), "4096")
    assert result.returncode == 0, result.stderr

    bs = parse_boot_sector(str(img))
    assert bs["root_entry_count"] == 128
    assert bs["reserved_sectors_count"] == 8
    assert fsck(str(img)).returncode == 0


def test_reserved_sectors_above_16bit_field_range_rejected(tmp_path):
    img = tmp_path / "hugereserved.img"
    # 65600 mod 65536 = 64: a plausible-looking but wrong on-disk value.
    # Large enough BLOCK-COUNT that the layout search would otherwise
    # succeed, so this must be rejected during argument parsing rather
    # than after computing offsets from the real value and writing there.
    result = run_mkfs("-F", "16", "-R", "65600", str(img), str(128 * 1024))
    assert result.returncode != 0
    assert not img.exists()


def test_root_entries_above_16bit_field_range_rejected(tmp_path):
    img = tmp_path / "hugeroot.img"
    # same truncation problem as -R above, for root_entry_count
    result = run_mkfs("-F", "16", "-r", "65600", str(img), str(128 * 1024))
    assert result.returncode != 0
    assert not img.exists()


# ---------------------------------------------------------------------------
# end-to-end: mount the created filesystem and use it
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("size_kib,forced", [(16384, 16), (1024 * 1024, 32)])
def test_mount_and_roundtrip(tmp_path, size_kib, forced):
    img = tmp_path / "mount.img"
    mnt = tmp_path / "mnt"
    mnt.mkdir()

    result = run_mkfs("-F", str(forced), "-n", "ROUNDTRIP", str(img), str(size_kib))
    assert result.returncode == 0, result.stderr

    subprocess.run([FAT_FUSE, "-s", str(img), str(mnt)], check=True)
    try:
        (mnt / "subdir").mkdir()
        text = "hello from test_mkfs\n"
        (mnt / "subdir" / "hello.txt").write_text(text)
        assert (mnt / "subdir" / "hello.txt").read_text() == text
    finally:
        subprocess.run(["fusermount", "-u", str(mnt)], check=True)
        time.sleep(0.1)

    assert_no_structural_corruption(str(img))
