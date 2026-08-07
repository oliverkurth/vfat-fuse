#define _GNU_SOURCE

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <linux/fs.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "fat.h"

#define DEFAULT_MEDIA 0xf8
#define DEFAULT_DRIVE_NUM 0x80
#define EXT_BOOT_SIGNATURE 0x29
#define FAT32_ROOT_CLUSTER 2
#define FAT32_FSINFO_SECTOR 1
#define FAT32_BACKUP_BOOT_SECTOR 6

static const int spc_candidates[] = {1, 2, 4, 8, 16, 32, 64, 128};
static const int num_spc_candidates = sizeof(spc_candidates) / sizeof(spc_candidates[0]);

struct fat_layout {
    int type;
    int sectors_per_cluster;
    int reserved_sectors;
    int root_entry_count;
    int32_t fat_size_sectors;
    int32_t cluster_count;
};

static void usage(const char *prog)
{
    fprintf(stderr,
        "usage: %s [OPTIONS] DEVICE [BLOCK-COUNT]\n"
        "\n"
        "Create a FAT12/16/32 filesystem on DEVICE (a file or block device).\n"
        "BLOCK-COUNT is the filesystem size in 1024-byte blocks; if omitted,\n"
        "the current size of DEVICE is used.\n"
        "\n"
        "  -F FAT-SIZE       FAT type: 12, 16 or 32 (default: chosen automatically)\n"
        "  -n LABEL          volume label, up to 11 characters\n"
        "  -L LABEL          same as -n\n"
        "  -i VOLUME-ID      32-bit hexadecimal volume id (default: derived from time)\n"
        "  -f NUM-FATS       number of FAT copies (default: 2)\n"
        "  -r ROOT-ENTRIES   root directory entries for FAT12/16 (default: 512)\n"
        "  -R RESERVED       number of reserved sectors (default: 1, or 32 for FAT32)\n"
        "  -s SECTORS        sectors per cluster, a power of two 1..128 (default: automatic)\n"
        "  -S SECTOR-SIZE    bytes per sector, a power of two >= 512 (default: 512)\n"
        "  -v                verbose\n"
        "  -h                this help\n",
        prog);
}

static bool is_pow2(long v)
{
    return v > 0 && (v & (v - 1)) == 0;
}

static uint32_t gen_volume_id(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return ((uint32_t)ts.tv_sec) ^ ((uint32_t)ts.tv_nsec) ^ ((uint32_t)getpid() << 16);
}

/* pad/truncate to 11 chars, upper-cased; NULL/empty means "no label" */
static void format_label(const char *label, char out[11])
{
    int i;

    if (!label || !label[0])
        label = "NO NAME";

    for (i = 0; i < 11 && label[i]; i++)
        out[i] = toupper((unsigned char)label[i]);
    for (; i < 11; i++)
        out[i] = ' ';
}

/*
 * Fixed-point search for the smallest FAT size (in sectors) consistent with
 * the resulting cluster count, mirroring the layout arithmetic in
 * init_fat_context() (fat.c) so that a freshly written image is read back
 * as exactly the FAT type it was written as.
 */
static bool try_layout(int type, int64_t total_sectors, int bytes_per_sector,
                        int num_fats, int spc, int reserved_sectors, int root_entry_count,
                        struct fat_layout *out)
{
    int bits = (type == FAT_TYPE32) ? 32 : (type == FAT_TYPE16) ? 16 : 12;
    int root_dir_sectors = (type == FAT_TYPE32) ? 0 :
        (32 * root_entry_count + bytes_per_sector - 1) / bytes_per_sector;
    int64_t fat_size = 1;
    int32_t cluster_count = 0;
    int iter;

    for (iter = 0; iter < 64; iter++) {
        int64_t avail = total_sectors - reserved_sectors - root_dir_sectors - (int64_t)num_fats * fat_size;
        int64_t bytes_needed, needed_fat_size;

        if (avail <= 0)
            return false;

        cluster_count = avail / spc;
        bytes_needed = ((int64_t)(cluster_count + 2) * bits + 7) / 8;
        needed_fat_size = (bytes_needed + bytes_per_sector - 1) / bytes_per_sector;
        if (needed_fat_size < 1)
            needed_fat_size = 1;

        if (needed_fat_size == fat_size)
            break;
        fat_size = needed_fat_size;
    }
    if (iter == 64)
        return false;

    if (type == FAT_TYPE12) {
        if (cluster_count < 1 || cluster_count > 4085)
            return false;
    } else if (type == FAT_TYPE16) {
        if (cluster_count <= 4085 || cluster_count > 65525)
            return false;
    } else {
        if (cluster_count <= 65525)
            return false;
    }

    out->type = type;
    out->sectors_per_cluster = spc;
    out->reserved_sectors = reserved_sectors;
    out->root_entry_count = root_entry_count;
    out->fat_size_sectors = fat_size;
    out->cluster_count = cluster_count;
    return true;
}

/*
 * Picks sectors-per-cluster (and derived FAT size) for one candidate FAT
 * type. Tries the smallest sectors-per-cluster first so the filesystem
 * wastes as little space as possible, unless the user forced a value.
 */
static bool choose_for_type(int type, int64_t total_sectors, int bytes_per_sector,
                             int num_fats, int user_spc, int user_root_entries,
                             int user_reserved, struct fat_layout *out)
{
    int reserved = (user_reserved > 0) ? user_reserved : (type == FAT_TYPE32 ? 32 : 1);
    int root_entries = (type == FAT_TYPE32) ? 0 : (user_root_entries > 0 ? user_root_entries : 512);
    int i;

    if (user_spc > 0)
        return try_layout(type, total_sectors, bytes_per_sector, num_fats,
                           user_spc, reserved, root_entries, out);

    for (i = 0; i < num_spc_candidates; i++) {
        if (try_layout(type, total_sectors, bytes_per_sector, num_fats,
                        spc_candidates[i], reserved, root_entries, out))
            return true;
    }
    return false;
}

/*
 * Chooses the FAT type automatically from the filesystem size (mirroring
 * common practice: small volumes use FAT12, medium ones FAT16, everything
 * above ~512MiB uses FAT32), then falls back to trying larger types if the
 * hinted one doesn't actually fit the requested geometry.
 */
static bool auto_choose_layout(int64_t total_sectors, int bytes_per_sector,
                                int num_fats, int user_spc, int user_root_entries,
                                int user_reserved, struct fat_layout *out)
{
    int64_t total_bytes = total_sectors * (int64_t)bytes_per_sector;
    int hint;
    int types[3];
    int ntypes = 0;
    int i;

    if (total_bytes <= 8LL * 1024 * 1024)
        hint = FAT_TYPE12;
    else if (total_bytes <= 512LL * 1024 * 1024)
        hint = FAT_TYPE16;
    else
        hint = FAT_TYPE32;

    if (hint == FAT_TYPE12) {
        types[ntypes++] = FAT_TYPE12;
        types[ntypes++] = FAT_TYPE16;
        types[ntypes++] = FAT_TYPE32;
    } else if (hint == FAT_TYPE16) {
        types[ntypes++] = FAT_TYPE16;
        types[ntypes++] = FAT_TYPE32;
    } else {
        types[ntypes++] = FAT_TYPE32;
    }

    for (i = 0; i < ntypes; i++) {
        if (choose_for_type(types[i], total_sectors, bytes_per_sector, num_fats,
                             user_spc, user_root_entries, user_reserved, out))
            return true;
    }
    return false;
}

static int64_t device_size_bytes(int fd, const char *path)
{
    struct stat st;

    if (fstat(fd, &st) != 0) {
        fprintf(stderr, "%s: cannot stat: %s\n", path, strerror(errno));
        return -1;
    }

    if (S_ISBLK(st.st_mode)) {
        uint64_t size;
        if (ioctl(fd, BLKGETSIZE64, &size) != 0) {
            fprintf(stderr, "%s: BLKGETSIZE64 failed: %s\n", path, strerror(errno));
            return -1;
        }
        return (int64_t)size;
    }

    if (S_ISREG(st.st_mode))
        return st.st_size;

    fprintf(stderr, "%s: not a regular file or block device\n", path);
    return -1;
}

/* writes FAT copy 'fatbuf' (fat_size_sectors * bytes_per_sector bytes) num_fats times */
static int write_fat_tables(int fd, const uint8_t *fatbuf, size_t fat_size_bytes,
                             int num_fats, off_t fat_start_byte)
{
    int i;

    for (i = 0; i < num_fats; i++) {
        off_t off = fat_start_byte + (off_t)i * fat_size_bytes;
        ssize_t wr = pwrite(fd, fatbuf, fat_size_bytes, off);
        if (wr != (ssize_t)fat_size_bytes) {
            fprintf(stderr, "writing FAT copy %d failed: %s\n", i, strerror(errno));
            return -1;
        }
    }
    return 0;
}

int main(int argc, char *argv[])
{
    const char *path;
    const char *label = NULL;
    long forced_fat_bits = 0;
    long user_spc = -1;
    long user_reserved = -1;
    long user_root_entries = -1;
    long num_fats = 2;
    long bytes_per_sector = 512;
    long block_count = -1;
    uint32_t volume_id = 0;
    bool have_volume_id = false;
    bool verbose = false;
    int fd = -1;
    int rc = 1;
    int opt;
    int64_t total_bytes;
    int64_t total_sectors;
    struct fat_layout layout;
    bool have_layout = false;

    while ((opt = getopt(argc, argv, "F:n:L:i:f:r:R:s:S:vh")) != -1) {
        switch (opt) {
        case 'F':
            forced_fat_bits = strtol(optarg, NULL, 10);
            if (forced_fat_bits != 12 && forced_fat_bits != 16 && forced_fat_bits != 32) {
                fprintf(stderr, "invalid FAT size '%s' (must be 12, 16 or 32)\n", optarg);
                return 1;
            }
            break;
        case 'n':
        case 'L':
            label = optarg;
            break;
        case 'i':
            volume_id = (uint32_t)strtoul(optarg, NULL, 16);
            have_volume_id = true;
            break;
        case 'f':
            num_fats = strtol(optarg, NULL, 10);
            if (num_fats < 1 || num_fats > 4) {
                fprintf(stderr, "invalid number of FATs '%s'\n", optarg);
                return 1;
            }
            break;
        case 'r':
            user_root_entries = strtol(optarg, NULL, 10);
            if (user_root_entries < 1) {
                fprintf(stderr, "invalid root directory entry count '%s'\n", optarg);
                return 1;
            }
            break;
        case 'R':
            user_reserved = strtol(optarg, NULL, 10);
            if (user_reserved < 1) {
                fprintf(stderr, "invalid reserved sector count '%s'\n", optarg);
                return 1;
            }
            break;
        case 's':
            user_spc = strtol(optarg, NULL, 10);
            if (!is_pow2(user_spc) || user_spc > 128) {
                fprintf(stderr, "invalid sectors-per-cluster '%s' (must be a power of two, 1..128)\n", optarg);
                return 1;
            }
            break;
        case 'S':
            bytes_per_sector = strtol(optarg, NULL, 10);
            if (!is_pow2(bytes_per_sector) || bytes_per_sector < 512) {
                fprintf(stderr, "invalid sector size '%s' (must be a power of two >= 512)\n", optarg);
                return 1;
            }
            break;
        case 'v':
            verbose = true;
            break;
        case 'h':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    if (optind >= argc) {
        usage(argv[0]);
        return 1;
    }
    path = argv[optind++];
    if (optind < argc) {
        block_count = strtol(argv[optind++], NULL, 10);
        if (block_count < 1) {
            fprintf(stderr, "invalid block count '%s'\n", argv[optind - 1]);
            return 1;
        }
    }

    if (label && strlen(label) > 11)
        fprintf(stderr, "warning: label '%s' truncated to 11 characters\n", label);

    fd = open(path, O_RDWR | O_CREAT, 0666);
    if (fd < 0) {
        fprintf(stderr, "%s: cannot open: %s\n", path, strerror(errno));
        return 1;
    }

    if (block_count > 0) {
        total_bytes = (int64_t)block_count * 1024;
        if (ftruncate(fd, total_bytes) != 0) {
            fprintf(stderr, "%s: cannot set size: %s\n", path, strerror(errno));
            goto out;
        }
    } else {
        total_bytes = device_size_bytes(fd, path);
        if (total_bytes <= 0) {
            fprintf(stderr, "%s: cannot determine size (pass BLOCK-COUNT to set one)\n", path);
            goto out;
        }
    }

    total_sectors = total_bytes / bytes_per_sector;
    if (total_sectors < 128) {
        fprintf(stderr, "%s: device too small (%ld bytes)\n", path, (long)total_bytes);
        goto out;
    }

    if (forced_fat_bits) {
        int type = (forced_fat_bits == 12) ? FAT_TYPE12 : (forced_fat_bits == 16) ? FAT_TYPE16 : FAT_TYPE32;
        have_layout = choose_for_type(type, total_sectors, bytes_per_sector, num_fats,
                                       user_spc, user_root_entries, user_reserved, &layout);
    } else {
        have_layout = auto_choose_layout(total_sectors, bytes_per_sector, num_fats,
                                          user_spc, user_root_entries, user_reserved, &layout);
    }

    if (!have_layout) {
        fprintf(stderr, "%s: could not find a valid FAT layout for this size"
                        " (try a different -F/-s/-r/-R)\n", path);
        goto out;
    }

    if (!have_volume_id)
        volume_id = gen_volume_id();

    {
        int type = layout.type;
        int spc = layout.sectors_per_cluster;
        int reserved = layout.reserved_sectors;
        int root_entry_count = layout.root_entry_count;
        int32_t fat_size_sectors = layout.fat_size_sectors;
        int32_t cluster_count = layout.cluster_count;

        int root_dir_sectors = (type == FAT_TYPE32) ? 0 :
            (32 * root_entry_count + bytes_per_sector - 1) / bytes_per_sector;
        int64_t fat_start_sector = reserved;
        int64_t root_dir_start_sector = fat_start_sector + num_fats * fat_size_sectors;
        int64_t data_start_sector = root_dir_start_sector + root_dir_sectors;

        size_t bootsector_buf_size = bytes_per_sector;
        uint8_t *bootsector_buf = calloc(1, bootsector_buf_size);
        struct fat_boot_sector *bs;
        char label_buf[11];

        if (!bootsector_buf) {
            fprintf(stderr, "out of memory\n");
            goto out;
        }

        format_label(label, label_buf);

        bs = (struct fat_boot_sector *)bootsector_buf;
        bs->jmpboot[0] = 0xeb;
        bs->jmpboot[1] = 0x3c;
        bs->jmpboot[2] = 0x90;
        memcpy(bs->oem_name, "VFATFUSE", 8);
        bs->bytes_per_sector = bytes_per_sector;
        bs->sectors_per_cluster = spc;
        bs->reserved_sectors_count = reserved;
        bs->num_fats = num_fats;
        bs->root_entry_count = root_entry_count;
        if (total_sectors <= 0xffff) {
            bs->total_sectors16 = total_sectors;
            bs->total_sectors32 = 0;
        } else {
            bs->total_sectors16 = 0;
            bs->total_sectors32 = total_sectors;
        }
        bs->media = DEFAULT_MEDIA;
        bs->fat_size16 = (type == FAT_TYPE32) ? 0 : fat_size_sectors;
        bs->sectors_per_track = 63;
        bs->num_heads = 64;
        bs->hidden_sectors = 0;

        if (type == FAT_TYPE32) {
            struct fat_boot_sector_ext32 *ext32 =
                (struct fat_boot_sector_ext32 *)(bootsector_buf + sizeof(*bs));

            ext32->fat_size = fat_size_sectors;
            ext32->ext_flags = 0;
            ext32->fs_version[0] = 0;
            ext32->fs_version[1] = 0;
            ext32->root_cluster = FAT32_ROOT_CLUSTER;
            ext32->fs_info_sector = FAT32_FSINFO_SECTOR;
            ext32->backup_boot_sector = FAT32_BACKUP_BOOT_SECTOR;
            ext32->drive_num = DEFAULT_DRIVE_NUM;
            ext32->reserved2 = 0;
            ext32->boot_signature = EXT_BOOT_SIGNATURE;
            ext32->volume_id = volume_id;
            memcpy(ext32->volume_label, label_buf, 11);
            memcpy(ext32->file_system_type, "FAT32   ", 8);
        } else {
            struct fat_boot_sector_ext16 *ext16 =
                (struct fat_boot_sector_ext16 *)(bootsector_buf + sizeof(*bs));

            ext16->drive_num = DEFAULT_DRIVE_NUM;
            ext16->reserved = 0;
            ext16->ext_boot_signature = EXT_BOOT_SIGNATURE;
            ext16->volume_id = volume_id;
            memcpy(ext16->volume_label, label_buf, 11);
            memcpy(ext16->file_system_type, (type == FAT_TYPE12) ? "FAT12   " : "FAT16   ", 8);
        }

        /* end-of-sector boot signature, at the very end of the logical sector */
        bootsector_buf[bootsector_buf_size - 2] = 0x55;
        bootsector_buf[bootsector_buf_size - 1] = 0xaa;

        if (pwrite(fd, bootsector_buf, bootsector_buf_size, 0) != (ssize_t)bootsector_buf_size) {
            fprintf(stderr, "%s: writing boot sector failed: %s\n", path, strerror(errno));
            free(bootsector_buf);
            goto out;
        }

        if (type == FAT_TYPE32 && reserved > FAT32_BACKUP_BOOT_SECTOR) {
            off_t backup_off = (off_t)FAT32_BACKUP_BOOT_SECTOR * bytes_per_sector;
            if (pwrite(fd, bootsector_buf, bootsector_buf_size, backup_off) != (ssize_t)bootsector_buf_size) {
                fprintf(stderr, "%s: writing backup boot sector failed: %s\n", path, strerror(errno));
                free(bootsector_buf);
                goto out;
            }
        }
        free(bootsector_buf);

        if (type == FAT_TYPE32) {
            struct fat_fsinfo fsinfo;
            off_t fsinfo_off = (off_t)FAT32_FSINFO_SECTOR * bytes_per_sector;

            memset(&fsinfo, 0, sizeof(fsinfo));
            fsinfo.lead_sig = 0x41615252;
            fsinfo.struc_sig = 0x61417272;
            fsinfo.free_count = cluster_count - 1; /* cluster 2 used by root dir */
            fsinfo.next_free = FAT32_ROOT_CLUSTER + 1;
            fsinfo.trail_sig = 0xaa550000;

            if (pwrite(fd, &fsinfo, sizeof(fsinfo), fsinfo_off) != (ssize_t)sizeof(fsinfo)) {
                fprintf(stderr, "%s: writing fsinfo sector failed: %s\n", path, strerror(errno));
                goto out;
            }
            if (reserved > FAT32_BACKUP_BOOT_SECTOR + 1) {
                off_t backup_fsinfo_off = (off_t)(FAT32_BACKUP_BOOT_SECTOR + 1) * bytes_per_sector;
                if (pwrite(fd, &fsinfo, sizeof(fsinfo), backup_fsinfo_off) != (ssize_t)sizeof(fsinfo)) {
                    fprintf(stderr, "%s: writing backup fsinfo sector failed: %s\n", path, strerror(errno));
                    goto out;
                }
            }
        }

        /*
         * Build one FAT copy in memory: entries 0/1 are reserved (media
         * descriptor + end-of-chain marker), matching the bit layout that
         * fat_next_cluster()/fat_set_cluster() (fat.c) decode on read.
         * FAT32 additionally marks cluster 2 (the root directory) as a
         * single-cluster chain.
         */
        {
            size_t fat_size_bytes = (size_t)fat_size_sectors * bytes_per_sector;
            uint8_t *fatbuf = calloc(1, fat_size_bytes);
            off_t fat_start_byte = fat_start_sector * bytes_per_sector;

            if (!fatbuf) {
                fprintf(stderr, "out of memory\n");
                goto out;
            }

            if (type == FAT_TYPE12) {
                uint16_t e0 = 0xf00 | DEFAULT_MEDIA;
                uint16_t e1 = fat_eoc_sentinel_for_type(FAT_TYPE12);
                fatbuf[0] = e0 & 0xff;
                fatbuf[1] = ((e0 >> 8) & 0x0f) | ((e1 & 0x0f) << 4);
                fatbuf[2] = (e1 >> 4) & 0xff;
            } else if (type == FAT_TYPE16) {
                uint16_t *fat16 = (uint16_t *)fatbuf;
                fat16[0] = 0xff00 | DEFAULT_MEDIA;
                fat16[1] = fat_eoc_sentinel_for_type(FAT_TYPE16);
            } else {
                uint32_t *fat32 = (uint32_t *)fatbuf;
                fat32[0] = 0x0fffff00 | DEFAULT_MEDIA;
                fat32[1] = fat_eoc_sentinel_for_type(FAT_TYPE32);
                fat32[FAT32_ROOT_CLUSTER] = fat_eoc_sentinel_for_type(FAT_TYPE32);
            }

            rc = write_fat_tables(fd, fatbuf, fat_size_bytes, num_fats, fat_start_byte);
            free(fatbuf);
            if (rc != 0)
                goto out;
        }

        /* root directory: fixed area for FAT12/16, first data cluster for FAT32 */
        {
            size_t root_bytes = (type == FAT_TYPE32) ?
                (size_t)spc * bytes_per_sector : (size_t)root_dir_sectors * bytes_per_sector;
            off_t root_off = (type == FAT_TYPE32) ?
                (off_t)data_start_sector * bytes_per_sector : (off_t)root_dir_start_sector * bytes_per_sector;
            uint8_t *root_buf = calloc(1, root_bytes);

            if (!root_buf) {
                fprintf(stderr, "out of memory\n");
                goto out;
            }

            if (label && label[0]) {
                struct fat_dir_entry *entry = (struct fat_dir_entry *)root_buf;
                memcpy(entry->name, label_buf, 11);
                entry->attr = FAT_ATTR_VOLUME_ID;
                fat_time_to_fat((time_t)0, &entry->creation_date, &entry->creation_time);
                entry->write_date = entry->creation_date;
                entry->write_time = entry->creation_time;
                entry->last_access_date = entry->creation_date;
            }

            if (pwrite(fd, root_buf, root_bytes, root_off) != (ssize_t)root_bytes) {
                fprintf(stderr, "%s: writing root directory failed: %s\n", path, strerror(errno));
                free(root_buf);
                goto out;
            }
            free(root_buf);
        }

        if (fsync(fd) != 0) {
            fprintf(stderr, "%s: fsync failed: %s\n", path, strerror(errno));
            goto out;
        }
        close(fd);
        fd = -1;

        /* re-open and re-parse the filesystem we just wrote as a sanity check */
        {
            int check_fd = open(path, O_RDONLY);
            struct fat_context *check_ctx;

            if (check_fd < 0) {
                fprintf(stderr, "%s: cannot reopen for verification: %s\n", path, strerror(errno));
                goto out;
            }
            check_ctx = init_fat_context(check_fd);
            if (!check_ctx) {
                fprintf(stderr, "%s: verification failed to parse the filesystem just written\n", path);
                close(check_fd);
                goto out;
            }
            if (check_ctx->type != type) {
                fprintf(stderr, "%s: internal error: wrote FAT%d but it reads back as FAT%d\n",
                        path, (type == FAT_TYPE12) ? 12 : (type == FAT_TYPE16) ? 16 : 32,
                        (check_ctx->type == FAT_TYPE12) ? 12 : (check_ctx->type == FAT_TYPE16) ? 16 : 32);
                free_fat_context(check_ctx);
                close(check_fd);
                goto out;
            }
            if (verbose) {
                printf("%s: FAT%d, %u bytes/sector, %u sectors/cluster, %d clusters, %d free\n",
                       path, (type == FAT_TYPE12) ? 12 : (type == FAT_TYPE16) ? 16 : 32,
                       (unsigned)bytes_per_sector, (unsigned)spc, cluster_count,
                       fat_free_cluster_count(check_ctx));
            }
            free_fat_context(check_ctx);
            close(check_fd);
        }
    }

    rc = 0;
out:
    if (fd >= 0)
        close(fd);
    return rc;
}
