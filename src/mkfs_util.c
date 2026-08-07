#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <wchar.h>

#include "fat.h"
#include "mkfs_util.h"

bool mkfs_needs_ftruncate(mode_t st_mode)
{
    return !S_ISBLK(st_mode);
}

static const int spc_candidates[] = {1, 2, 4, 8, 16, 32, 64, 128};
static const int num_spc_candidates = sizeof(spc_candidates) / sizeof(spc_candidates[0]);

/*
 * Fixed-point search for the smallest FAT size (in sectors) consistent with
 * the resulting cluster count, mirroring the layout arithmetic in
 * init_fat_context() (fat.c) so that a freshly written image is read back
 * as exactly the FAT type it was written as.
 */
static bool try_layout(int type, int64_t total_sectors, int bytes_per_sector,
                        int num_fats, int spc, long reserved_sectors, long root_entry_count,
                        struct fat_layout *out)
{
    int bits = (type == FAT_TYPE32) ? 32 : (type == FAT_TYPE16) ? 16 : 12;
    int64_t root_dir_sectors = (type == FAT_TYPE32) ? 0 :
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
        /* FAT32's FSInfo sector lives at the fixed index
         * FAT32_FSINFO_SECTOR; reserved_sectors must leave it (and the
         * boot sector at index 0) before the FAT table begins at
         * fat_start_sector == reserved_sectors, or the FAT write clobbers
         * the FSInfo sector that was just written */
        if (reserved_sectors <= FAT32_FSINFO_SECTOR)
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
bool choose_for_type(int type, int64_t total_sectors, int bytes_per_sector,
                      int num_fats, int user_spc, long user_root_entries,
                      long user_reserved, struct fat_layout *out)
{
    long reserved = (user_reserved > 0) ? user_reserved : (type == FAT_TYPE32 ? 32 : 1);
    long root_entries = (type == FAT_TYPE32) ? 0 : (user_root_entries > 0 ? user_root_entries : 512);
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
bool auto_choose_layout(int64_t total_sectors, int bytes_per_sector,
                         int num_fats, int user_spc, long user_root_entries,
                         long user_reserved, struct fat_layout *out)
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
