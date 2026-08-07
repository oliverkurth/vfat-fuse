#ifndef MKFS_UTIL_H
#define MKFS_UTIL_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

/*
 * ftruncate(2) can only resize a regular file; on Linux it returns
 * EINVAL for block-special files, which already have a fixed size set
 * by the underlying device/partition. Split out from main() so the
 * S_ISBLK() distinction is unit-testable without a real block device.
 */
bool mkfs_needs_ftruncate(mode_t st_mode);

/* fixed sector index of FAT32's FSInfo structure; also needed by mkfs.c
 * itself to know where to write it */
#define FAT32_FSINFO_SECTOR 1

struct fat_layout {
    int type;
    int sectors_per_cluster;
    int reserved_sectors;
    int root_entry_count;
    int32_t fat_size_sectors;
    int32_t cluster_count;
};

/*
 * Layout search used by mkfs.vfat, split out from main() so it's
 * unit-testable directly. user_spc/user_root_entries/user_reserved <= 0
 * mean "no explicit override, choose automatically"; they're `long`
 * (matching main()'s strtol()-parsed variables) so an out-of-range CLI
 * value can't narrow into a negative int and silently fall back to the
 * built-in default instead of being honored (and rejected).
 */
bool choose_for_type(int type, int64_t total_sectors, int bytes_per_sector,
                      int num_fats, int user_spc, long user_root_entries,
                      long user_reserved, struct fat_layout *out);

bool auto_choose_layout(int64_t total_sectors, int bytes_per_sector,
                         int num_fats, int user_spc, long user_root_entries,
                         long user_reserved, struct fat_layout *out);

#endif
