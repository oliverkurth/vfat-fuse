#ifndef MKFS_UTIL_H
#define MKFS_UTIL_H

#include <stdbool.h>
#include <sys/types.h>

/*
 * ftruncate(2) can only resize a regular file; on Linux it returns
 * EINVAL for block-special files, which already have a fixed size set
 * by the underlying device/partition. Split out from main() so the
 * S_ISBLK() distinction is unit-testable without a real block device.
 */
bool mkfs_needs_ftruncate(mode_t st_mode);

#endif
