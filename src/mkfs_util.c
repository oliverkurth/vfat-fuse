#include <sys/stat.h>

#include "mkfs_util.h"

bool mkfs_needs_ftruncate(mode_t st_mode)
{
    return !S_ISBLK(st_mode);
}
