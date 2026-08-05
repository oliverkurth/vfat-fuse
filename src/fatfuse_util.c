#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <wchar.h>

#include "fatfuse_util.h"

int fatfuse_open_check(struct fat_dir_entry *entry, int accmode, int read_only)
{
    if (!entry)
        return -ENOENT;

    if (accmode != O_RDONLY) {
        if (entry->attr & FAT_ATTR_READ_ONLY)
            return -EACCES;
        if (read_only)
            return -EROFS;
    }
    return 0;
}

void fatfuse_force_singlethreaded(struct fuse_args *args)
{
    int i;

    for (i = 0; i < args->argc; i++) {
        if (strcmp(args->argv[i], "-s") == 0)
            return;
    }
    fuse_opt_add_arg(args, "-s");
}
