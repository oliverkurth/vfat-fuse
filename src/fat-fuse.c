#define FUSE_USE_VERSION 31

#include <fuse.h>
#include <fuse_lowlevel.h>
#include <libgen.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

#include "fat.h"


#define check_cond(COND) if(!(COND)) { \
    fprintf(stderr, "check_cond failed in %s line %d\n", \
        __FUNCTION__, __LINE__); \
    rc = -1; \
    ((void)(rc)); /* suppress "set but not used" warning */ \
    goto error; \
}

#define check_ptr(ptr) if(!(ptr)) { \
    fprintf(stderr, "check_ptr failed in %s line %d\n", \
        __FUNCTION__, __LINE__); \
    rc = -1; \
    ((void)(rc)); /* suppress "set but not used" warning */ \
    goto error; \
}

#define safe_free(ptr) { if ((ptr) != NULL) { free(ptr); ptr = NULL; }}

struct options {
    char *file_path;
};

#define OPTION(t, p) { t, offsetof(struct options, p), 1 }
static const struct fuse_opt option_spec[] = {
    OPTION("--file=%s", file_path),
    FUSE_OPT_END
};

struct fatfuse_data {
    struct options options;
    char *file_path;
    int fd;
    struct fat_context *fat_ctx;
};

int fatfuse_init(struct fatfuse_data *data)
{
    data->fd = open(data->file_path, O_RDONLY);
    if (data->fd < 0) {
        fprintf(stderr, "could not open %s: %s (%d)", data->file_path, strerror(errno), errno);
        return 1;
    }

    data->fat_ctx = init_fat_context(data->fd);
    if (data->fat_ctx == NULL) {
        fprintf(stderr, "could not initialize fat context");
        return 1;
    }

    return 0;
}

static int fatfuse_getattr(const char *path, struct stat *stbuf,
                           struct fuse_file_info *fi)
{
	(void) fi;
    int rc = 0;
    struct stat st;
    struct fatfuse_data *data = (struct fatfuse_data *)fuse_get_context()->private_data;
    struct fat_context *fat_ctx = data->fat_ctx;
    struct fat_dir_context *dir_ctx_root = NULL, *dir_ctx = NULL;
    struct fat_dir_entry *entry = NULL;
    int index;
    char path_copy[strlen(path) + 1];
    char path_copy1[strlen(path) + 1];

    strcpy(path_copy, path + 1);
    strcpy(path_copy1, path + 1);

    char *base_name = basename(path_copy);
    char *dir_name = dirname(path_copy1);

    dir_ctx_root = init_fat_dir_context(fat_ctx, fat_ctx->bootsector_ext.ext32.root_cluster);
    fat_dir_read(dir_ctx_root);

    dir_ctx = fat_dir_context_by_path(dir_ctx_root, dir_name);
    if (!dir_ctx) {
        rc = -ENOENT;
        goto error;
    }
    if (dir_ctx) {
        index = fat_dir_find_entry_index(dir_ctx, base_name);
        if (index >= 0) {
            entry = &dir_ctx->entries[index];

            fstat(data->fd, &st);

            stbuf->st_mode = (st.st_mode & ~S_IFMT) | (S_IXUSR|S_IXGRP|S_IXOTH);
            if (entry->attr & FAT_ATTR_DIRECTORY)
                stbuf->st_mode |= S_IFDIR;
            else
                stbuf->st_mode |= S_IFREG;
            if (entry->attr & FAT_ATTR_READ_ONLY)
                stbuf->st_mode &= ~(S_IWUSR|S_IWGRP|S_IWOTH);

            stbuf->st_nlink = 1;
            stbuf->st_uid = getuid();
            stbuf->st_gid = getgid();
            stbuf->st_size = entry->filesize;
            stbuf->st_blocks = entry->filesize/512;
            stbuf->st_atime = fat_time(entry, FAT_DATE_ACCESS);
            stbuf->st_mtime = fat_time(entry, FAT_DATE_WRITE);
            stbuf->st_ctime = fat_time(entry, FAT_DATE_WRITE);
        } else {
            rc = -ENOENT;
            goto error;  
        }
    }

error:
    if (dir_ctx_root) free_fat_dir_context(dir_ctx_root);
	return rc;
}

static
int fatfuse_opt_proc(void *data, const char *arg,
			         int key, struct fuse_args *outargs)
{
    struct fatfuse_data *fatfuse_data = (struct fatfuse_data *)data;

	switch (key) {
	case FUSE_OPT_KEY_NONOPT:
        if (fatfuse_data->options.file_path == NULL) {
            fatfuse_data->options.file_path = strdup(arg);
            return 0;
        }
        return 1;
    }
    return 1;
}

static const struct fuse_operations fatfuse_oper = {
    .getattr	= fatfuse_getattr,
};

int main(int argc, char *argv[])
{
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	struct stat stbuf;
    struct fatfuse_data data = {0};
    int argc_saved;
    char **argv_saved;

    if (fuse_opt_parse(&args, &data, option_spec, fatfuse_opt_proc) == -1)
            return 1;

    if (!data.options.file_path) {
        fprintf(stderr, "missing fat file parameter (file=)\n");
        return 1;        
    } else {
        data.file_path = realpath(data.options.file_path, NULL);
    }

    if (stat(data.file_path, &stbuf) == -1) {
        fprintf(stderr ,"failed to access fat file %s: %s\n",
            data.file_path, strerror(errno));
        free(data.file_path);
        exit(1);
    }
    if (!S_ISREG(stbuf.st_mode)) { // TODO: allow device file
        fprintf(stderr, "fat file %s is not a regular file\n", data.file_path);
        exit(1);
    }

    argc_saved = args.argc;
    argv_saved = args.argv;

    if (fatfuse_init(&data) != 0) {
        return 1;
    }

    return fuse_main(argc_saved, argv_saved, &fatfuse_oper, (void *)&data);
}
