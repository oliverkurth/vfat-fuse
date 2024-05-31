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
    struct fat_dir_context *dir_ctx_root;
};

/* needed for statfs, which has no data arg */
struct fatfuse_data *g_fatfuse_data = NULL;

int fatfuse_init(struct fatfuse_data *data)
{
    data->fd = open(data->file_path, O_RDWR);
    if (data->fd < 0) {
        fprintf(stderr, "could not open %s: %s (%d)", data->file_path, strerror(errno), errno);
        return 1;
    }

    data->fat_ctx = init_fat_context(data->fd);
    if (data->fat_ctx == NULL) {
        fprintf(stderr, "could not initialize fat context");
        return 1;
    }

    data->dir_ctx_root = init_fat_dir_context_root(data->fat_ctx);
    if (data->dir_ctx_root == NULL) {
        fprintf(stderr, "could not initialize root dir context");
        return 1;
    }

    g_fatfuse_data = data;

    return 0;
}

void fatfuse_deinit(struct fatfuse_data *data)
{
    if (data->fd >= 0)
        close(data->fd);
    if (data->fat_ctx)
        free_fat_context(data->fat_ctx);
    if(data->dir_ctx_root)
        free_fat_dir_context(data->dir_ctx_root);
    if (data->file_path)
        free(data->file_path);
    if (data->options.file_path)
        free(data->options.file_path);
}

static
struct fat_dir_context *_fatfuse_find_dir_context(struct fat_dir_context *dir_ctx_root, const char *path)
{
    char path_copy[strlen(path) + 1];

    strcpy(path_copy, path + 1);

    return fat_dir_context_by_path(dir_ctx_root, dirname(path_copy));
}

static
struct fat_dir_entry *_fatfuse_find_entry_by_path(struct fat_dir_context *dir_ctx_root, const char *path)
{
    char path_copy[strlen(path) + 1];
    char path_copy1[strlen(path) + 1];

    strcpy(path_copy, path + 1);
    strcpy(path_copy1, path + 1);

    char *base_name = basename(path_copy);
    char *dir_name = dirname(path_copy1);

    struct fat_dir_context *dir_ctx = fat_dir_context_by_path(dir_ctx_root, dir_name);

    if (dir_ctx) {
        int index = fat_dir_find_entry_index(dir_ctx, base_name);
        if (index >= 0)
            return &dir_ctx->entries[index];
    }
    return NULL;
}

static int fatfuse_getattr(const char *path, struct stat *stbuf,
                           struct fuse_file_info *fi)
{
    (void) fi;
    int rc = 0;
    struct stat st;
    struct fatfuse_data *data = (struct fatfuse_data *)fuse_get_context()->private_data;
    struct fat_dir_context *dir_ctx_root = data->dir_ctx_root;
    struct fat_dir_entry *entry = NULL;

    /* special case for root, which has no entry */
    if (strcmp(path, "/") == 0) {
        if(fstat(data->fd, stbuf)) {
            rc = -errno;
            goto error;
        }
        stbuf->st_mode &= ~S_IFMT;
        stbuf->st_mode |= S_IFDIR;
        return 0;
    }

    entry = _fatfuse_find_entry_by_path(dir_ctx_root, path);
    if (entry) {
        if(fstat(data->fd, &st)){
            rc = -errno;
            goto error;
        }
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

error:
    return rc;
}

static int fatfuse_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                           off_t offset, struct fuse_file_info *fi,
                           enum fuse_readdir_flags flags)
{
    (void) fi;
    (void) offset;
    (void) flags;
    int rc = 0;
    struct fatfuse_data *data = (struct fatfuse_data *)fuse_get_context()->private_data;
    struct fat_dir_context *dir_ctx_root = data->dir_ctx_root;
    struct fat_dir_context *dir_ctx;
    int i;

    if (strcmp(path, "/") == 0) {
        dir_ctx = dir_ctx_root;
    } else {
        dir_ctx = fat_dir_context_by_path(dir_ctx_root, path + 1);
    }

    if (!dir_ctx) {
        rc = -EIO;
        goto error;
    }

    if (!dir_ctx->entries) fat_dir_read(dir_ctx);

    if (dir_ctx == dir_ctx_root) {
        filler(buf, ".", NULL, 0, 0);
        filler(buf, "..", NULL, 0, 0);
    }

    for(i = 0; dir_ctx->entries[i].name[0]; i++) {
        struct fat_dir_entry *entry = &dir_ctx->entries[i];
        if (fat_entry_is_valid(entry)) {
            char name[256];
            fat_dir_get_entry_name(dir_ctx, entry, name);
            if (filler(buf, name, NULL, 0, 0)) {
                break;
            }
        }
    }

error:
	return rc;
}

static int fatfuse_open(const char *path, struct fuse_file_info *fi)
{
    (void) fi;
    struct fatfuse_data *data = (struct fatfuse_data *)fuse_get_context()->private_data;
    struct fat_dir_context *dir_ctx_root = data->dir_ctx_root;
    struct fat_dir_entry *entry = NULL;

    entry = _fatfuse_find_entry_by_path(dir_ctx_root, path);

    if (entry->attr & FAT_ATTR_READ_ONLY)
        if ((fi->flags & O_ACCMODE) != O_RDONLY)
            return -EACCES;

    return 0;
}

static int fatfuse_read(const char *path, char *buf, size_t size, off_t offset,
                        struct fuse_file_info *fi)
{
    ssize_t rd = 0;
    (void) fi;
    struct fatfuse_data *data = (struct fatfuse_data *)fuse_get_context()->private_data;
    struct fat_context *fat_ctx = data->fat_ctx;
    struct fat_dir_context *dir_ctx_root = data->dir_ctx_root;
    struct fat_dir_entry *entry = NULL;

    entry = _fatfuse_find_entry_by_path(dir_ctx_root, path);
    if (entry) {
        rd = fat_file_pread(fat_ctx, entry, buf, offset, size);
    } else {
        rd = -ENOENT;
    }

    return rd;
}

static int fatfuse_write(const char *path, const char *buf, size_t size, off_t offset,
                         struct fuse_file_info *fi)
{
    ssize_t wr = 0;
    struct fatfuse_data *data = (struct fatfuse_data *)fuse_get_context()->private_data;
    struct fat_dir_context *dir_ctx_root = data->dir_ctx_root;

    struct fat_dir_context *dir_ctx = _fatfuse_find_dir_context(dir_ctx_root, path);
    if (!dir_ctx)
        return -ENOENT;

    char path_copy[strlen(path) + 1];
    strcpy(path_copy, path + 1);

    int index = fat_dir_find_entry_index(dir_ctx, basename(path_copy));
    if (index < 0)
        return -ENOENT;

    wr = fat_file_pwrite(dir_ctx, index, buf, offset, size);
    if (wr < 0)
        return -errno;

    return wr;
}

static int fatfuse_unlink(const char *path)
{
    struct fatfuse_data *data = (struct fatfuse_data *)fuse_get_context()->private_data;
    struct fat_dir_context *dir_ctx_root = data->dir_ctx_root;

    struct fat_dir_context *dir_ctx = _fatfuse_find_dir_context(dir_ctx_root, path);
    if (!dir_ctx)
        return -ENOENT;

    char path_copy[strlen(path) + 1];
    strcpy(path_copy, path + 1);

    int index = fat_dir_find_entry_index(dir_ctx, basename(path_copy));
    if (index < 0)
        return -ENOENT;

    struct fat_dir_entry *entry = &dir_ctx->entries[index];

    if (entry->attr & FAT_ATTR_DIRECTORY)
        return -EISDIR;

    far_dir_entry_delete(dir_ctx, index);

    return 0;
}

static int fatfuse_rmdir(const char *path)
{
    struct fatfuse_data *data = (struct fatfuse_data *)fuse_get_context()->private_data;
    struct fat_dir_context *dir_ctx_root = data->dir_ctx_root;

    struct fat_dir_context *dir_ctx = _fatfuse_find_dir_context(dir_ctx_root, path);
    if (!dir_ctx)
        return -ENOENT;

    char path_copy[strlen(path) + 1];
    strcpy(path_copy, path + 1);

    int index = fat_dir_find_entry_index(dir_ctx, basename(path_copy));
    if (index < 0)
        return -ENOENT;

    struct fat_dir_entry *entry = &dir_ctx->entries[index];

    if (!(entry->attr & FAT_ATTR_DIRECTORY))
        return -ENOTDIR;

    struct fat_dir_context *subdir_ctx = fat_dir_get_dir_context(dir_ctx, index);
    if (!fat_dir_is_empty(subdir_ctx))
        return -ENOTEMPTY;

    far_dir_entry_delete(dir_ctx, index);

    return 0;
}

static int fatfuse_create(const char *path, mode_t mode,
                          struct fuse_file_info *fi)
{
    struct fatfuse_data *data = (struct fatfuse_data *)fuse_get_context()->private_data;
    struct fat_dir_context *dir_ctx_root = data->dir_ctx_root;

    struct fat_dir_context *dir_ctx = _fatfuse_find_dir_context(dir_ctx_root, path);
    if (!dir_ctx)
        return -ENOENT;

    char path_copy[strlen(path) + 1];
    strcpy(path_copy, path + 1);

    int index = fat_dir_find_entry_index(dir_ctx, basename(path_copy));
    if (index >= 0)
        return -EEXIST;

    index = fat_dir_create_entry(dir_ctx, basename(path_copy), 0);
    if (index < 0)
        return -ENOBUFS; /* good value? */

    return 0;
}

static int fatfuse_rename(const char *from, const char *to, unsigned int flags)
{
    struct fatfuse_data *data = (struct fatfuse_data *)fuse_get_context()->private_data;
    struct fat_dir_context *dir_ctx_root = data->dir_ctx_root;

    if(_fatfuse_find_entry_by_path(dir_ctx_root, to) != NULL)
        return -EEXIST;

    struct fat_dir_context *dir_ctx = _fatfuse_find_dir_context(dir_ctx_root, from);
    if (!dir_ctx) {
        fprintf(stderr, "dir not found\n");
        return -ENOENT;
    }

    char path_copy_dir_from[strlen(from) + 1];
    strcpy(path_copy_dir_from, from + 1);

    char path_copy_dir_to[strlen(from) + 1];
    strcpy(path_copy_dir_to, from + 1);

    if (strcmp(dirname(path_copy_dir_from), dirname(path_copy_dir_to)) != 0)
        return -ENOSYS;

    char path_copy[strlen(from) + 1];
    strcpy(path_copy, from + 1);

    int index = fat_dir_find_entry_index(dir_ctx, basename(path_copy));
    if (index < 0){
        fprintf(stderr, "dir not found\n");
        return -ENOENT;
    }

    char path_copy_base_to[strlen(to) + 1];
    strcpy(path_copy_base_to, to + 1);

    if (far_dir_entry_rename(dir_ctx, index, basename(path_copy_base_to)) != 0)
        return errno ? -errno : -EIO;

    return 0;
}

static int fatfuse_mkdir(const char *path, mode_t mode)
{
    struct fatfuse_data *data = (struct fatfuse_data *)fuse_get_context()->private_data;
    struct fat_dir_context *dir_ctx_root = data->dir_ctx_root;

    struct fat_dir_context *dir_ctx = _fatfuse_find_dir_context(dir_ctx_root, path);
    if (!dir_ctx)
        return -ENOENT;

    char path_copy[strlen(path) + 1];
    strcpy(path_copy, path + 1);

    int index = fat_dir_find_entry_index(dir_ctx, basename(path_copy));
    if (index >= 0)
        return -EEXIST;

    index = fat_dir_create_entry(dir_ctx, basename(path_copy), FAT_ATTR_DIRECTORY);
    if (index < 0)
        return -ENOBUFS; /* good value? */

    return 0;
}

static int fatfuse_utimens(const char *path, const struct timespec tv[2],
                           struct fuse_file_info *fi)
{
	(void) fi;

    struct fatfuse_data *data = (struct fatfuse_data *)fuse_get_context()->private_data;
    struct fat_dir_context *dir_ctx_root = data->dir_ctx_root;

    struct fat_dir_context *dir_ctx = _fatfuse_find_dir_context(dir_ctx_root, path);
    if (!dir_ctx)
        return -ENOENT;

    char path_copy[strlen(path) + 1];
    strcpy(path_copy, path + 1);

    int index = fat_dir_find_entry_index(dir_ctx, basename(path_copy));
    if (index < 0)
        return -ENOENT;

    struct fat_dir_entry *entry = &dir_ctx->entries[index];

    if (tv != NULL) {
        fat_time_to_fat(tv[0].tv_sec, &entry->last_access_date, NULL);
        fat_time_to_fat(tv[1].tv_sec, &entry->write_date, &entry->write_time);
    } else {
        fat_time_to_fat((time_t)0, &entry->write_date, &entry->write_time);
        entry->last_access_date = entry->write_date;
    }

    fat_file_pwrite_to_cluster(dir_ctx->fat_ctx, dir_ctx->first_cluster,
                               (void *)entry,
                               index * sizeof(struct fat_dir_entry), sizeof(struct fat_dir_entry));

	return 0;
}

static int fatfuse_statfs(const char *path, struct statvfs *stbuf)
{
    struct fat_context *fat_ctx = g_fatfuse_data->fat_ctx;

    stbuf->f_bsize = stbuf->f_frsize = fat_ctx->bootsector.sectors_per_cluster * fat_ctx->bootsector.bytes_per_sector;
    stbuf->f_blocks = fat_ctx->num_clusters;
    stbuf->f_bfree = stbuf->f_bavail = fat_free_cluster_count(fat_ctx);

    stbuf->f_fsid = fat_ctx->bootsector_ext.ext16.volume_id;
    stbuf->f_namemax = 255;

	return 0;
}

static
int fatfuse_opt_proc(void *data, const char *arg,
                     int key, struct fuse_args *outargs)
{
    (void) outargs;
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
    .readdir	= fatfuse_readdir,
    .open       = fatfuse_open,
    .read       = fatfuse_read,
    .write      = fatfuse_write,
    .unlink     = fatfuse_unlink,
    .rename     = fatfuse_rename,
    .rmdir      = fatfuse_rmdir,
    .create     = fatfuse_create,
    .mkdir      = fatfuse_mkdir,
    .utimens    = fatfuse_utimens,
    .statfs     = fatfuse_statfs,
};

int main(int argc, char *argv[])
{
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    struct stat stbuf;
    struct fatfuse_data data = {0};
    int argc_saved;
    char **argv_saved;
    int ret;

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

    ret = fuse_main(argc_saved, argv_saved, &fatfuse_oper, (void *)&data);
    fatfuse_deinit(&data);
    fuse_opt_free_args(&args);
    return ret;
}
