#include <asm/byteorder.h>
#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "fat.h"


struct fat_context *init_fat_context(int fd)
{
    struct fat_context *ctx = calloc(sizeof(struct fat_context), 1);
    read(fd, &ctx->bootsector, sizeof(ctx->bootsector));
    read(fd, &ctx->bootsector_ext, sizeof(ctx->bootsector_ext));

    int64_t fat_start_sector = ctx->bootsector.reserved_sectors_count;
    int64_t fat_sectors = ctx->bootsector_ext.ext32.fat_size * ctx->bootsector.num_fats;

    ctx->fat = malloc(ctx->bootsector_ext.ext32.fat_size * ctx->bootsector.bytes_per_sector);

    pread(fd, ctx->fat,
          ctx->bootsector_ext.ext32.fat_size * ctx->bootsector.bytes_per_sector,
          fat_start_sector * ctx->bootsector.bytes_per_sector);

    ctx->data_start_sector = fat_start_sector + fat_sectors;

    ctx->fd = fd;

    return ctx;
}

void free_fat_context(struct fat_context *ctx)
{
    if (ctx) {
        if (ctx->fat)
            free(ctx->fat);
        free(ctx);
    }
}

void free_fat_file_context(struct fat_file_context *ctx)
{
    if (ctx) free(ctx);
}

struct fat_file_context *init_fat_file_context(struct fat_context *fat_ctx, int32_t first_cluster, size_t size)
{
    struct fat_file_context *ctx = calloc(sizeof(struct fat_file_context), 1);
    ctx->fat_ctx = fat_ctx;
    ctx->current_cluster = first_cluster;
    ctx->current_pos = 0;
    ctx->size = size;

    return ctx;
}

int64_t fat_get_sector_from_cluster(struct fat_context *fat_ctx, uint32_t cluster)
{
    return fat_ctx->data_start_sector + (cluster - 2) * fat_ctx->bootsector.sectors_per_cluster;
}

ssize_t fat_file_read(struct fat_file_context *file_ctx, void *buf, size_t len)
{
    struct fat_context *fat_ctx = file_ctx->fat_ctx;
    uint32_t bytes_per_cluster = (fat_ctx->bootsector.bytes_per_sector * fat_ctx->bootsector.sectors_per_cluster);
    uint8_t *ptr = (uint8_t *)buf;

    if (file_ctx->size > 0) {
        /* do not read beyond end of file */
        if ((file_ctx->current_pos + len) > file_ctx->size) {
            len = file_ctx->size - file_ctx->current_pos;
        }
    }

    while ((len > 0) && (file_ctx->current_cluster > 0)) {
        int64_t sector = fat_ctx->data_start_sector + (file_ctx->current_cluster - 2) * fat_ctx->bootsector.sectors_per_cluster; /* sector of current cluster */
        uint32_t skip = file_ctx->current_pos & (bytes_per_cluster - 1);

        uint32_t read_len = bytes_per_cluster - skip;
        if (len < read_len)
            read_len = len;

        off_t p = (sector * fat_ctx->bootsector.bytes_per_sector) + skip;

        ssize_t rd = pread(fat_ctx->fd, ptr, read_len, p);
        if (rd < 0) {
            fprintf(stderr, "pread failed: %s\n", strerror(errno));
            return rd;
        }
        if (rd < read_len) {
            fprintf(stderr, "short pread (%d < %d), p=%d: %s\n", (int)rd, read_len, (int)p, strerror(errno));
            return -1;
        }
        ptr += read_len;
        len -= read_len;
        file_ctx->current_pos += read_len;
        if (skip + read_len >= bytes_per_cluster)
            file_ctx->current_cluster = fat_ctx->fat[file_ctx->current_cluster] & 0x0FFFFFFF;
    }
    return ptr - (uint8_t *)buf;
}

void free_fat_dir_context(struct fat_dir_context *ctx)
{
    if (ctx) {
        int i;

        if (ctx->entries)
            free(ctx->entries);
        if (ctx->sub_dirs) {
            for (i = 0; i < ctx->num_entries; i++) {
                if (ctx->sub_dirs[i]) {
                    free_fat_dir_context(ctx->sub_dirs[i]);
                }
            }
            free(ctx->sub_dirs);
        }
        free(ctx);
    }
}

struct fat_dir_context *init_fat_dir_context(struct fat_context *fat_ctx, int32_t first_cluster)
{
    struct fat_dir_context *ctx = calloc(sizeof(struct fat_dir_context), 1);
    ctx->fat_ctx = fat_ctx;
    ctx->first_cluster = first_cluster;
}

ssize_t fat_dir_read(struct fat_dir_context *ctx)
{
    struct fat_context *fat_ctx = ctx->fat_ctx;
    size_t bytes_per_cluster = ((size_t)fat_ctx->bootsector.bytes_per_sector * (size_t)fat_ctx->bootsector.sectors_per_cluster);
    struct fat_file_context *file_ctx = init_fat_file_context(ctx->fat_ctx, ctx->first_cluster, 0);
    int32_t cluster, num_clusters = 0;

    for(cluster = ctx->first_cluster;
        cluster && ((cluster & 0x0FFFFFF8) != 0x0FFFFFF8);
        cluster = fat_ctx->fat[cluster] & 0x0FFFFFFF) {
        num_clusters++;
    }
    ssize_t dir_size = num_clusters * bytes_per_cluster;

    if (ctx->entries)
        free(ctx->entries);
    ctx->entries = malloc(dir_size);

    ctx->num_entries = dir_size / sizeof(struct fat_dir_entry);

    if (ctx->sub_dirs)
        free(ctx->sub_dirs);
    ctx->sub_dirs = calloc(ctx->num_entries, sizeof(struct fat_dir_context *));

    ssize_t rd = fat_file_read(file_ctx, (void *)ctx->entries, dir_size);
    if (rd < dir_size) {
        fprintf(stderr, "fat_file_read failed: %s\n", strerror(errno));
        free(ctx->entries);
        return rd;
    }

    free_fat_file_context(file_ctx);
}

const char *fat_pretty_date(struct fat_dir_entry *entry, char buf[], size_t buf_size, int type)
{
    int date = 0, time = 0;
    int tenths = 0;

    if (type == FAT_DATE_WRITE) {
        date = entry->write_date;
        time = entry->write_time;
    } else if (type == FAT_DATE_CREATION) {
        date = entry->creation_date;
        time = entry->creation_time;
        tenths = entry->creation_time_tenth;
    } else if (type == FAT_DATE_ACCESS) {
        date = entry->last_access_date;
        time = 0;
    }

    int year = (date >> 9) + 1980;
    int month = (date >> 5) & 0x0f;
    int day = date & 0x1f;

    int hour = time >> 11;
    int minute = (time >> 5) & 0x3f;
    int second = (time & 0x3f) * 2;

    snprintf(buf, buf_size, "%4d-%02d-%02d %02d:%02d:%02d", year, month, day, hour, minute, hour);

    return buf;
}

const char *fat_file_sfn_pretty(struct fat_dir_entry *entry, char buf[])
{
    int i;
    char *ptr = buf;

    char *slf = entry->name;
    for (i = 0; i < 8 && slf[i] != ' '; i++) {
        *ptr++ = tolower(slf[i]);
    }
    if (slf[8] != ' ')
        *ptr++ = '.';
    for (i = 8; i < 11 && slf[i] != ' '; i++) {
        *ptr++ = tolower(slf[i]);
    }
    *ptr = 0;
    return buf;
}

uint32_t fat_dir_entry_get_cluster(struct fat_dir_entry *entry)
{
    return ((uint32_t)entry->first_cluster_high << 16) + (uint32_t)entry->first_cluster_low;
}

struct fat_dir_entry *fat_dir_entry_by_path(struct fat_dir_context *ctx, const char *path)
{
    char path_copy[strlen(path)+1];
    char *path1;
    
    if (!ctx->entries)
        fat_dir_read(ctx);

    strcpy(path_copy, path);
    path1 = path_copy;
    strsep(&path1, "/");

    int i;
    for (i = 0; ctx->entries[i].name[0]; i++) {
        struct fat_dir_entry *entry = &ctx->entries[i];
        if (entry->attr != FAT_ATTR_LONG_FILE_NAME) {
            char sfn_pretty[12];
            fat_file_sfn_pretty(entry, sfn_pretty);
            if (strcasecmp(path_copy, sfn_pretty) == 0) {
                if (path1 == NULL || path1[0] == 0)
                    return entry;
                else if (entry->attr & FAT_ATTR_DIRECTORY) {
                    if (ctx->sub_dirs[i] == NULL) {
                        ctx->sub_dirs[i] = init_fat_dir_context(ctx->fat_ctx, fat_dir_entry_get_cluster(entry));
                    }
                    return fat_dir_entry_by_path(ctx->sub_dirs[i], path1);
                } else {
                    fprintf(stderr, "not a directory: %s\n", sfn_pretty);
                }
            }
        }
    }
    return NULL;
}

struct fat_dir_context *fat_dir_context_by_path(struct fat_dir_context *ctx, const char *path)
{
    char path_copy[strlen(path)+1];
    char *path1;

    if (!ctx->entries)
        fat_dir_read(ctx);

    if (strcmp(path, ".") == 0)
        return ctx;

    strcpy(path_copy, path);
    path1 = path_copy;
    strsep(&path1, "/");

    int i;
    for (i = 0; ctx->entries[i].name[0]; i++) {
        struct fat_dir_entry *entry = &ctx->entries[i];
        if (entry->attr != FAT_ATTR_LONG_FILE_NAME) {
            char sfn_pretty[12];
            fat_file_sfn_pretty(entry, sfn_pretty);
            if (strcasecmp(path_copy, sfn_pretty) == 0) {
                if (entry->attr & FAT_ATTR_DIRECTORY) {
                    if (ctx->sub_dirs[i] == NULL) {
                        ctx->sub_dirs[i] = init_fat_dir_context(ctx->fat_ctx, fat_dir_entry_get_cluster(entry));
                    }
                    if (path1 == NULL || path1[0] == 0) {
                        return ctx->sub_dirs[i];
                    } else {
                        return fat_dir_context_by_path(ctx->sub_dirs[i], path1);
                    }
                } else {
                    fprintf(stderr, "not a directory: %s\n", sfn_pretty);
                }
            }
        }
    }
    return NULL;
}

int fat_dir_find_entry_index(struct fat_dir_context *ctx, const char *name)
{
    if (!ctx->entries)
        fat_dir_read(ctx);

    int i;
    for (i = 0; ctx->entries[i].name[0]; i++) {
        struct fat_dir_entry *entry = &ctx->entries[i];
        if (entry->attr != FAT_ATTR_LONG_FILE_NAME) {
            char sfn_pretty[12];
            fat_file_sfn_pretty(entry, sfn_pretty);
            if (strcasecmp(name, sfn_pretty) == 0)
                return i;
        }
    }
    return -1;
}

struct fat_dir_entry *fat_dir_find_entry(struct fat_dir_context *ctx, const char *name)
{
    int index = fat_dir_find_entry_index(ctx, name);
    if (index >= 0)
        return &ctx->entries[index];
    return NULL;
}

struct fat_dir_context *fat_dir_find_dir_context(struct fat_dir_context *ctx, const char *name)
{
    int index = fat_dir_find_entry_index(ctx, name);
    if (index >= 0) {
        if (ctx->sub_dirs[index] == NULL) {
            struct fat_dir_entry *entry = &ctx->entries[index];
            ctx->sub_dirs[index] = init_fat_dir_context(ctx->fat_ctx, fat_dir_entry_get_cluster(entry));
            fat_dir_read(ctx->sub_dirs[index]);
        }
        return ctx->sub_dirs[index];
    }
    return NULL;
}
