#define _GNU_SOURCE

#include <asm/byteorder.h>
#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <libgen.h>
#include <unistd.h>
#include <wctype.h>
#include <wchar.h>
#include "fat.h"


struct fat_context *init_fat_context(int fd)
{
    struct fat_context *ctx = calloc(sizeof(struct fat_context), 1);
    int rc;

    rc = read(fd, &ctx->bootsector, sizeof(ctx->bootsector));
    if (rc != sizeof(ctx->bootsector))
        return NULL;

    rc = read(fd, &ctx->bootsector_ext, sizeof(ctx->bootsector_ext));
    if (rc != sizeof(ctx->bootsector_ext))
        goto error;

    int64_t fat_start_sector = ctx->bootsector.reserved_sectors_count;
    if (ctx->bootsector.total_sectors16 == 0) {
        /* FAT32 */
        int64_t fat_sectors = ctx->bootsector_ext.ext32.fat_size * ctx->bootsector.num_fats;

        ctx->fat32 = malloc(ctx->bootsector_ext.ext32.fat_size * ctx->bootsector.bytes_per_sector);

        rc = pread(fd, ctx->fat32,
                   ctx->bootsector_ext.ext32.fat_size * ctx->bootsector.bytes_per_sector,
                   fat_start_sector * ctx->bootsector.bytes_per_sector);

        if (rc != ctx->bootsector_ext.ext32.fat_size * ctx->bootsector.bytes_per_sector)
            goto error;

        ctx->data_start_sector = fat_start_sector + fat_sectors;

        ctx->type = FAT_TYPE32;
    } else {
        /* FAT16 or FAT12 */
        int64_t fat_sectors = ctx->bootsector.fat_size16 * ctx->bootsector.num_fats;

        ctx->fat16 = malloc(ctx->bootsector.fat_size16 * ctx->bootsector.bytes_per_sector);

        rc = pread(fd, ctx->fat16,
                   ctx->bootsector.fat_size16 * ctx->bootsector.bytes_per_sector,
                   fat_start_sector * ctx->bootsector.bytes_per_sector);

        if (rc != ctx->bootsector.fat_size16 * ctx->bootsector.bytes_per_sector)
            goto error;

        ctx->data_start_sector = fat_start_sector + fat_sectors;

        ctx->type = FAT_TYPE16;
    }

    ctx->fd = fd;

    return ctx;
error:
    if (ctx) {
        if (ctx->fd > 0)
            close(ctx->fd);
        free_fat_context(ctx);
    }
    return NULL;
}

void free_fat_context(struct fat_context *ctx)
{
    if (ctx) {
        if (ctx->fat32)
            free(ctx->fat32);
        if (ctx->fat16)
            free(ctx->fat16);
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

uint32_t fat_dir_entry_get_cluster(struct fat_dir_entry *entry)
{
    return ((uint32_t)entry->first_cluster_high << 16) + (uint32_t)entry->first_cluster_low;
}

uint32_t fat_next_cluster(struct fat_context *fat_ctx, uint32_t cluster)
{
    return fat_ctx->fat32[cluster] & 0x0FFFFFFF;
}

bool fat_cluster_is_eoc(struct fat_context *fat_ctx, uint32_t cluster)
{
    return (cluster & 0x0FFFFFF8) == 0x0FFFFFF8;
}

int32_t fat_find_cluster(struct fat_context *fat_ctx, struct fat_dir_entry *entry, off_t pos)
{
    uint32_t bytes_per_cluster = (fat_ctx->bootsector.bytes_per_sector * fat_ctx->bootsector.sectors_per_cluster);
    int32_t cluster;

    if (pos > entry->filesize)
        return -1;

    for(cluster = fat_dir_entry_get_cluster(entry);
        pos >= bytes_per_cluster && cluster && !fat_cluster_is_eoc(fat_ctx, cluster);
        cluster = fat_next_cluster(fat_ctx, cluster)) {
            pos -= bytes_per_cluster;
    }

    if (fat_cluster_is_eoc(fat_ctx, cluster))
        return -1;

    return cluster;
}

ssize_t fat_file_pread(struct fat_context *fat_ctx, struct fat_dir_entry *entry, void *buf, off_t pos, size_t len)
{
    uint32_t bytes_per_cluster = (fat_ctx->bootsector.bytes_per_sector * fat_ctx->bootsector.sectors_per_cluster);
    uint8_t *ptr = (uint8_t *)buf;
    int32_t current_cluster;

    if (entry->filesize > 0) {
        /* do not read beyond end of file */
        if ((pos + len) > entry->filesize) {
            len = entry->filesize - pos;
        }
    }

    current_cluster = fat_find_cluster(fat_ctx, entry, pos);

    if (current_cluster < 0)
        return -1;

    while ((len > 0) && (current_cluster > 0)) {
        int64_t sector = fat_ctx->data_start_sector + (current_cluster - 2) * fat_ctx->bootsector.sectors_per_cluster; /* sector of current cluster */
        uint32_t skip = pos & (bytes_per_cluster - 1);

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
        pos += read_len;
        if (skip + read_len >= bytes_per_cluster)
            current_cluster = fat_next_cluster(fat_ctx, current_cluster);
    }
    return ptr - (uint8_t *)buf;
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
            file_ctx->current_cluster = fat_next_cluster(fat_ctx, file_ctx->current_cluster);
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

    return ctx;
}

ssize_t fat_dir_read(struct fat_dir_context *ctx)
{
    struct fat_context *fat_ctx = ctx->fat_ctx;
    size_t bytes_per_cluster = ((size_t)fat_ctx->bootsector.bytes_per_sector * (size_t)fat_ctx->bootsector.sectors_per_cluster);
    struct fat_file_context *file_ctx = init_fat_file_context(ctx->fat_ctx, ctx->first_cluster, 0);
    int32_t cluster, num_clusters = 0;

    for(cluster = ctx->first_cluster;
        cluster && !fat_cluster_is_eoc(fat_ctx, cluster);
        cluster = fat_next_cluster(fat_ctx, file_ctx->current_cluster)) {
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
    return rd;
}

const char *fat_pretty_date(struct fat_dir_entry *entry, char buf[], size_t buf_size, int type)
{
    int date = 0, time = 0;

    if (type == FAT_DATE_WRITE) {
        date = entry->write_date;
        time = entry->write_time;
    } else if (type == FAT_DATE_CREATION) {
        date = entry->creation_date;
        time = entry->creation_time;
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

    snprintf(buf, buf_size, "%4d-%02d-%02d %02d:%02d:%02d", year, month, day, hour, minute, second);

    return buf;
}

time_t fat_time(struct fat_dir_entry *entry, int type)
{
    time_t time;
    char buf[20];
    struct tm tm = {0};

    fat_pretty_date(entry, buf, sizeof(buf), type);
    strptime(buf, "%Y-%m-%d %H:%M:%S", &tm);
    time = mktime(&tm);
    return time;
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

static
uint8_t _lfn_checksum (const char *sfn)
{
    int i;
    uint8_t sum;

    for (i = sum = 0; i < 11; i++) { /* Calculate sum of DIR_Name[] field */
        sum = (sum >> 1) + (sum << 7) + sfn[i];
    }
    return sum;
}

wchar_t *fat_file_lfn(struct fat_dir_context *ctx, struct fat_dir_entry *entry, wchar_t buf[], size_t buf_size)
{
    int i, j, pos = 0;
    struct fat_lfn_entry *lfn_entry = (struct fat_lfn_entry *)&(entry[-1]);
    uint8_t checksum = _lfn_checksum(entry->name);

    if (entry == ctx->entries) {
        return NULL;
    }

    for (i = 0; (struct fat_dir_entry *)lfn_entry >= ctx->entries; i++, lfn_entry--) {
        if (lfn_entry->attr != FAT_ATTR_LONG_FILE_NAME) {
            return NULL;
        }
        if ((lfn_entry->seq_number & FAT_LFN_SEQ_MASK) - 1 != i) {
            fprintf(stderr, "lfn sequence %d out of order (!= %d)\n", lfn_entry->seq_number, i+1);
            return NULL;
        }
        if (lfn_entry->type != 0) {
            fprintf(stderr, "lfn type %x != 0\n", lfn_entry->type);
            return NULL;
        }
        if (lfn_entry->checksum != checksum) {
            fprintf(stderr, "lfn checksum %x does not match %x\n", lfn_entry->checksum, checksum);
            return NULL;
        }
        for (j = 0; j < 5 && pos < (int)buf_size-1; pos++, j++)
            buf[pos] = lfn_entry->name1[j];
        for (j = 0; j < 6 && pos < (int)buf_size-1; pos++, j++)
            buf[pos] = lfn_entry->name2[j];
        for (j = 0; j < 2 && pos < (int)buf_size-1; pos++, j++)
            buf[pos] = lfn_entry->name3[j];
        if (lfn_entry->seq_number & FAT_LFN_LAST_LONG_ENTRY)
            break;
    }
    buf[pos] = L'\0';

    return buf;
}

wchar_t *str_to_wstr(const char *str, wchar_t *wbuf)
{
    const char *str_ptr = str;
    ssize_t len = strlen(str);
    ssize_t wlen = mbsrtowcs(wbuf, &str_ptr, len+1, NULL);
    if (wlen == len)
        return wbuf;
    return NULL;
}

char *wstr_to_str(const wchar_t *wstr, char *buf)
{
    const wchar_t *wstr_ptr = wstr;
    ssize_t wlen = wcslen(wstr);
    ssize_t len = wcsrtombs(buf, &wstr_ptr, wlen+1, NULL);
    if (wlen == len)
        return buf;
    return NULL;
}

bool fat_name_matches_entry(struct fat_dir_context *ctx, struct fat_dir_entry *entry, const char *name)
{
    bool matched = false;
    wchar_t lfn[256];
    wchar_t wpath[strlen(name)+1];

    if (fat_file_lfn(ctx, entry, lfn, sizeof(lfn))) {
        str_to_wstr(name, wpath);
        if (wcscasecmp(lfn, wpath) == 0)
            matched = true;
    }
    if (!matched) {
        char sfn_pretty[12];
        fat_file_sfn_pretty(entry, sfn_pretty);
        if (strcasecmp(name, sfn_pretty) == 0)
            matched = true;
    }
    return matched;
}

char *fat_dir_get_entry_name(struct fat_dir_context *ctx, struct fat_dir_entry *entry, char *buf)
{
    wchar_t lfn[256];
    if (fat_file_lfn(ctx, entry, lfn, sizeof(lfn))) {
        wstr_to_str(lfn, buf);
    } else {
        fat_file_sfn_pretty(entry, buf);
    }
    return buf;
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
            if (fat_name_matches_entry(ctx, entry, path_copy)) {
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
                    fprintf(stderr, "not a directory: %s\n", path_copy);
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
            if (fat_name_matches_entry(ctx, entry, name))
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
