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

    int32_t total_sectors = ctx->bootsector.total_sectors16;
    if (total_sectors == 0)
        total_sectors = ctx->bootsector.total_sectors32;

    int32_t fat_sectors = ctx->bootsector.fat_size16;
    if (fat_sectors == 0)
        fat_sectors = ctx->bootsector_ext.ext32.fat_size;

    int32_t root_dir_start_sector = fat_start_sector + ctx->bootsector.num_fats * fat_sectors;
    int32_t root_dir_sectors = (32 * ctx->bootsector.root_entry_count + ctx->bootsector.bytes_per_sector - 1) / ctx->bootsector.bytes_per_sector;
    int32_t data_start_sector = root_dir_start_sector + root_dir_sectors;
    int32_t data_sectors = total_sectors - data_start_sector;
    int32_t cluster_count = data_sectors / ctx->bootsector.sectors_per_cluster;

    ctx->num_clusters = (total_sectors - fat_sectors * ctx->bootsector.num_fats - ctx->bootsector.reserved_sectors_count) / ctx->bootsector.sectors_per_cluster;

    /* FAT type only determined by cluster count */
    if (cluster_count <= 4085) {
        ctx->type = FAT_TYPE12;
    } else if(cluster_count <= 65525) {
        ctx->type = FAT_TYPE16;
    } else {
        ctx->type = FAT_TYPE32;
    }

    if (ctx->type == FAT_TYPE32) {
        /* FAT32 */
        int64_t fat_sectors = ctx->bootsector_ext.ext32.fat_size * ctx->bootsector.num_fats;

        ctx->fat32 = malloc(ctx->bootsector_ext.ext32.fat_size * ctx->bootsector.bytes_per_sector);

        rc = pread(fd, ctx->fat32,
                   ctx->bootsector_ext.ext32.fat_size * ctx->bootsector.bytes_per_sector,
                   fat_start_sector * ctx->bootsector.bytes_per_sector);

        if (rc != ctx->bootsector_ext.ext32.fat_size * ctx->bootsector.bytes_per_sector) {
            fprintf(stderr, "reading FAT32 failed\n");
            goto error;
        }

        ctx->data_start_sector = fat_start_sector + fat_sectors;
        ctx->type = FAT_TYPE32;

        ctx->fs_info = malloc(sizeof(struct fat_fsinfo));

        rc = pread(fd, ctx->fs_info,
                   sizeof(struct fat_fsinfo),
                   ctx->bootsector_ext.ext32.fs_info_sector * ctx->bootsector.bytes_per_sector);

        if (rc != sizeof(struct fat_fsinfo)) {
            fprintf(stderr, "reading fsinfo failed\n");
            goto error;
        }

    } else if (ctx->type == FAT_TYPE16) {
        /* FAT16 or FAT12 */
        int64_t fat_sectors = ctx->bootsector.fat_size16 * ctx->bootsector.num_fats;

        ctx->fat16 = malloc(ctx->bootsector.fat_size16 * ctx->bootsector.bytes_per_sector);

        rc = pread(fd, ctx->fat16,
                   ctx->bootsector.fat_size16 * ctx->bootsector.bytes_per_sector,
                   fat_start_sector * ctx->bootsector.bytes_per_sector);

        if (rc != ctx->bootsector.fat_size16 * ctx->bootsector.bytes_per_sector) {
               fprintf(stderr, "reading FAT16 failed\n");
               goto error;
           }

        ctx->rootdir16_sector = fat_start_sector + fat_sectors;
        ctx->data_start_sector = ctx->rootdir16_sector + (ctx->bootsector.root_entry_count * 32) / ctx->bootsector.bytes_per_sector;
        ctx->type = FAT_TYPE16;
    } else {
        fprintf(stderr, "fat type FAT12 not (yet) supported\n");
        goto error;
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
        if (ctx->fs_info)
            free(ctx->fs_info);
        free(ctx);
    }
}

uint32_t fat_next_cluster(struct fat_context *fat_ctx, uint32_t cluster)
{
    if (fat_ctx->type == FAT_TYPE32)
        return fat_ctx->fat32[cluster] & 0x0FFFFFFF;
    else
        return fat_ctx->fat16[cluster] & 0xFFFF;
}

int32_t fat_free_cluster_count(struct fat_context *fat_ctx)
{
    int32_t count = 0, i;
    for (i = 0; i < fat_ctx->num_clusters; i++) {
        if (fat_next_cluster(fat_ctx, i) == 0) {
            count++;
        }
    }
    return count;
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

void fat_dir_entry_set_cluster(struct fat_dir_entry *entry, uint32_t cluster)
{
    entry->first_cluster_low = cluster & 0xffff;
    entry->first_cluster_high = (cluster >> 16) & 0xffff;
}

uint32_t fat_first_cluster(struct fat_context *fat_ctx)
{
    if (fat_ctx->type == FAT_TYPE32)
        return fat_ctx->bootsector_ext.ext32.root_cluster;
    else
        return 0;
}

bool fat_cluster_is_eoc(struct fat_context *fat_ctx, uint32_t cluster)
{
    if (fat_ctx->type == FAT_TYPE32)
        return (cluster & 0x0FFFFFF8) == 0x0FFFFFF8;
    else
        return (cluster & 0xFFF8) == 0xFFF8;
}

int fat_write_fat_cluster(struct fat_context *fat_ctx, uint32_t cluster)
{
    int64_t fat_start_sector = fat_ctx->bootsector.reserved_sectors_count;
    off_t offset = fat_start_sector * fat_ctx->bootsector.bytes_per_sector;
    ssize_t wr = 0;
    int i;

    if (fat_ctx->type == FAT_TYPE32) {
        offset += cluster * sizeof(uint32_t);
        for (i = 0; i < fat_ctx->bootsector.num_fats; i++) {
            wr = pwrite(fat_ctx->fd, &fat_ctx->fat32[cluster], sizeof(uint32_t), offset);
            offset += fat_ctx->bootsector_ext.ext32.fat_size * fat_ctx->bootsector.bytes_per_sector;
        }
    } else {
        offset += cluster * sizeof(uint16_t);
        for (i = 0; i < fat_ctx->bootsector.num_fats; i++) {
            wr = pwrite(fat_ctx->fd, &fat_ctx->fat16[cluster], sizeof(uint16_t), offset);
            offset += fat_ctx->bootsector.fat_size16 * fat_ctx->bootsector.bytes_per_sector;
        }
    }
    return wr;
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

uint32_t fat_set_cluster(struct fat_context *fat_ctx, uint32_t cluster, uint32_t value)
{
    uint32_t old_value;
    if (fat_ctx->type == FAT_TYPE32) {
        old_value = fat_ctx->fat32[cluster] & 0x0FFFFFFF;
        fat_ctx->fat32[cluster] = value;
    } else {
        old_value = fat_ctx->fat16[cluster] & 0xFFFF;
        fat_ctx->fat16[cluster] = value;
    }
    return old_value;
}

uint32_t fat_set_cluster_eoc(struct fat_context *fat_ctx, uint32_t cluster)
{
    if (fat_ctx->type == FAT_TYPE32) {
        return fat_set_cluster(fat_ctx, cluster, 0x0FFFFFFF);
    } else {
        return fat_set_cluster(fat_ctx, cluster, 0xFFFF);
    }
}

int32_t fat_allocate_cluster(struct fat_context *fat_ctx, int32_t cluster_hint)
{
    int32_t cluster;

    if (cluster_hint < 2)
        cluster_hint = 2;

    for(cluster = cluster_hint; cluster < fat_ctx->num_clusters; cluster++){
        if (fat_next_cluster(fat_ctx, cluster) == 0) {
            fat_set_cluster_eoc(fat_ctx, cluster);
            fat_write_fat_cluster(fat_ctx, cluster);

            return cluster;
        }
    }
    return -1;
}

ssize_t fat_file_pread_from_cluster(struct fat_context *fat_ctx, int32_t cluster, void *buf, off_t pos, size_t len)
{
    uint8_t *ptr = (uint8_t *)buf;
    uint32_t bytes_per_cluster = (fat_ctx->bootsector.bytes_per_sector * fat_ctx->bootsector.sectors_per_cluster);

    while ((len > 0) && (cluster > 0) && !fat_cluster_is_eoc(fat_ctx, cluster)) {
        int64_t sector = fat_get_sector_from_cluster(fat_ctx, cluster);
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
            cluster = fat_next_cluster(fat_ctx, cluster);
    }
    return ptr - (uint8_t *)buf;
}

ssize_t fat_file_pread(struct fat_context *fat_ctx, struct fat_dir_entry *entry, void *buf, off_t pos, size_t len)
{
    int32_t cluster;

    if (!(entry->attr & FAT_ATTR_DIRECTORY) && (entry->filesize > 0)) {
        /* do not read beyond end of file */
        if ((pos + len) > entry->filesize) {
            len = entry->filesize - pos;
        }
    }

    cluster = fat_find_cluster(fat_ctx, entry, pos);

    if (cluster < 0)
        return -1;

    return fat_file_pread_from_cluster(fat_ctx, cluster, buf, pos, len);
}

/* clusters need to be allocated already */
ssize_t fat_file_pwrite_to_cluster(struct fat_context *fat_ctx, int32_t cluster, const void *buf, off_t pos, size_t len)
{
    int rc = 0;
    uint8_t *ptr = (uint8_t *)buf;
    uint32_t bytes_per_cluster = (fat_ctx->bootsector.bytes_per_sector * fat_ctx->bootsector.sectors_per_cluster);

    while (pos >= bytes_per_cluster && !fat_cluster_is_eoc(fat_ctx, cluster)) {
        cluster = fat_next_cluster(fat_ctx, cluster);
        pos -= bytes_per_cluster;
    }

    if (fat_cluster_is_eoc(fat_ctx, cluster)) {
        fprintf(stderr, "attempt to write beyond end of cluster chain\n");
        return -1;
    }

    while ((len > 0) && (cluster > 0) && !fat_cluster_is_eoc(fat_ctx, cluster)) {
        int64_t sector = fat_get_sector_from_cluster(fat_ctx, cluster);
        uint32_t skip = pos & (bytes_per_cluster - 1);

        uint32_t write_len = bytes_per_cluster - skip;
        if (len < write_len)
            write_len = len;

        off_t p = (sector * fat_ctx->bootsector.bytes_per_sector) + skip;

        ssize_t wr = pwrite(fat_ctx->fd, ptr, write_len, p);
        if (wr < 0) {
            fprintf(stderr, "pwrite failed: %s\n", strerror(errno));
            return wr;
        }
        if (wr < write_len) {
            fprintf(stderr, "short pwrite (%d < %d), p=%d: %s\n", (int)wr, write_len, (int)p, strerror(errno));
            return -1;
        }
        ptr += write_len;
        len -= write_len;
        pos += write_len;
        if (skip + write_len >= bytes_per_cluster)
            cluster = fat_next_cluster(fat_ctx, cluster);
    }
    return ptr - (uint8_t *)buf;
error:
    return rc;
}

ssize_t fat_dir_write_entries(struct fat_dir_context *dir_ctx, int index, int count)
{
    int rc = 0;
    struct fat_context *fat_ctx = dir_ctx->fat_ctx;
    ssize_t wr, size;

    size = sizeof(struct fat_dir_entry) * count;

    if (dir_ctx->ctx_parent != NULL || fat_ctx->type == FAT_TYPE32) {
        wr = fat_file_pwrite_to_cluster(fat_ctx, dir_ctx->first_cluster,
                                       (void *)&dir_ctx->entries[index],
                                       index * sizeof(struct fat_dir_entry), size);
        check_cond(wr == size);
    } else {
        off_t pos = fat_ctx->rootdir16_sector * fat_ctx->bootsector.bytes_per_sector + index * sizeof(struct fat_dir_entry);
        wr = pwrite(fat_ctx->fd, (void *)&dir_ctx->entries[index], size, pos);
        check_cond(wr == size);
    }
    return wr;
error:
    return rc;
}

ssize_t fat_dir_file_entry_extend(struct fat_dir_context *dir_ctx, int index, size_t new_size)
{
    int rc = 0;
    struct fat_context *fat_ctx = dir_ctx->fat_ctx;
    size_t bytes_per_cluster = ((size_t)fat_ctx->bootsector.bytes_per_sector * (size_t)fat_ctx->bootsector.sectors_per_cluster);
    struct fat_dir_entry *entry = &dir_ctx->entries[index];
    int32_t cl_count_current = ((int)entry->filesize - 1)/bytes_per_cluster + 1;
    int32_t cl_count_needed = (new_size - 1)/bytes_per_cluster + 1;
    int32_t cluster;

    if (cl_count_needed > cl_count_current) {
        uint8_t buf0[bytes_per_cluster];
        memset(buf0, 0, bytes_per_cluster);

        int32_t last_cluster;
        for (last_cluster = fat_dir_entry_get_cluster(entry);
             last_cluster && !fat_cluster_is_eoc(fat_ctx, fat_next_cluster(fat_ctx, last_cluster));
             last_cluster = fat_next_cluster(fat_ctx, last_cluster));

        if (last_cluster == 0) {
            /* no cluster yet for entry */
            last_cluster = fat_allocate_cluster(fat_ctx, 0);
            fat_dir_entry_set_cluster(entry, last_cluster);
            ssize_t wr = fat_file_pwrite_to_cluster(fat_ctx, last_cluster,
                                                    (void *)buf0,
                                                    0, bytes_per_cluster);
            check_cond(wr == bytes_per_cluster);
            cl_count_current++;
        }

        while (cl_count_needed > cl_count_current) {
            cluster = fat_allocate_cluster(fat_ctx, last_cluster);
            ssize_t wr = fat_file_pwrite_to_cluster(fat_ctx, cluster,
                                                    (void *)buf0,
                                                    0, bytes_per_cluster);
            check_cond(wr == bytes_per_cluster);
            fat_set_cluster(fat_ctx, last_cluster, cluster);
            fat_write_fat_cluster(fat_ctx, last_cluster);
            last_cluster = cluster;
            cl_count_current++;
        }
    }
    entry->filesize = new_size;
    fat_dir_write_entries(dir_ctx, index, 1);

    return new_size;
error:
    return rc;
}

ssize_t fat_file_pwrite(struct fat_dir_context *dir_ctx, int index, const void *buf, off_t pos, size_t len)
{
    int rc = 0;
    struct fat_context *fat_ctx = dir_ctx->fat_ctx;
    struct fat_dir_entry *entry = &dir_ctx->entries[index];

    if (!(entry->attr & FAT_ATTR_DIRECTORY)) {
        /* extend file if needed */
        if ((pos + len) > entry->filesize) {
            fat_dir_file_entry_extend(dir_ctx, index, pos + len);
        }
    }

    int32_t cluster = fat_dir_entry_get_cluster(entry);
    ssize_t wr = fat_file_pwrite_to_cluster(fat_ctx, cluster, buf, pos, len);
    check_cond(wr == len);

    /* update write time */
    fat_time_to_fat((time_t)0, &entry->write_date, &entry->write_time);
    rc = fat_dir_write_entries(dir_ctx, index, 1);
    check_cond(rc >= 0);

    return wr;
error:
    return rc;
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

ssize_t fat_dir_read_root16(struct fat_dir_context *ctx)
{
    struct fat_context *fat_ctx = ctx->fat_ctx;
    struct fat_boot_sector *bs = &fat_ctx->bootsector;
    ssize_t dir_size = bs->root_entry_count * 32;
    off_t pos = fat_ctx->rootdir16_sector * bs->bytes_per_sector;

    if (ctx->entries)
        free(ctx->entries);
    ctx->entries = malloc(dir_size);

    ctx->num_entries = bs->root_entry_count;

    if (ctx->sub_dirs)
        free(ctx->sub_dirs);
    ctx->sub_dirs = calloc(ctx->num_entries, sizeof(struct fat_dir_context *));

    ssize_t rd = pread(fat_ctx->fd, (void *)ctx->entries, dir_size, pos);

    return rd;
}

ssize_t fat_dir_read(struct fat_dir_context *ctx)
{
    struct fat_context *fat_ctx = ctx->fat_ctx;
    size_t bytes_per_cluster = ((size_t)fat_ctx->bootsector.bytes_per_sector * (size_t)fat_ctx->bootsector.sectors_per_cluster);
    int32_t cluster, num_clusters = 0;

    for(cluster = ctx->first_cluster;
        cluster && !fat_cluster_is_eoc(fat_ctx, cluster);
        cluster = fat_next_cluster(fat_ctx, cluster)) {
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

    ssize_t rd = fat_file_pread_from_cluster(fat_ctx, ctx->first_cluster, (void *)ctx->entries, 0, dir_size);
    if (rd < dir_size) {
        fprintf(stderr, "fat_file_pread_from_cluster failed: %s\n", strerror(errno));
        free(ctx->entries);
        return rd;
    }

    return rd;
}

static
struct fat_dir_context *_init_fat_dir_context(struct fat_context *fat_ctx, struct fat_dir_context *ctx_parent, int32_t first_cluster)
{
    struct fat_dir_context *ctx = calloc(sizeof(struct fat_dir_context), 1);

    ctx->fat_ctx = fat_ctx;
    ctx->first_cluster = first_cluster;
    ctx->ctx_parent = ctx_parent;

    return ctx;
}

struct fat_dir_context *init_fat_dir_context(struct fat_context *fat_ctx, struct fat_dir_context *ctx_parent, int index)
{
    struct fat_dir_entry *entry = &ctx_parent->entries[index];
    struct fat_dir_context *ctx = _init_fat_dir_context(fat_ctx, ctx_parent, fat_dir_entry_get_cluster(entry));

    fat_dir_read(ctx);

    return ctx;
}

struct fat_dir_context *init_fat_dir_context_root(struct fat_context *fat_ctx)
{
    struct fat_dir_context *ctx;

    if (fat_ctx->type == FAT_TYPE32) {
        ctx = _init_fat_dir_context(fat_ctx, NULL, fat_first_cluster(fat_ctx));
        fat_dir_read(ctx);
    } else {
        ctx = _init_fat_dir_context(fat_ctx, NULL, 0);
        fat_dir_read_root16(ctx);
    }
    return ctx;
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
    int second = (time & 0x1f) << 1;

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

void fat_time_to_fat(time_t t, __le16 *pdate, __le16 *ptime)
{
    struct tm *tm;

    if (t == 0)
        time(&t);
    tm = localtime(&t);

    if (pdate)
        *pdate = (tm->tm_year - 80) << 9 | ((tm->tm_mon + 1) << 5) | tm->tm_mday;
    if (ptime)
        *ptime = (tm->tm_hour << 11) | (tm->tm_min << 5) | (tm->tm_sec >> 1);
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

    char sfn[12];
    fat_file_sfn_pretty(entry, sfn);

    for (i = 0; (struct fat_dir_entry *)lfn_entry >= ctx->entries; i++, lfn_entry--) {
        if (lfn_entry->attr != FAT_ATTR_LONG_FILE_NAME || lfn_entry->seq_number == 0xe5) {
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
            fprintf(stderr, "lfn checksum %x does not match %x, sfn=%s\n", lfn_entry->checksum, checksum, sfn);
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

bool fat_entry_is_valid(struct fat_dir_entry *entry)
{
    return (entry->name[0] != 0) && (entry->attr != FAT_ATTR_LONG_FILE_NAME) && (entry->name[0] != 0xe5);
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
        if (fat_entry_is_valid(entry)) {
            if (fat_name_matches_entry(ctx, entry, path_copy)) {
                if (entry->attr & FAT_ATTR_DIRECTORY) {
                    if (ctx->sub_dirs[i] == NULL) {
                        ctx->sub_dirs[i] = init_fat_dir_context(ctx->fat_ctx, ctx, i);
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
        if (fat_entry_is_valid(entry)) {
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

struct fat_dir_context *fat_dir_get_dir_context(struct fat_dir_context *ctx, int index)
{
    if (index >= 0) {
        if (ctx->sub_dirs[index] == NULL) {
            ctx->sub_dirs[index] = init_fat_dir_context(ctx->fat_ctx, ctx, index);
        }
        return ctx->sub_dirs[index];
    }
    return NULL;
}

struct fat_dir_context *fat_dir_find_dir_context(struct fat_dir_context *ctx, const char *name)
{
    int index = fat_dir_find_entry_index(ctx, name);
    return fat_dir_get_dir_context(ctx, index);
}

bool fat_dir_is_empty(struct fat_dir_context *dir_ctx)
{
    int i;
    for(i = 0; dir_ctx->entries[i].name[0]; i++) {
        if (fat_entry_is_valid(&dir_ctx->entries[i])) {
            char sfn[13];
            fat_file_sfn_pretty(&dir_ctx->entries[i], sfn);
            if (strcmp(sfn, ".") == 0 || strcmp(sfn, "..") == 0)
                continue;
            return false;
        }
    }
    return true;
}

static
int _fat_dir_delete_lfn_entries(struct fat_dir_context *dir_ctx, int index)
{
    int rc = 0;

    if (dir_ctx->entries[index].name[0] == 0xe5) {
        struct fat_lfn_entry *lfn_entry;
        for(int j = index - 1; j >= 0; j--) {
            lfn_entry = (struct fat_lfn_entry *)&dir_ctx->entries[j];
            if (lfn_entry->attr == FAT_ATTR_LONG_FILE_NAME) {
                lfn_entry->seq_number = 0xe5;
                rc = fat_dir_write_entries(dir_ctx, j, 1);
                check_cond(rc >= 0);
            } else
                break;
        }
    }
error:
    return rc;
}

static
int _fat_dir_count_lfn_entries(struct fat_dir_context *dir_ctx, int index)
{
    struct fat_lfn_entry *lfn_entry;
    int count = 0;

    for(int j = index - 1; j >= 0; j--) {
        lfn_entry = (struct fat_lfn_entry *)&dir_ctx->entries[j];
        if (lfn_entry->attr == FAT_ATTR_LONG_FILE_NAME) {
            count++;
        } else
            break;
    }
    return count;
}

int far_dir_entry_delete(struct fat_dir_context *dir_ctx, int index)
{
    int rc = 0;
    struct fat_context *fat_ctx = dir_ctx->fat_ctx;
    struct fat_dir_entry *entry = &dir_ctx->entries[index];
    int32_t cluster = fat_dir_entry_get_cluster(entry);
    int32_t next_cluster;

    if (cluster && cluster >= 2) {
        for(;!fat_cluster_is_eoc(fat_ctx, cluster) && cluster >= 2; cluster = next_cluster) {
            next_cluster = fat_set_cluster(fat_ctx, cluster, 0);
            fat_write_fat_cluster(fat_ctx, cluster);
        }
    }
    entry->first_cluster_low = entry->first_cluster_high = 0;
    entry->name[0] = 0xe5;
    entry->filesize = 0;

    rc = fat_dir_write_entries(dir_ctx, index, 1);
    check_cond(rc >= 0);

    rc = _fat_dir_delete_lfn_entries(dir_ctx, index);
    check_cond(rc >= 0);

error:
    return rc;
}

/* convert a filename to a SFN entry. Does not NUL terminate */
static char *_str_to_sfn(const char *name, char *buf)
{
    char *p;
    const char *q = name;

    p = buf;
    while (*q && *q != '.')
        if (p - buf < 8)
            *p++ = toupper(*q++);
        else
            q++;
    if (*q == '.') {
        while(p - buf < 8)
            *p++ = ' ';
        q++;
        while(*q && (p - buf < 11))
            *p++ = toupper(*q++);
    }
    while(p - buf < 11)
        *p++ = ' ';

    return buf;
}

bool _name_needs_lfn(const char *name)
{
    const char *p = name;
    const char *dot = NULL;
    const char *specials = "$%'-_@~`!(){}^#&";

    while(*p) {
        if ((dot == NULL) && p - 8 > name)
            return true;
        else if (dot && p - 3 > dot)
            return true;
        if (islower(*p))
            return true;
        if (*p == '.') {
            if (dot != NULL)
                return true;
            dot = p;
        }
        if (!isalnum(*p) && *p < 0x80 && *p != '.') {
            const char *s = specials;
            while(*s) {
                if (*p == *s)
                    break;
                s++;
            }
            if (!*s)
                return true;
        }
        p++;
    }
    return false;
}

int _create_lfn_entry(struct fat_dir_context *dir_ctx, int index, const wchar_t *wname)
{
    int i;
    struct fat_dir_entry *entry = &dir_ctx->entries[index];
    struct fat_lfn_entry *lfn_entry = (struct fat_lfn_entry *)&(entry[-1]);
    uint8_t checksum = _lfn_checksum(entry->name);
    const wchar_t *wq = wname;
    uint16_t *p16;

    for (i = 0; (struct fat_dir_entry *)lfn_entry >= dir_ctx->entries; i++, lfn_entry--) {
        memset(lfn_entry, 0, sizeof(struct fat_lfn_entry));
        lfn_entry->seq_number = (uint8_t)i+1;
        for (p16 = lfn_entry->name1; *wq && p16 < lfn_entry->name1+5; *p16++ = (uint16_t)*wq++);
        for (p16 = lfn_entry->name2; *wq && p16 < lfn_entry->name2+6; *p16++ = (uint16_t)*wq++);
        for (p16 = lfn_entry->name3; *wq && p16 < lfn_entry->name3+2; *p16++ = (uint16_t)*wq++);
        lfn_entry->attr = FAT_ATTR_LONG_FILE_NAME;
        lfn_entry->checksum = checksum;
        if (!*wq) {
            lfn_entry->seq_number |= FAT_LFN_LAST_LONG_ENTRY;
            break;
        }
    }
    if (*wq)
        return -1;
    return i + 1;
}

/* returns index of main entry, lfn entries will be before that */
int fat_dir_allocate_entries(struct fat_dir_context *dir_ctx, int count)
{
    int rc;
    struct fat_context *fat_ctx = dir_ctx->fat_ctx;
    int i, found = 0, pos = 0;

    /* find sufficiently large block of deleted entries */
    for (i = 0; i < dir_ctx->num_entries; i++) {
        if (dir_ctx->entries[i].name[0] == 0xe5 || dir_ctx->entries[i].name[0] == 0) {
            if (!found)
                pos = i;
            found++;
            if (found == count)
                break;
        } else {
            found = 0;
        }
    }

    if (found == count)
        return pos + count - 1;

    if (dir_ctx->ctx_parent == NULL && fat_ctx->type != FAT_TYPE32) {
        fprintf(stderr, "cannot allocate additional clusters for root dir in FAT12/16\n");
        return -1;
    }

    pos = dir_ctx->num_entries - found;

    if ((pos + count) > (1 << 16))
        /* 2^16 is the max entries */
        return -1;

    int32_t last_cluster;
    size_t bytes_per_cluster = ((size_t)fat_ctx->bootsector.bytes_per_sector * (size_t)fat_ctx->bootsector.sectors_per_cluster);

    for (last_cluster = dir_ctx->first_cluster;
         !fat_cluster_is_eoc(fat_ctx, fat_next_cluster(fat_ctx, last_cluster));
         last_cluster = fat_next_cluster(fat_ctx, last_cluster));

    int32_t new_cluster = fat_allocate_cluster(fat_ctx, 0);
    fat_write_fat_cluster(fat_ctx, new_cluster);

    uint8_t buf0[bytes_per_cluster];
    memset(buf0, 0, bytes_per_cluster);

    ssize_t wr = fat_file_pwrite_to_cluster(fat_ctx, new_cluster,
                                            (void *)buf0,
                                            0, bytes_per_cluster);
    check_cond(wr == bytes_per_cluster);
    fat_set_cluster(fat_ctx, last_cluster, new_cluster);
    fat_write_fat_cluster(fat_ctx, last_cluster);

    int old_max = dir_ctx->num_entries;
    dir_ctx->num_entries += bytes_per_cluster / sizeof(struct fat_dir_entry);
    dir_ctx->entries = realloc(dir_ctx->entries, dir_ctx->num_entries * sizeof(struct fat_dir_entry));
    dir_ctx->sub_dirs = realloc(dir_ctx->sub_dirs, dir_ctx->num_entries * sizeof(struct fat_dir_context *));
    /* realloc does not zero out */
    memset(&dir_ctx->entries[old_max], 0, bytes_per_cluster);
    memset(&dir_ctx->sub_dirs[old_max], 0, (dir_ctx->num_entries - old_max) * sizeof(struct fat_dir_context *));

    return pos + count - 1;
error:
    return rc;
}

int fat_dir_create_entry(struct fat_dir_context *dir_ctx, const char *name, int attr)
{
    int rc = 0;
    struct fat_context *fat_ctx = dir_ctx->fat_ctx;
    size_t bytes_per_cluster = ((size_t)fat_ctx->bootsector.bytes_per_sector * (size_t)fat_ctx->bootsector.sectors_per_cluster);
    ssize_t wr = 0;
    int index, count = 1;
    wchar_t wname[strlen(name)+1];

    if (_name_needs_lfn(name)) {
        str_to_wstr(name, wname);
        count += (wcslen(wname)-1)/13+1;
    }

    index = fat_dir_allocate_entries(dir_ctx, count);
    if (index < 0)
        return index;

    struct fat_dir_entry *entry = &dir_ctx->entries[index];

    memset((void *)entry, 0, sizeof(struct fat_dir_entry));
    _str_to_sfn(name, entry->name);
    entry->attr = attr;
    entry->ntres = 0;

    fat_time_to_fat((time_t)0, &entry->creation_date, &entry->creation_time);
    entry->write_time = entry->creation_time;
    entry->write_date = entry->creation_date;

    if (count > 1) /* have LFN entries */
        _create_lfn_entry(dir_ctx, index, wname);

    if (attr & FAT_ATTR_DIRECTORY) {
        /* move to own function? */
        int32_t cluster = fat_allocate_cluster(fat_ctx, 0);

        if (cluster < 2) {
            fprintf(stderr, "fat_allocate_cluster failed\n");
            return -1;
        }

        struct fat_dir_context *newdir_ctx = _init_fat_dir_context(fat_ctx, dir_ctx, cluster);

        newdir_ctx->entries = calloc(bytes_per_cluster, 1);
        newdir_ctx->num_entries = bytes_per_cluster / sizeof(struct fat_dir_entry);
        newdir_ctx->sub_dirs = calloc(newdir_ctx->num_entries, sizeof(struct fat_dir_context *));

        struct fat_dir_entry *sub_entries = newdir_ctx->entries;
        memcpy(sub_entries[0].name, ".          ", 11);
        memcpy(sub_entries[1].name, "..         ", 11);
        sub_entries[0].attr = sub_entries[1].attr = FAT_ATTR_DIRECTORY;
        sub_entries[0].creation_date = sub_entries[1].creation_date = entry->creation_date;
        sub_entries[0].creation_time = sub_entries[1].creation_time = entry->creation_time;
        sub_entries[0].write_date = sub_entries[1].write_date = entry->write_date;
        sub_entries[0].write_time = sub_entries[1].write_time = entry->write_time;

        entry->first_cluster_low = cluster & 0xffff;
        entry->first_cluster_high = (cluster >> 16) & 0xffff;

        sub_entries[0].first_cluster_low = entry->first_cluster_low;
        sub_entries[0].first_cluster_high = entry->first_cluster_high;

        if (dir_ctx->ctx_parent != NULL) {
            sub_entries[1].first_cluster_low = dir_ctx->first_cluster & 0xffff;
            sub_entries[1].first_cluster_high = (dir_ctx->first_cluster >> 16) & 0xffff;
        }

        wr = fat_file_pwrite_to_cluster(
            fat_ctx, cluster,
            (void *)sub_entries,
            0, bytes_per_cluster);
        if (wr < bytes_per_cluster)
            return -1;

        dir_ctx->sub_dirs[index] = newdir_ctx;
    }

    wr = fat_dir_write_entries(dir_ctx, index - count + 1, count);
    check_cond(wr >= 0);

    return index;
error:
    return rc;
}

/* rename a file in same dir */
int far_dir_entry_rename(struct fat_dir_context *dir_ctx, int index, const char *name)
{
    struct fat_dir_entry *entry = &dir_ctx->entries[index];
    ssize_t wr;
    int old_count = 1, new_count = 1, new_index = index;
    wchar_t wname[strlen(name)+1];

    old_count += _fat_dir_count_lfn_entries(dir_ctx, index);

    if (_name_needs_lfn(name)) {
        str_to_wstr(name, wname);
        new_count += (wcslen(wname)-1)/13+1;
    }

    if (old_count >= new_count) {
        _str_to_sfn(name, entry->name);
        for (int i = 0; i < old_count - 1; i++) {
            dir_ctx->entries[index - i - 1].name[0] = 0xe5;
        }
        if (new_count > 1) /* have LFN entries */
            _create_lfn_entry(dir_ctx, index, wname);

        wr = fat_dir_write_entries(dir_ctx, index - old_count + 1, old_count);
        if (wr < sizeof(struct fat_dir_entry))
            return -1;
    } else {
        new_index = fat_dir_allocate_entries(dir_ctx, new_count);
        if (new_index < 0)
            return new_index;

        struct fat_dir_entry *new_entry = &dir_ctx->entries[new_index];

        memcpy((void *)new_entry, (void *)entry, sizeof(struct fat_dir_entry));
        _str_to_sfn(name, new_entry->name);

        _create_lfn_entry(dir_ctx, new_index, wname);

        wr = fat_dir_write_entries(dir_ctx, new_index - new_count + 1, new_count);
        if (wr < sizeof(struct fat_dir_entry))
            return -1;

        for (int i = 0; i < old_count; i++) {
            dir_ctx->entries[index - i].name[0] = 0xe5;
        }
        wr = fat_dir_write_entries(dir_ctx, index - old_count + 1, old_count);
        if (wr < sizeof(struct fat_dir_entry))
            return -1;
    }

    return new_index;
}

/* move a file to another directory */
int fat_dir_entry_move(struct fat_dir_context *dir_ctx, int index, struct fat_dir_context *dir_ctx_dest, const char *name)
{
    struct fat_dir_entry *entry = &dir_ctx->entries[index];
    ssize_t wr;
    int old_count = 1, new_count = 1, new_index = index;
    wchar_t wname[strlen(name)+1];

    old_count += _fat_dir_count_lfn_entries(dir_ctx, index);

    if (_name_needs_lfn(name)) {
        str_to_wstr(name, wname);
        new_count += (wcslen(wname)-1)/13+1;
    }

    new_index = fat_dir_allocate_entries(dir_ctx_dest, new_count);
    if (new_index < 0)
        return new_index;

    struct fat_dir_entry *new_entry = &dir_ctx_dest->entries[new_index];

    memcpy((void *)new_entry, (void *)entry, sizeof(struct fat_dir_entry));
    _str_to_sfn(name, new_entry->name);

    _create_lfn_entry(dir_ctx_dest, new_index, wname);

    wr = fat_dir_write_entries(dir_ctx_dest, new_index - new_count + 1, new_count);
    if (wr < sizeof(struct fat_dir_entry))
        return -1;

    for (int i = 0; i < old_count; i++) {
        dir_ctx->entries[index - i].name[0] = 0xe5;
    }
    wr = fat_dir_write_entries(dir_ctx, index - old_count + 1, old_count);
    if (wr < sizeof(struct fat_dir_entry))
        return -1;

    return new_index;
}

int far_dir_entry_set_attr(struct fat_dir_context *dir_ctx, int index, uint8_t attr)
{
    struct fat_dir_entry *entry = &dir_ctx->entries[index];

    entry->attr = attr;

    ssize_t wr = fat_dir_write_entries(dir_ctx, index, 1);
    if (wr < sizeof(struct fat_dir_entry))
        return -1;
    return 0;
}
