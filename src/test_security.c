/*
 * Regression tests for the findings in REVIEW.md.
 *
 * Built with -fsanitize=address,undefined against fat.c/fatfuse_util.c
 * (see the `test` target in Makefile) so that out-of-bounds reads/writes
 * and infinite loops are caught reliably rather than by chance.
 */
#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "fat.h"
#include "fatfuse_util.h"

static int tests_run = 0;

#define RUN(fn) do { \
    fprintf(stderr, "-- running %s\n", #fn); \
    fn(); \
    tests_run++; \
} while (0)

/* ---- issue 1: off-by-one stack overflow in SFN pretty-printing ---- */

static void test_sfn_pretty_full_8dot3_no_overflow(void)
{
    /* two entries, so entries[1] is not ctx->entries[0] (fat_file_lfn's
     * early-out) and fat_name_matches_entry/fat_file_lfn actually run the
     * sfn-pretty formatting path on it. */
    struct fat_dir_entry entries[2] = {0};
    struct fat_dir_context ctx = {0};

    memcpy(entries[0].name, "PLACEHOLD ", 11);
    memcpy(entries[1].name, "ABCDEFGHTXT", 11); /* "ABCDEFGH.TXT", full 8.3 */
    entries[1].attr = FAT_ATTR_ARCHIVE;

    ctx.entries = entries;
    ctx.num_entries = 2;

    char buf[FAT_SFN_PRETTY_SIZE];
    fat_file_sfn_pretty(&entries[1], buf);
    assert(strcmp(buf, "abcdefgh.txt") == 0);
    assert(strlen(buf) == 12); /* == FAT_SFN_PRETTY_SIZE - 1 */

    /* exercise the two call sites that were previously one byte short */
    wchar_t lfn[256];
    assert(fat_file_lfn(&ctx, &entries[1], lfn, 256) == NULL); /* no LFN precedes it */

    assert(fat_name_matches_entry(&ctx, &entries[1], "ABCDEFGH.TXT") == true);
    assert(fat_name_matches_entry(&ctx, &entries[1], "abcdefgh.txt") == true);
    assert(fat_name_matches_entry(&ctx, &entries[1], "nope.txt") == false);
}

/* ---- issue 2: unvalidated cluster numbers used as raw FAT indices ---- */

static struct fat_context *_make_fat16_context(int16_t *table, int32_t entries)
{
    struct fat_context *fat_ctx = calloc(1, sizeof(struct fat_context));
    fat_ctx->type = FAT_TYPE16;
    fat_ctx->fat16 = table;
    fat_ctx->fat_entries = entries;
    fat_ctx->num_clusters = entries - 2;
    return fat_ctx;
}

static void test_cluster_bounds_checked(void)
{
    /* a tiny 8-entry FAT16 table: clusters 0/1 reserved, 2..7 usable */
    int16_t table[8] = {0};
    struct fat_context *fat_ctx = _make_fat16_context(table, 8);

    table[2] = 3;
    table[3] = 0xffff; /* EOC */

    /* in-range clusters still behave correctly */
    assert(fat_next_cluster(fat_ctx, 2) == 3);
    assert(fat_cluster_is_eoc(fat_ctx, fat_next_cluster(fat_ctx, 3)));
    assert(fat_cluster_in_range(fat_ctx, 2) == true);
    assert(fat_cluster_in_range(fat_ctx, 7) == true);

    /* cluster numbers taken from a crafted/corrupt directory entry, far
     * outside the loaded fat table, must not be read/written out of bounds */
    assert(fat_cluster_in_range(fat_ctx, 1000000) == false);
    assert(fat_cluster_in_range(fat_ctx, 0) == false);
    assert(fat_cluster_in_range(fat_ctx, 1) == false);

    assert(fat_cluster_is_eoc(fat_ctx, fat_next_cluster(fat_ctx, 1000000)));
    assert(fat_cluster_is_eoc(fat_ctx, fat_set_cluster(fat_ctx, 1000000, 42)));
    assert(fat_write_fat_cluster(fat_ctx, 1000000) == -1);

    free(fat_ctx);
}

/* ---- issue 3: no cycle detection when walking FAT chains ---- */

static void _timeout_handler(int sig)
{
    (void) sig;
    /* write(2) instead of fprintf: async-signal-safe */
    const char msg[] = "TIMEOUT - infinite loop while walking a cyclic FAT chain\n";
    write(2, msg, sizeof(msg) - 1);
    _exit(1);
}

static void test_cyclic_chain_does_not_hang(void)
{
    /* FAT16 table where cluster 2 -> 3 -> 2: a cycle with no EOC marker */
    int16_t table[8] = {0};
    struct fat_context *fat_ctx = _make_fat16_context(table, 8);
    fat_ctx->bootsector.bytes_per_sector = 512;
    fat_ctx->bootsector.sectors_per_cluster = 1;
    fat_ctx->fd = -1; /* fat_dir_read's cluster-counting loop never reaches I/O
                        * when it (correctly) bails out early on the cycle */

    table[2] = 3;
    table[3] = 2;

    struct fat_dir_context dir_ctx = {0};
    dir_ctx.fat_ctx = fat_ctx;
    dir_ctx.first_cluster = 2;

    struct sigaction sa = {0};
    sa.sa_handler = _timeout_handler;
    sigaction(SIGALRM, &sa, NULL);

    alarm(5);
    ssize_t rd = fat_dir_read(&dir_ctx);
    alarm(0);

    assert(rd < 0); /* cycle detected and reported, not an infinite loop */

    /* same cycle, reached via the "find last cluster" helper used by
     * fat_dir_file_entry_extend()/fat_dir_allocate_entries() */
    alarm(5);
    int32_t last = fat_chain_last_cluster(fat_ctx, 2);
    alarm(0);
    assert(last == -1);

    free(fat_ctx);
}

/* ---- issue 4: unbounded directory-entry scan loops ---- */

static void test_dir_scan_stops_at_num_entries(void)
{
    /* every slot is a valid-looking, non-zero, non-matching entry: no NUL
     * terminator anywhere in the array (as a crafted image could produce) */
    const int32_t N = 4;
    struct fat_dir_entry *entries = calloc(N, sizeof(struct fat_dir_entry));
    struct fat_dir_context ctx = {0};
    int i;

    for (i = 0; i < N; i++) {
        memset(entries[i].name, 'A' + i, 11); /* non-zero, no LFN */
        entries[i].attr = FAT_ATTR_ARCHIVE;
    }

    ctx.entries = entries;
    ctx.num_entries = N;
    ctx.sub_dirs = calloc(N, sizeof(struct fat_dir_context *));

    /* none of these must read entries[N] or beyond */
    assert(fat_dir_find_entry_index(&ctx, "ZZZZZZZZ.ZZZ") == -1);
    assert(fat_dir_is_empty(&ctx) == false);
    assert(fat_dir_context_by_path(&ctx, "ZZZZZZZZ.ZZZ") == NULL);

    free(entries);
    free(ctx.sub_dirs);
}

/* ---- issue 5: divide-by-zero on a malformed boot sector ---- */

/* writes a minimal-but-otherwise-plausible FAT16 boot sector + extension
 * to a fresh temp file and returns its fd, positioned at offset 0 */
static int _make_boot_sector_fd(uint16_t bytes_per_sector, uint8_t sectors_per_cluster)
{
    struct fat_boot_sector bs = {0};
    struct fat_boot_sector_ext16 ext = {0};

    bs.bytes_per_sector = bytes_per_sector;
    bs.sectors_per_cluster = sectors_per_cluster;
    bs.reserved_sectors_count = 1;
    bs.num_fats = 1;
    bs.root_entry_count = 16;
    bs.total_sectors16 = 1000;
    bs.fat_size16 = 4;

    FILE *f = tmpfile();
    int fd = dup(fileno(f));
    fwrite(&bs, sizeof(bs), 1, f);
    fwrite(&ext, sizeof(ext), 1, f);
    fflush(f);
    fclose(f); /* fd survives the dup() above */
    /* big enough for init_fat_context() to pread() the (empty/zero) fat
     * table without a short read, regardless of bytes_per_sector/fat_size16 */
    ftruncate(fd, 1 << 20);
    lseek(fd, 0, SEEK_SET);
    return fd;
}

static void test_malformed_boot_sector_rejected(void)
{
    int fd = _make_boot_sector_fd(0, 4); /* bytes_per_sector == 0 */
    assert(init_fat_context(fd) == NULL);
    close(fd);

    fd = _make_boot_sector_fd(512, 0); /* sectors_per_cluster == 0 */
    assert(init_fat_context(fd) == NULL);
    close(fd);

    fd = _make_boot_sector_fd(511, 4); /* not a power of two */
    assert(init_fat_context(fd) == NULL);
    close(fd);

    /* a plausible, valid boot sector must still be accepted */
    fd = _make_boot_sector_fd(512, 4);
    struct fat_context *ctx = init_fat_context(fd);
    assert(ctx != NULL);
    free_fat_context(ctx);
    close(fd);
}

/* ---- issue 7: NULL deref in fatfuse_open() when lookup fails ---- */

static void test_open_check_rejects_missing_entry(void)
{
    struct fat_dir_entry entry = {0};
    entry.attr = FAT_ATTR_ARCHIVE;

    /* the actual bug: a NULL entry (failed lookup) must not be
     * dereferenced, regardless of the requested access mode */
    assert(fatfuse_open_check(NULL, O_RDONLY, 0) == -ENOENT);
    assert(fatfuse_open_check(NULL, O_WRONLY, 0) == -ENOENT);

    /* existing behavior for a resolved entry must be unaffected */
    assert(fatfuse_open_check(&entry, O_RDONLY, 0) == 0);
    assert(fatfuse_open_check(&entry, O_WRONLY, 0) == 0);
    assert(fatfuse_open_check(&entry, O_WRONLY, /*read_only=*/1) == -EROFS);

    entry.attr |= FAT_ATTR_READ_ONLY;
    assert(fatfuse_open_check(&entry, O_RDONLY, 0) == 0);
    assert(fatfuse_open_check(&entry, O_WRONLY, 0) == -EACCES);
}

/* ---- issue 8: no locking around shared state under multi-threaded FUSE ---- */

static int _count_dash_s(struct fuse_args *args)
{
    int i, count = 0;
    for (i = 0; i < args->argc; i++) {
        if (strcmp(args->argv[i], "-s") == 0)
            count++;
    }
    return count;
}

static void test_force_singlethreaded_adds_dash_s_once(void)
{
    struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
    fuse_opt_add_arg(&args, "vfat-fuse");
    fuse_opt_add_arg(&args, "image.img");
    fuse_opt_add_arg(&args, "/mnt");

    assert(_count_dash_s(&args) == 0);

    fatfuse_force_singlethreaded(&args);
    assert(_count_dash_s(&args) == 1);

    /* idempotent: calling again (e.g. if the user also passed -s) must
     * not add a second copy */
    fatfuse_force_singlethreaded(&args);
    assert(_count_dash_s(&args) == 1);

    fuse_opt_free_args(&args);
}

/* ---- issue 9: stale sub_dirs[] cache leaked on delete+reuse ---- */

/* a scratch fd large enough for fat_dir_write_entries()'s pwrite() to
 * always succeed, regardless of where in it we write */
static int _make_scratch_fd(void)
{
    FILE *f = tmpfile();
    int fd = dup(fileno(f));
    fclose(f);
    ftruncate(fd, 1 << 16);
    return fd;
}

static void test_delete_frees_cached_subdir(void)
{
    struct fat_dir_entry entries[2] = {0};
    struct fat_context fat_ctx = {0};
    struct fat_dir_context ctx = {0};

    fat_ctx.type = FAT_TYPE16;
    fat_ctx.bootsector.bytes_per_sector = 512;
    fat_ctx.bootsector.sectors_per_cluster = 1;
    fat_ctx.bootsector.num_fats = 1;
    fat_ctx.rootdir16_sector = 0;
    fat_ctx.fd = _make_scratch_fd();

    memcpy(entries[0].name, "SUBDIR     ", 11);
    entries[0].attr = FAT_ATTR_DIRECTORY; /* cluster 0: no chain to free */

    ctx.fat_ctx = &fat_ctx;
    ctx.entries = entries;
    ctx.num_entries = 2;
    ctx.sub_dirs = calloc(2, sizeof(struct fat_dir_context *));

    /* a cached sub-directory context for entries[0], as if it had been
     * looked up earlier via fat_dir_get_dir_context() */
    struct fat_dir_context *cached = calloc(1, sizeof(struct fat_dir_context));
    cached->entries = calloc(1, sizeof(struct fat_dir_entry));
    cached->sub_dirs = calloc(1, sizeof(struct fat_dir_context *));
    ctx.sub_dirs[0] = cached;

    int rc = fat_dir_entry_delete(&ctx, 0);
    assert(rc >= 0);
    /* the fix: the stale cache entry must be gone (freed), not just left
     * dangling for fat_dir_create_entry() to silently overwrite/leak later */
    assert(ctx.sub_dirs[0] == NULL);

    close(fat_ctx.fd);
    free(ctx.sub_dirs);
}

/* ---- issue 10: fat_time() decodes bit fields directly, no string round-trip ---- */

static void test_fat_time_decodes_date_time_bits(void)
{
    struct fat_dir_entry entry = {0};

    /* 2024-08-15, 13:45:36 (FAT time has 2-second resolution: 36/2 = 18) */
    entry.write_date = (44 << 9) | (8 << 5) | 15;
    entry.write_time = (13 << 11) | (45 << 5) | 18;

    time_t t = fat_time(&entry, FAT_DATE_WRITE);
    struct tm tm;
    localtime_r(&t, &tm);

    assert(tm.tm_year + 1900 == 2024);
    assert(tm.tm_mon + 1 == 8);
    assert(tm.tm_mday == 15);
    assert(tm.tm_hour == 13);
    assert(tm.tm_min == 45);
    assert(tm.tm_sec == 36);

    /* also cross-check against the (independently bit-decoded) pretty
     * string, so the two functions can't silently drift apart */
    char buf[20];
    fat_pretty_date(&entry, buf, sizeof(buf), FAT_DATE_WRITE);
    assert(strcmp(buf, "2024-08-15 13:45:36") == 0);
}

int main(void)
{
    RUN(test_sfn_pretty_full_8dot3_no_overflow);
    RUN(test_cluster_bounds_checked);
    RUN(test_cyclic_chain_does_not_hang);
    RUN(test_dir_scan_stops_at_num_entries);
    RUN(test_malformed_boot_sector_rejected);
    RUN(test_open_check_rejects_missing_entry);
    RUN(test_force_singlethreaded_adds_dash_s_once);
    RUN(test_delete_frees_cached_subdir);
    RUN(test_fat_time_decodes_date_time_bits);

    fprintf(stderr, "%d test(s) passed\n", tests_run);
    return 0;
}
