/*
 * Regression tests for the security findings in REVIEW.md (issues 1-5).
 *
 * Built with -fsanitize=address,undefined against fat.c (see the `test`
 * target in Makefile) so that out-of-bounds reads/writes and infinite
 * loops are caught reliably rather than by chance.
 */
#define _GNU_SOURCE

#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fat.h"

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

int main(void)
{
    RUN(test_sfn_pretty_full_8dot3_no_overflow);
    RUN(test_cluster_bounds_checked);

    fprintf(stderr, "%d test(s) passed\n", tests_run);
    return 0;
}
