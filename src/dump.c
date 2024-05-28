#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <unistd.h>
#include <wctype.h>
#include <wchar.h>

#include "fat.h"

void dump_boot_sector(struct fat_boot_sector *bs)
{
    char oem_name[9];
    int i;

    printf("jmpboot = ");
    for(i = 0; i < 3; i++){
        printf("%1x", (int)bs->jmpboot[i]);
    }
    printf("\n");

    strncpy(oem_name, bs->oem_name, 8);
    oem_name[8] = 0;
    printf("oem_name = %s\n", oem_name);

    printf("bytes_per_sector = %d\n", (int)bs->bytes_per_sector);
    printf("sectors_per_cluster = %d\n", (int)bs->sectors_per_cluster);
    printf("reserved_sectors_count = %d\n", (int)bs->reserved_sectors_count);
    printf("num_fats = %d\n", (int)bs->num_fats);
    printf("root_entry_count = %d\n", (int)bs->root_entry_count);
    printf("total_sectors16 = %d\n", (int)bs->total_sectors16);
    printf("media = %1x\n", (int)bs->media);
    printf("fat_size16 = %d\n", (int)bs->fat_size16);
    printf("sectors_per_track = %d\n", (int)bs->sectors_per_track);
    printf("num_heads = %d\n", (int)bs->num_heads);
    printf("hidden_sectors = %d\n", (int)bs->hidden_sectors);
    printf("total_sectors32 = %d\n", (int)bs->total_sectors32);
}

void dump_boot_sector_ext16(struct fat_boot_sector_ext16 *bs)
{
    char volume_label[12];
    char file_system_type[9];

    printf("drive_num = %d\n", (int)bs->drive_num);
    printf("ext_boot_signature = %d\n", (int)bs->ext_boot_signature);
    printf("volume_id = %8x\n", bs->volume_id);

    strncpy(volume_label, bs->volume_label, 11);
    volume_label[11] = 0;
    printf("volume_label = %s\n", volume_label);

    strncpy(file_system_type, bs->file_system_type, 8);
    file_system_type[8] = 0;
    printf("file_system_type = %s\n", file_system_type);
}

void dump_boot_sector_ext32(struct fat_boot_sector_ext32 *bs)
{
    char volume_label[12];
    char file_system_type[9];

    printf("fat_size = %d\n", (int)bs->fat_size);
    printf("ext_flags = %2x\n", (int)bs->ext_flags);
    printf("fs_version = %d.%d\n", (int)bs->fs_version[1], (int)bs->fs_version[0]);
    printf("root_cluster = %d\n", (int)bs->root_cluster);
    printf("fs_info_sector = %d\n", (int)bs->fs_info_sector);
    printf("backup_boot_sector = %d\n", (int)bs->backup_boot_sector);
    printf("drive_num = %d\n", (int)bs->drive_num);
    printf("boot_signature = %x\n", (int)bs->boot_signature);
    printf("volume_id = %x\n", (int)bs->volume_id);

    strncpy(volume_label, bs->volume_label, 11);
    volume_label[11] = 0;
    printf("volume_label = %s\n", volume_label);

    strncpy(file_system_type, bs->file_system_type, 8);
    file_system_type[8] = 0;
    printf("file_system_type = %s\n", file_system_type);

    printf("boot_signature = %2x\n", (int)bs->boot_signature);
}

void dump_info(struct fat_context *fat_ctx)
{
    dump_boot_sector(&fat_ctx->bootsector);

    printf("\ntype is %s\n", fat_ctx->type == FAT_TYPE32 ? "FAT32" : "FAT16/12");
    printf("num_clusters = %d\n", fat_ctx->num_clusters);
    printf("free clusters = %d\n", fat_free_cluster_count(fat_ctx));

    printf("\n");

    if (fat_ctx->type == FAT_TYPE32)
        dump_boot_sector_ext32(&fat_ctx->bootsector_ext.ext32);
    else
        dump_boot_sector_ext16(&fat_ctx->bootsector_ext.ext16);
    printf("\n");

    printf("data start sector: %ld (pos = %ld/0x%lx)\n",
        fat_ctx->data_start_sector,
        fat_ctx->data_start_sector * fat_ctx->bootsector.bytes_per_sector,
        fat_ctx->data_start_sector * fat_ctx->bootsector.bytes_per_sector);
    printf("root dir sector: %ld (pos = %ld/0x%lx)\n",
        fat_ctx->rootdir16_sector,
        fat_ctx->rootdir16_sector * fat_ctx->bootsector.bytes_per_sector,
        fat_ctx->rootdir16_sector * fat_ctx->bootsector.bytes_per_sector);
}

void dump_dir_entry(struct fat_dir_entry *entry)
{
    if (entry->attr != FAT_ATTR_LONG_FILE_NAME) {
        char name[12];
        strncpy(name, entry->name, 11);
        name[11] = 0;
        printf("name[0] = %x\n", name[0]);
        printf("name = %s\n", name);
        printf("attr = %x\n", entry->attr);
        printf("ntres = %x\n", entry->ntres);
        printf("creation_time_tenth = %d\n", (int)entry->creation_time_tenth);
        printf("creation_time = %d\n", (int)entry->creation_time);
        printf("creation_date = %d\n", (int)entry->creation_date);
        printf("last_access_date = %d\n", (int)entry->last_access_date);
        printf("first_cluster_high = %d\n", (int)entry->first_cluster_high);
        printf("first_cluster_low = %d\n", (int)entry->first_cluster_low);
        int first_cluster = ((int)entry->first_cluster_high << 16) + (int)entry->first_cluster_low;
        printf("first_cluster = %d\n", first_cluster);
        printf("write_time = %d\n", (int)entry->write_time);
        printf("write_date = %d\n", (int)entry->write_date);
        printf("filesize = %d\n", (int)entry->filesize);
        printf("\n");
    } else {
        struct fat_lfn_entry *lfn_entry = (struct fat_lfn_entry *)entry;
        printf("lfn\n");
        printf("seq_number = %x\n", lfn_entry->seq_number);
        printf("attr = %x\n", lfn_entry->attr);
        printf("\n");
    }
}

void dump_dir(struct fat_dir_entry *entries)
{
    int i;

    for(i = 0; entries[i].name[0]; i++) {
        dump_dir_entry(&entries[i]);
    }
}

void print_dir_entry(struct fat_dir_context *dir_ctx, struct fat_dir_entry *entry)
{
    char date[20];
    char name[256];

    fat_pretty_date(entry, date, sizeof(date), FAT_DATE_WRITE);
    fat_dir_get_entry_name(dir_ctx, entry, name);
    if (entry->attr & FAT_ATTR_DIRECTORY)
        printf("%-12s <dir>      %s\n", date, name);
    else
        printf("%-12s %10d %s\n", date, entry->filesize, name);
}

void list_dir(struct fat_dir_context *dir_ctx)
{
    int i;

    if (!dir_ctx->entries)
        fat_dir_read(dir_ctx);

    for(i = 0; dir_ctx->entries[i].name[0]; i++) {
        if (fat_entry_is_valid(&dir_ctx->entries[i])) {
            print_dir_entry(dir_ctx, &dir_ctx->entries[i]);
        }
    }
}

void print_attr(struct fat_dir_context *dir_ctx, struct fat_dir_entry *entry)
{
    char sfn_pretty[12];
    fat_file_sfn_pretty(entry, sfn_pretty);
    printf("     sfn: %s\n", sfn_pretty);

    wchar_t lfn[256];
    if (fat_file_lfn(dir_ctx, entry, lfn, 256)) {
        printf("     lfn: %ls\n", lfn);
    } else
        printf("     lfn: (none)\n");

    printf("    size: %d\n", entry->filesize);
    printf("    attr: %s %s %s %s %s\n",
        entry->attr & FAT_ATTR_READ_ONLY ? "ro" : "rw",
        entry->attr & FAT_ATTR_HIDDEN ? "hidden" : "not-hidden",
        entry->attr & FAT_ATTR_SYSTEM ? "system" : "not-system",
        entry->attr & FAT_ATTR_DIRECTORY ? "directory" : "file",
        entry->attr & FAT_ATTR_ARCHIVE ? "archived" : "not-archived"
    );

    char date[20];
    printf("  access: %s\n", fat_pretty_date(entry, date, sizeof(date), FAT_DATE_ACCESS));
    printf("   write: %s\n", fat_pretty_date(entry, date, sizeof(date), FAT_DATE_WRITE));
    printf("creation: %s\n", fat_pretty_date(entry, date, sizeof(date), FAT_DATE_CREATION));
    printf(" cluster: %d\n", fat_dir_entry_get_cluster(entry));
}

int main(int argc, char *argv[])
{
    int fd;
    char *op, *filename;
    struct fat_context *fat_ctx;

    if (argc <= 1) {
        fprintf(stderr, "no operation given\n");
        exit(1);
    }

    if (argc <= 2) {
        fprintf(stderr, "no image file given\n");
        exit(1);
    }

    op = argv[1];
    filename = argv[2];

    fd = open(filename, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "could not open image file %s (%d)\n", strerror(errno), errno);
        exit(1);
    }

    fat_ctx = init_fat_context(fd);
    if (fat_ctx == NULL) {
        fprintf(stderr, "initializing fat context failed.\n");
        exit(1);
    }

    if (strcmp(op, "info") == 0) {
        dump_info(fat_ctx);
    } else if (strcmp(op, "rootdir") == 0) {
        struct fat_dir_context *dir_ctx_root = init_fat_dir_context_root(fat_ctx);
        dump_dir(dir_ctx_root->entries);
    } else if (strcmp(op, "list") == 0 || strcmp(op, "cat") == 0 || strcmp(op, "attr") == 0){
        if (argc <= 3) {
            fprintf(stderr, "no path file given for %s\n", op);
            exit(1);
        }
        const char *path = argv[3];

        char path_copy[strlen(path) + 1];
        char path_copy1[strlen(path) + 1];

        strcpy(path_copy, path);
        strcpy(path_copy1, path);

        char *base_name = basename(path_copy);
        char *dir_name = dirname(path_copy1);

        struct fat_dir_context *dir_ctx_root = init_fat_dir_context_root(fat_ctx);

        if (strcmp(base_name, ".") == 0 && strcmp(op, "list") == 0) {
            list_dir(dir_ctx_root);
        } else {
            struct fat_dir_context *dir_ctx = fat_dir_context_by_path(dir_ctx_root, dir_name);

            if (dir_ctx) {
                int index = fat_dir_find_entry_index(dir_ctx, base_name);

                if (index >= 0) {
                    struct fat_dir_entry *entry = &dir_ctx->entries[index];
                    if (strcmp(op, "list") == 0) {
                        if (path[strlen(path)-1] == '/') {
                            if (entry->attr != FAT_ATTR_DIRECTORY) {
                                fprintf(stderr, "%s is not a directory\n", path);
                            }
                            struct fat_dir_context *subdir_ctx = fat_dir_find_dir_context(dir_ctx, base_name);
                            if (subdir_ctx) {
                                list_dir(subdir_ctx);
                            }
                        } else
                            print_dir_entry(dir_ctx, entry);
                    } else if (strcmp(op, "cat") == 0) {
                        struct fat_file_context *file_ctx = init_fat_file_context(fat_ctx, fat_dir_entry_get_cluster(entry), entry->filesize);
                        int rd;
                        char buf[333];
                        off_t pos = 0;
                        while ((rd = fat_file_pread(fat_ctx, entry, buf, pos, sizeof(buf))) > 0) {
                            if (write(1, buf, rd) != rd) {
                                fprintf(stderr, "failed to write to stdout: %s (%d)", strerror(errno), errno);
                            }
                            pos += rd;
                        }
                        free_fat_file_context(file_ctx);
                    } else if (strcmp(op, "attr") == 0) {
                        print_attr(dir_ctx, entry);
                    }
                } else {
                    fprintf(stderr, "%s not found\n", base_name);
                }
            } else
                fprintf(stderr, "%s not found\n", path);
        }
        free_fat_dir_context(dir_ctx_root);
    }
    free_fat_context(fat_ctx);
}
