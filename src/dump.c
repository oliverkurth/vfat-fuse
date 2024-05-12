#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
    }  
}

void print_dir_entry(struct fat_dir_entry *entry)
{
    char sfn_pretty[12], date[20];
    fat_file_sfn_pretty(entry, sfn_pretty);
    fat_pretty_date(entry, date, sizeof(date), FAT_DATE_WRITE);
    if (entry->attr & FAT_ATTR_DIRECTORY)
        printf("%-12s %s <dir>\n", sfn_pretty, date);
    else
        printf("%-12s %s %d\n", sfn_pretty, date, entry->filesize);
}

void dump_dir(struct fat_dir_entry *entries)
{
    int i;

    for(i = 0; entries[i].name[0]; i++) {
        if (entries[i].attr != FAT_ATTR_LONG_FILE_NAME) {
            dump_dir_entry(&entries[i]);
        }
    }
}

int main(int argc, char *argv[])
{
    int fd;
    char *op, *filename, *path;
    struct fat_context *fat_ctx;
    int i;

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
    fat_ctx = init_fat_context(fd);

    if (strcmp(op, "list") == 0 || strcmp(op, "cat") == 0) {
        if (argc <= 3) {
            fprintf(stderr, "no path file given for 'list'\n");
            exit(1);
        }
        const char *path = argv[3];

        struct fat_dir_context *dir_ctx = init_fat_dir_context(fat_ctx, fat_ctx->bootsector_ext.ext32.root_cluster);
        fat_dir_read(dir_ctx);

        struct fat_dir_entry *entry = fat_dir_entry_by_path(dir_ctx, path);

        if (entry) {
            if (strcmp(op, "list") == 0) {
                print_dir_entry(entry);
            } else if (strcmp(op, "cat") == 0) {
                struct fat_file_context *file_ctx = init_fat_file_context(fat_ctx, fat_dir_entry_get_cluster(entry), entry->filesize);
                int rd;
                char buf[333];
                while ((rd = fat_file_read(file_ctx, buf, sizeof(buf))) > 0) {
                    write(1, buf, rd);
                }
            }
        }
        else
            printf("%s not found\n", path);
        free_fat_dir_context(dir_ctx);
    }
    free_fat_context(fat_ctx);
}
