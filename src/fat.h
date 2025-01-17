#include <asm/byteorder.h>
#include <stdint.h>
#include <stdbool.h>

/* on disk boot sector */

#pragma pack(push, 1)
struct fat_boot_sector {
    char jmpboot[3];
    char oem_name[8];
    __le16 bytes_per_sector;
    uint8_t sectors_per_cluster;
    __le16 reserved_sectors_count;
    uint8_t num_fats;
    __le16 root_entry_count;
    __le16 total_sectors16;
    uint8_t media;
    __le16 fat_size16;
    __le16 sectors_per_track;
    __le16 num_heads;
    __le32 hidden_sectors;
    __le32 total_sectors32;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct fat_boot_sector_ext16 {
    uint8_t drive_num;
    uint8_t reserved;
    uint8_t ext_boot_signature;
    __le32 volume_id;
    char volume_label[11];
    char file_system_type[8];
};
#pragma pack(pop)

#pragma pack(push, 1)
struct fat_boot_sector_ext32 {
    __le32 fat_size;
    __le16 ext_flags;
    uint8_t fs_version[2];
    __le32 root_cluster;
    __le16 fs_info_sector;
    __le16 backup_boot_sector;
    char reserved1[12];
    uint8_t drive_num;
    uint8_t reserved2;
    uint8_t boot_signature;
    __le32 volume_id;
    char volume_label[11];
    char file_system_type[8];
    char boot_code[420];
    __le16 boot_signature1;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct fat_dir_entry {
    char name[11];
    uint8_t attr;
    uint8_t ntres;
    uint8_t creation_time_tenth;
    __le16 creation_time;
    __le16 creation_date;
    __le16 last_access_date;
    __le16 first_cluster_high;
    __le16 write_time;
    __le16 write_date;
    __le16 first_cluster_low;
    __le32 filesize;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct fat_lfn_entry {
    uint8_t seq_number;
    uint16_t name1[5];
    uint8_t attr;
    uint8_t type;
    uint8_t checksum;
    uint16_t name2[6];
    __le16 first_cluster_low;
    uint16_t name3[2];
};
#pragma pack(pop)

#pragma pack(push, 1)
struct fat_fsinfo {
    __le32 lead_sig; /* 0x41615252 */
    uint8_t reserved1[480];
    __le32 struc_sig; /* 0x61417272 */
    __le32 free_count;
    __le32 next_free;
    uint8_t reserved2[12];
    __le32 trail_sig; /* 0xAA550000 */
};
#pragma pack(pop)

#define FAT_TYPE12 1
#define FAT_TYPE16 2
#define FAT_TYPE32 3

#define FAT_ATTR_READ_ONLY 0x01
#define FAT_ATTR_HIDDEN 0x02
#define FAT_ATTR_SYSTEM 0x04
#define FAT_ATTR_VOLUME_ID 0x08
#define FAT_ATTR_DIRECTORY 0x10
#define FAT_ATTR_ARCHIVE 0x20
#define FAT_ATTR_LONG_FILE_NAME 0x0F

#define FAT_DATE_WRITE 1
#define FAT_DATE_CREATION 2
#define FAT_DATE_ACCESS 3

#define FAT_LFN_LAST_LONG_ENTRY 0x40
#define FAT_LFN_SEQ_MASK 0x3f

struct fat_context {
    struct fat_boot_sector bootsector;
    union {
       struct fat_boot_sector_ext16 ext16;
       struct fat_boot_sector_ext32 ext32;
    } bootsector_ext;

    /* FAT32 only */
    struct fat_fsinfo *fs_info;

    int type;
    int fd;

    union {
        int32_t *fat32;
        int16_t *fat16;
        uint8_t *fat12;
    };

    int64_t rootdir16_sector;
    int64_t data_start_sector;
    int32_t num_clusters;
};

struct fat_dir_context {
    struct fat_context *fat_ctx;
    struct fat_dir_context *ctx_parent;
    int32_t first_cluster;
    int32_t num_entries;
    struct fat_dir_entry *entries;
    struct fat_dir_context **sub_dirs;
};

struct fat_file_context {
    struct fat_context *fat_ctx;
    size_t size;
    off_t current_pos;
    int32_t current_cluster;
};

struct fat_context *init_fat_context(int fd);
void free_fat_context(struct fat_context *ctx);
int32_t fat_free_cluster_count(struct fat_context *fat_ctx);

uint32_t fat_first_cluster(struct fat_context *fat_ctx);
uint32_t fat_next_cluster(struct fat_context *fat_ctx, uint32_t cluster);
bool fat_cluster_is_eoc(struct fat_context *fat_ctx, uint32_t cluster);

struct fat_file_context *init_fat_file_context(struct fat_context *fat_ctx, int32_t first_cluster, size_t size);
void free_fat_file_context(struct fat_file_context *ctx);

int64_t fat_get_sector_from_cluster(struct fat_context *fat_ctx, uint32_t cluster);

struct fat_file_context *init_fat_file_context(struct fat_context *fat_ctx, int32_t first_cluster, size_t size);
ssize_t fat_file_pread(struct fat_context *fat_ctx, struct fat_dir_entry *entry, void *buf, off_t pos, size_t len);
ssize_t fat_file_pwrite(struct fat_dir_context *dir_ctx, int index, const void *buf, off_t pos, size_t len);
ssize_t fat_dir_write_entries(struct fat_dir_context *dir_ctx, int index, int count);

struct fat_dir_context *init_fat_dir_context(struct fat_context *fat_ctx, struct fat_dir_context *ctx_parent, int index);
struct fat_dir_context *init_fat_dir_context_root(struct fat_context *fat_ctx);
void free_fat_dir_context(struct fat_dir_context *ctx);
ssize_t fat_dir_read(struct fat_dir_context *ctx);

uint32_t fat_dir_entry_get_cluster(struct fat_dir_entry *entry);
    
int fat_dir_find_entry_index(struct fat_dir_context *ctx, const char * name);
struct fat_dir_entry *fat_dir_find_entry(struct fat_dir_context *ctx, const char *name);
struct fat_dir_context *fat_dir_get_dir_context(struct fat_dir_context *ctx, int index);
struct fat_dir_context *fat_dir_find_dir_context(struct fat_dir_context *ctx, const char *name);

struct fat_dir_context *fat_dir_context_by_path(struct fat_dir_context *ctx, const char *path);

bool fat_entry_is_valid(struct fat_dir_entry *entry);
const char *fat_file_sfn_pretty(struct fat_dir_entry *entry, char buf[]);
wchar_t *fat_file_lfn(struct fat_dir_context *ctx, struct fat_dir_entry *entry, wchar_t buf[], size_t buf_size);
const char *fat_pretty_date(struct fat_dir_entry *entry, char buf[], size_t buf_size, int type);
time_t fat_time(struct fat_dir_entry *entry, int type);
void fat_time_to_fat(time_t t, __le16 *pdate, __le16 *ptime);

wchar_t *str_to_wstr(const char *str, wchar_t *wbuf);
char *wstr_to_str(const wchar_t *wstr, char *buf);
char *fat_dir_get_entry_name(struct fat_dir_context *ctx, struct fat_dir_entry *entry, char *buf);

bool fat_dir_is_empty(struct fat_dir_context *dir_ctx);
int far_dir_entry_delete(struct fat_dir_context *dir_ctx, int index);

int fat_dir_create_entry(struct fat_dir_context *dir_ctx, const char *name, int attr);
int far_dir_entry_rename(struct fat_dir_context *dir_ctx, int index, const char *name);
int fat_dir_entry_move(struct fat_dir_context *dir_ctx, int index, struct fat_dir_context *dir_ctx_dest, const char *name);
int far_dir_entry_set_attr(struct fat_dir_context *dir_ctx, int index, uint8_t attr);
