#Zakeriya Muhumed Lab3


typedef struct viktar_header_s {
    char viktar_name[VIKTAR_MAX_FILE_NAME_LEN];    // Member file name, usually NULL terminated.
    off_t st_size; // Total size, in bytes
    mode_t st_mode; // File type and mode
    uid_t st_uid; // User ID of owner
    gid_t st_gid; // Group ID of owner
    struct timespec st_atim; // Time of last access
    struct timespec st_mtim; // Time of last modification
} viktar_header_t;
