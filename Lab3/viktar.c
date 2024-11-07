//Zakeriya Muhumed Viktar Lab
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <pwd.h>
#include <grp.h>
#include <stdint.h>
#include <openssl/md5.h>
#include <openssl/evp.h> 

#include "viktar.h"

// Global
int is_verbose = FALSE;
viktar_action_t user_action = ACTION_NONE;
char *archive_filename = NULL;

// Function 
void display_help(void);
void parse_arguments(int argc, char *argv[]);
int check_archive_validity(int fd);
void build_archive(char *archive_name, char **files, int file_count);
void decompress_files(char *archive_name, char **files, int file_count);
void show_table_of_contents(char *archive_name, int long_format);
void verify_content(char *archive_name);
void compute_md5_checksum(void *data, size_t size, uint8_t *digest);
void display_permissions(mode_t mode);
char *format_timestamp(struct timespec ts);

int main(int argc, char *argv[]) {
    parse_arguments(argc, argv);
    
    switch (user_action) {
        case ACTION_CREATE:
            build_archive(archive_filename, argv + optind, argc - optind);
            break;
                
        case ACTION_EXTRACT:
            decompress_files(archive_filename, argv + optind, argc - optind);
            break;
                
        case ACTION_TOC_SHORT:
            show_table_of_contents(archive_filename, FALSE);
            break;
                
        case ACTION_TOC_LONG:
            show_table_of_contents(archive_filename, TRUE);
            break;
                
        case ACTION_VALIDATE:
            verify_content(archive_filename);
            break;
                
        case ACTION_NONE:
            fprintf(stderr, "No action specified\n");
            display_help();
            exit(1);
    }
    
    return 0;
}

void parse_arguments(int argc, char *argv[]) {
    int opt;
        
    while ((opt = getopt(argc, argv, OPTIONS)) != -1) {
        switch (opt) {
            case 'v':
                is_verbose = TRUE;
                if (is_verbose) {
                    fprintf(stderr, "Verbose mode enabled\n");
                }
                break;
                    
            case 'h':
                display_help();
                exit(0);
                    
            case 'f':
                archive_filename = optarg;
                break;
                    
            case 'x':
                user_action = ACTION_EXTRACT;
                break;
                    
            case 'c':
                user_action = ACTION_CREATE;
                break;
                    
            case 't':
                user_action = ACTION_TOC_SHORT;
                break;
                    
            case 'T':
                user_action = ACTION_TOC_LONG;
                break;
                    
            case 'V':
                user_action = ACTION_VALIDATE;
                break;
                    
            default:
                fprintf(stderr, "Unknown option: %c\n", opt);
                display_help();
                exit(1);
        }
    }
}

void display_help(void) {
  printf("help text\n");
  printf("    ./viktar\n");
  printf("    Options: xctTf:Vhv\n");
  printf("        -x        extract file/files from archive\n");
  printf("        -c        create an archive file\n");
  printf("        -t        display a short table of contents of the archive file\n");
  printf("        -T        display a long table of contents of the archive file\n");
  printf("        Only one of xctTV can be specified\n");
  printf("        -f filename    use filename as the archive file\n");
  printf("        -v        give verbose diagnostic messages\n");
  printf("        -h        display this AMAZING help message\n");
  exit(EXIT_SUCCESS);
}

int check_archive_validity(int fd) {
    char tag_buffer[strlen(VIKTAR_TAG) + 1]; 
    ssize_t num_bytes_read;


    off_t original_pos = lseek(fd, 0, SEEK_CUR);
    
    lseek(fd, 0, SEEK_SET);
    num_bytes_read = read(fd, tag_buffer, strlen(VIKTAR_TAG));
    tag_buffer[strlen(VIKTAR_TAG)] = '\0';
    if (num_bytes_read != strlen(VIKTAR_TAG)) {
        if (is_verbose) {
            fprintf(stderr, "reading archive from stdin\n");
            fprintf(stderr, "not a viktar file: \"stdin\"\n");
        }
        return FALSE;
    }
    
    if (strncmp(tag_buffer, VIKTAR_TAG, strlen(VIKTAR_TAG)) != 0) {
        if (is_verbose) {
            if (isatty(fd)) {
                fprintf(stderr, "not a viktar file: \"stdin\"\n");
            } else {
                fprintf(stderr, "not a viktar file: \"%s\"\n", "stdin");
            }
        }
        return FALSE;
    }

    lseek(fd, original_pos + strlen(VIKTAR_TAG), SEEK_SET);
    
    return TRUE;
}

void compute_md5_checksum(void *data, size_t size, uint8_t *digest) {
    EVP_MD_CTX *md_context;
    unsigned int digest_length;

    md_context = EVP_MD_CTX_new();
    EVP_DigestInit_ex(md_context, EVP_md5(), NULL);
    EVP_DigestUpdate(md_context, data, size);
    EVP_DigestFinal_ex(md_context, digest, &digest_length);
    EVP_MD_CTX_free(md_context);
}

void build_archive(char *archive_name, char **files, int file_count) {
    int archive_fd;
    mode_t file_mode = 0644; 
    int idx;
    struct stat file_stat;
    viktar_header_t archive_header;
    viktar_footer_t archive_footer;
    int file_fd;
    char *file_buffer;
    ssize_t read_bytes, written_bytes;
        
    if (archive_name == NULL) {
        archive_fd = STDOUT_FILENO;
    } else {
        archive_fd = open(archive_name, O_WRONLY | O_CREAT | O_TRUNC, file_mode);
        if (archive_fd < 0) {
            perror("Error creating archive");
            exit(1);
        }
    	fchmod(archive_fd, file_mode);
    }
        
    if (write(archive_fd, VIKTAR_TAG, strlen(VIKTAR_TAG)) != strlen(VIKTAR_TAG)) {
        perror("Error writing archive tag");
        exit(1);
    }
        
    for (idx = 0; idx < file_count; idx++) {
        if (stat(files[idx], &file_stat) < 0) {
            perror("Error getting file stats");
            continue;
        }
            
        memset(&archive_header, 0, sizeof(archive_header));
        strncpy(archive_header.viktar_name, files[idx], VIKTAR_MAX_FILE_NAME_LEN);
        if (is_verbose && strlen(files[idx]) >= VIKTAR_MAX_FILE_NAME_LEN) {
            fprintf(stderr, "Filename '%s' truncated to '%s'\n", files[idx], archive_header.viktar_name);
        }
            
        archive_header.st_size = file_stat.st_size;
        archive_header.st_mode = file_stat.st_mode;
        archive_header.st_uid = file_stat.st_uid;
        archive_header.st_gid = file_stat.st_gid;
        archive_header.st_atim = file_stat.st_atim;
        archive_header.st_mtim = file_stat.st_mtim;
            
        compute_md5_checksum(&archive_header, sizeof(archive_header), archive_footer.md5sum_header);
            
        if (write(archive_fd, &archive_header, sizeof(archive_header)) != sizeof(archive_header)) {
            perror("Error writing header");
            exit(1);
        }
            
        file_fd = open(files[idx], O_RDONLY);
        if (file_fd < 0) {
            perror("Error opening input file");
            continue;
        }
            
        file_buffer = malloc(file_stat.st_size);
        if (file_buffer == NULL) {
            perror("Memory allocation failed");
            close(file_fd);
            continue;
        }
            
        read_bytes = read(file_fd, file_buffer, file_stat.st_size);
        if (read_bytes == file_stat.st_size) {
            compute_md5_checksum(file_buffer, file_stat.st_size, archive_footer.md5sum_data);
                
            written_bytes = write(archive_fd, file_buffer, file_stat.st_size);
            if (written_bytes != file_stat.st_size) {
                perror("Error writing file content");
                free(file_buffer);
                close(file_fd);
                exit(1);
            }
                
            if (write(archive_fd, &archive_footer, sizeof(archive_footer)) != sizeof(archive_footer)) {
                perror("Error writing footer");
                free(file_buffer);
                close(file_fd);
                exit(1);
            }
        }
            
        free(file_buffer);
        close(file_fd);
    }
        
    if (archive_fd != STDOUT_FILENO) {
        close(archive_fd);
    }
}

void display_permissions(mode_t mode) {
    printf("%c%c%c%c%c%c%c%c%c",
           (mode & S_IRUSR) ? 'r' : '-',
           (mode & S_IWUSR) ? 'w' : '-',
           (mode & S_IXUSR) ? 'x' : '-',
           (mode & S_IRGRP) ? 'r' : '-',
           (mode & S_IWGRP) ? 'w' : '-',
           (mode & S_IXGRP) ? 'x' : '-',
           (mode & S_IROTH) ? 'r' : '-',
           (mode & S_IWOTH) ? 'w' : '-',
           (mode & S_IXOTH) ? 'x' : '-');
}

char *format_timestamp(struct timespec ts) {
    static char buffer[64];
    struct tm *tm_info;
        
    tm_info = localtime(&ts.tv_sec);
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S %Z", tm_info);
    return buffer;
}

void decompress_files(char *archive_name, char **files, int file_count) {
    int fd;
    viktar_header_t archive_header;
    viktar_footer_t archive_footer;
    uint8_t calc_md5_header[MD5_DIGEST_LENGTH];
    uint8_t calc_md5_data[MD5_DIGEST_LENGTH];
    char *file_buffer;
    int extract;
    int out_fd;
    struct timespec times[2];
    int i;
        
    if (archive_name == NULL) {
        fd = STDIN_FILENO;
        if (is_verbose) {
            fprintf(stderr, "reading archive from stdin\n");
        }
    } else {
        fd = open(archive_name, O_RDONLY);
        if (fd < 0) {
            perror("Error opening archive");
            exit(1);
        }
    }
        
    if (!check_archive_validity(fd)) {
        fprintf(stderr, "not a viktar file: \"%s\"\n", 
                archive_name ? archive_name : "stdin");
        exit(1);
    }
    if (!archive_name) {
        fprintf(stderr, "reading archive from stdin\n");
    }
    while (read(fd, &archive_header, sizeof(archive_header)) == sizeof(archive_header)) {
        extract = file_count == 0; 

        for (i = 0; i < file_count && !extract; i++) {
            if (strncmp(archive_header.viktar_name, files[i], VIKTAR_MAX_FILE_NAME_LEN) == 0) {
                extract = 1;
            }
        }
            
        file_buffer = malloc(archive_header.st_size);
        if (file_buffer == NULL) {
            perror("Memory allocation failed");
            exit(1);
        }
            

        if (read(fd, file_buffer, archive_header.st_size) != archive_header.st_size) {
            perror("Error reading archive content");
            free(file_buffer);
            continue;
        }
            

        if (read(fd, &archive_footer, sizeof(archive_footer)) != sizeof(archive_footer)) {
            perror("Error reading archive footer");
            free(file_buffer);
            continue;
        }

        if (extract) {
            compute_md5_checksum(&archive_header, sizeof(archive_header), calc_md5_header);
            compute_md5_checksum(file_buffer, archive_header.st_size, calc_md5_data);


            if (memcmp(calc_md5_header, archive_footer.md5sum_header, MD5_DIGEST_LENGTH) != 0) {
            }

            if (memcmp(calc_md5_data, archive_footer.md5sum_data, MD5_DIGEST_LENGTH) != 0) {
            }
                
            out_fd = open(archive_header.viktar_name, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (out_fd < 0) {
                perror("Error creating output file");
                free(file_buffer);
                continue;
            }
                
            if (fchmod(out_fd, archive_header.st_mode) < 0) {
                perror("Error setting file permissions");
            }
                
            if (write(out_fd, file_buffer, archive_header.st_size) != archive_header.st_size) {
                perror("Error writing output file");
                close(out_fd);
                free(file_buffer);
                continue;
            }
                
            times[0] = archive_header.st_atim;
            times[1] = archive_header.st_mtim;
            if (futimens(out_fd, times) < 0) {
                perror("Error setting file times");
            }
                
            close(out_fd);
                
            if (is_verbose) {
                fprintf(stderr, "Extracted: %s\n", archive_header.viktar_name);
            }
        } else {
            if (is_verbose) {
                fprintf(stderr, "Skipping: %s\n", archive_header.viktar_name);
            }
        }
            
        free(file_buffer);
    }
        
    if (fd != STDIN_FILENO) {
        close(fd);
    }
}

void show_table_of_contents(char *archive_name, int long_format) {
    int fd;
    viktar_header_t archive_header;
    viktar_footer_t archive_footer;
    struct passwd *pw;
    struct group *gr;
    char mode_str[11];
    int i;
        
    if (archive_name == NULL) {
        fd = STDIN_FILENO;
    } else {
        fd = open(archive_name, O_RDONLY);
        if (fd < 0) {
            perror("Error opening archive");
            exit(1);
        }
    }

    if (!check_archive_validity(fd)) {
        if (archive_name) {
            fprintf(stderr, "reading archive file: \"%s\"\n", archive_name ? archive_name : "stdin");
        } else {
            fprintf(stderr, "reading archive from stdin\n");
        }
        fprintf(stderr, "not a viktar file: \"%s\"\n", archive_name ? archive_name : "stdin");
        exit(1);
    }

    printf("Contents of viktar file: %s\n", archive_name ? archive_name : "stdin");
        
    while (read(fd, &archive_header, sizeof(archive_header)) == sizeof(archive_header)) {
        printf("\tfile name: %s\n", archive_header.viktar_name);
              
        if (long_format) {
            mode_str[0] = S_ISDIR(archive_header.st_mode) ? 'd' : '-';
            mode_str[1] = (archive_header.st_mode & S_IRUSR) ? 'r' : '-';
            mode_str[2] = (archive_header.st_mode & S_IWUSR) ? 'w' : '-';
            mode_str[3] = (archive_header.st_mode & S_IXUSR) ? 'x' : '-';
            mode_str[4] = (archive_header.st_mode & S_IRGRP) ? 'r' : '-';
            mode_str[5] = (archive_header.st_mode & S_IWGRP) ? 'w' : '-';
            mode_str[6] = (archive_header.st_mode & S_IXGRP) ? 'x' : '-';
            mode_str[7] = (archive_header.st_mode & S_IROTH) ? 'r' : '-';
            mode_str[8] = (archive_header.st_mode & S_IWOTH) ? 'w' : '-';
            mode_str[9] = (archive_header.st_mode & S_IXOTH) ? 'x' : '-';
            mode_str[10] = '\0';

            pw = getpwuid(archive_header.st_uid);
            gr = getgrgid(archive_header.st_gid);
                
            printf("\t\tmode:           %s\n", mode_str);
            printf("\t\tuser:           %s\n", pw ? pw->pw_name : "unknown");
            printf("\t\tgroup:          %s\n", gr ? gr->gr_name : "unknown");
            printf("\t\tsize:           %lld\n", (long long)archive_header.st_size);
            printf("\t\tmtime:          %s\n", format_timestamp(archive_header.st_mtim));
            printf("\t\tatime:          %s\n", format_timestamp(archive_header.st_atim));

            lseek(fd, archive_header.st_size, SEEK_CUR);
            if (read(fd, &archive_footer, sizeof(archive_footer)) == sizeof(archive_footer)) {
                printf("\t\tmd5 sum header: ");
                for (i = 0; i < MD5_DIGEST_LENGTH; i++) {
                    printf("%02x", archive_footer.md5sum_header[i]);
                }
                printf("\n\t\tmd5 sum data:   ");
                for (i = 0; i < MD5_DIGEST_LENGTH; i++) {
                    printf("%02x", archive_footer.md5sum_data[i]);
                }
                printf("\n");
            }
            continue; 
        }
            
        lseek(fd, archive_header.st_size + sizeof(viktar_footer_t), SEEK_CUR);
    }
        
    if (fd != STDIN_FILENO) {
        close(fd);
    }
}

void verify_content(char *archive_name) {
    int fd;
    viktar_header_t archive_header;
    viktar_footer_t archive_footer;
    uint8_t calc_md5[MD5_DIGEST_LENGTH];
    int member_count = 0;
    char *file_buffer;
    int validation_failed;
        
    if (archive_name == NULL) {
        fd = STDIN_FILENO;
    } else {
        fd = open(archive_name, O_RDONLY);
        if (fd < 0) {
            perror("Error opening archive");
            exit(1);
        }
    }
        
    if (!check_archive_validity(fd)) {
        fprintf(stderr, "not a viktar file: \"%s\"\n", 
                archive_name ? archive_name : "stdin");
        exit(1);
    }
        
    while (read(fd, &archive_header, sizeof(archive_header)) == sizeof(archive_header)) {
        validation_failed = FALSE;
        member_count++;
        printf("Validation for data member %d:\n", member_count);
            
        file_buffer = malloc(archive_header.st_size);
        if (file_buffer == NULL) {
            perror("Memory allocation failed");
            exit(1);
        }
            

        if (read(fd, file_buffer, archive_header.st_size) != archive_header.st_size) {
            perror("Error reading archive content");
            free(file_buffer);
            continue;
        }
            

        if (read(fd, &archive_footer, sizeof(archive_footer)) != sizeof(archive_footer)) {
            perror("Error reading archive footer");
            free(file_buffer);
            continue;
        }

        compute_md5_checksum(&archive_header, sizeof(archive_header), calc_md5);
        if (memcmp(calc_md5, archive_footer.md5sum_header, MD5_DIGEST_LENGTH) == 0) {
            printf("\tHeader MD5 does match:\n");
        } else {
            validation_failed = TRUE;
            printf("\t*** Header MD5 does not match:\n");
        }
        printf("\t\tfound: ");
        for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
            printf("%02x", calc_md5[i]);
        }
        printf("\n\t\tin file: ");
        for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
            printf("%02x", archive_footer.md5sum_header[i]);
        }
        printf("\n");
            
        compute_md5_checksum(file_buffer, archive_header.st_size, calc_md5);
        if (memcmp(calc_md5, archive_footer.md5sum_data, MD5_DIGEST_LENGTH) == 0) {
            printf("\tData MD5 does match:\n");
        } else {
            validation_failed = TRUE;
            printf("\t*** Data MD5 does not match:\n");
        }
        printf("\t\tfound: ");
        for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
            printf("%02x", calc_md5[i]);
        }
        printf("\n\t\tin file: ");
        for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
            printf("%02x", archive_footer.md5sum_data[i]);
        }
        printf("\n");
            
        if (validation_failed) {
            printf("\t*** Validation failure: %s for member %d\n",
                   archive_name ? archive_name : "stdin",
                   member_count);
        }
            
        free(file_buffer);
    }
        
    if (fd != STDIN_FILENO) {
        close(fd);
    }
}
