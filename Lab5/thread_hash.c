//Zakeriya Muhumed Operating System Threads From the Crypt
//Libray
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <crypt.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/time.h>
#include "thread_hash.h"

void usage(void);
void parse(int argc, char **argv, char **input_file, char **dict_file, char **output_file, int *threads, int *verbose);
char **load_file(const char *filename, size_t *size);
void *crack_passwords(void *args);

typedef struct thread_args {
    char **dictionary;
    size_t dict_size;
    char **hashes;         // Hashed passwords
    size_t hash_count;     // Number of hashed passwords
    int thread_id;         // Thread ID
    int thread_count;      // Total number of threads
} thread_args_t;

// Global variables and mutex 
static pthread_mutex_t output_mutex = PTHREAD_MUTEX_INITIALIZER;
static size_t cracked_count = 0;
static size_t failed_count = 0;

// Print usage instructions
void usage(void) {
    fprintf(stderr, "Usage: ./thread_hash -i <input file> -d <dictionary file> -o <output file> [-t <threads>] [-v] [-h]\n");

    fprintf(stderr, "Supported hash algorithms:\n");

    for (int i = 0; i < ALGORITHM_MAX; i++) {
        fprintf(stderr, "  %s\n", algorithm_string[i]);
    }

    exit(EXIT_FAILURE);
}

// Parse command-line arguments
void parse(int argc, char **argv, char **input_file, char **dict_file, char **output_file, int *threads, int *verbose) {
    int opt;
    while ((opt = getopt(argc, argv, OPTIONS)) != -1) {
        switch (opt) {
            case 'i': *input_file = optarg; break;
            case 'd': *dict_file = optarg; break;
            case 'o': *output_file = optarg; break;
            case 't': *threads = atoi(optarg); break;
            case 'v': *verbose = 1; break;
            case 'h': usage(); break;
            default: usage();
        }
    }

    if (!*input_file || !*dict_file) {
        usage();
    }
}

char **load_file(const char *filename, size_t *size) {
    FILE *fp;
    char **lines;
    char buffer[256];

    fp = fopen(filename, "r");
    if (!fp) {
        perror("Failed to open file");
        exit(EXIT_FAILURE);
    }

    lines = malloc(20000 * sizeof(char *)); // max 20k lines
    *size = 0;

    while (fgets(buffer, sizeof(buffer), fp)) {
        buffer[strcspn(buffer, "\n")] = '\0'; // Remove newline
        lines[(*size)++] = strdup(buffer);
    }

    fclose(fp);
    return lines;
}
void *crack_passwords(void *args) {
    thread_args_t *targs = (thread_args_t *) args;
    struct crypt_data crypt_stuff;
    size_t local_cracked = 0, local_failed = 0;
    memset(&crypt_stuff, 0, sizeof(crypt_stuff));

    for (size_t i = targs->thread_id; i < targs->hash_count; i += targs->thread_count) {
        int cracked = 0;  // Flag to check if a hash is cracked

        for (size_t j = 0; j < targs->dict_size; j++) {
            char *crypt_result = crypt_r(targs->dictionary[j], targs->hashes[i], &crypt_stuff);
            if (strcmp(crypt_result, targs->hashes[i]) == 0) {
                pthread_mutex_lock(&output_mutex);
                printf("cracked %s\t%s\n", targs->dictionary[j], targs->hashes[i]);
                local_cracked++;
                pthread_mutex_unlock(&output_mutex);
                cracked = 1;  
                break;       
            }
        }

        if (!cracked) {
            // Log failed hash if it couldn't be cracked
            pthread_mutex_lock(&output_mutex);
            printf("*** failed to crack %s\n", targs->hashes[i]);
            local_failed++;
            pthread_mutex_unlock(&output_mutex);
        }
    }

    pthread_mutex_lock(&output_mutex);
    cracked_count += local_cracked;
    failed_count += local_failed;
    pthread_mutex_unlock(&output_mutex);

    return NULL;
}

int main(int argc, char **argv) {
    char *input_file = NULL, *dict_file = NULL, *output_file = NULL;
    int threads = 1, verbose = 0;

    size_t dict_size = 0, hash_count = 0;
    char **dictionary, **hashes;
    pthread_t *thread_ids;
    thread_args_t *targs;

    // Parse arguments
    parse(argc, argv, &input_file, &dict_file, &output_file, &threads, &verbose);

    // Load files
    dictionary = load_file(dict_file, &dict_size);
    hashes = load_file(input_file, &hash_count);

    // Create threads
    thread_ids = malloc(threads * sizeof(pthread_t));
    targs = malloc(threads * sizeof(thread_args_t));

    for (int i = 0; i < threads; i++) {
        targs[i] = (thread_args_t){ dictionary, dict_size, hashes, hash_count, i, threads };
        pthread_create(&thread_ids[i], NULL, crack_passwords, &targs[i]);
    }

    // Join threads
    for (int i = 0; i < threads; i++) {
        pthread_join(thread_ids[i], NULL);
    }

    // Print summary
    fprintf(stderr, "Cracked passwords: %zu, Failed passwords: %zu\n", cracked_count, failed_count);

    // Clean up
    for (size_t i = 0; i < dict_size; i++) free(dictionary[i]);
    for (size_t i = 0; i < hash_count; i++) free(hashes[i]);
    free(dictionary);
    free(hashes);
    free(thread_ids);
    free(targs);

    return EXIT_SUCCESS;
}

