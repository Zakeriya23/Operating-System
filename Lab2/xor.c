#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#define DEFAULT_KEY "Xerographic"
#define BUF_SIZE 1024  //read/write operations buffer size

void xor_cipher(const char *key, int key_length);

int main(int argc, char *argv[]) {
    const char *key = DEFAULT_KEY;
    int option;
    int key_length;  

    // getopt() to parse command line options
    while ((option = getopt(argc, argv, "k:")) != -1) {
        switch (option) {
            case 'k':
                key = optarg;
                break;
            default:
                fprintf(stderr, "Usage: %s [-k key]\n", argv[0]);
                return 1;
        }
    }

    key_length = strlen(key); 
    if (key_length == 0) {
        fprintf(stderr, "Error: Key must not be empty.\n");
        return 1;
    }

    xor_cipher(key, key_length);

    return 0;
}

void xor_cipher(const char *key, int key_length) {
    char buffer[BUF_SIZE];
    ssize_t bytes_read;
    int key_index = 0;

    while ((bytes_read = read(STDIN_FILENO, buffer, BUF_SIZE)) > 0) {
        for (ssize_t i = 0; i < bytes_read; i++) {
            buffer[i] ^= key[key_index];
            key_index = (key_index + 1) % key_length;
        }

        if (write(STDOUT_FILENO, buffer, bytes_read) != bytes_read) {
            perror("write");
            exit(EXIT_FAILURE);
        }
    }

    if (bytes_read < 0) {
        perror("read");
        exit(EXIT_FAILURE);
    }
}