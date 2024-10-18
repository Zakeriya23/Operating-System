#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>

#define ASCII_MIN 32
#define ASCII_MAX 126
#define ASCII_RANGE (ASCII_MAX - ASCII_MIN + 1)

void encrypt(FILE *input, FILE *output, int shift);
void decrypt(FILE *input, FILE *output, int shift);

int main(int argc, char *argv[]) {
    int shift = 3;  
    int encrypt_flag = 1;  
    int option;

    // Use getopt() to parse command line options
    while ((option = getopt(argc, argv, "eds:")) != -1) {
        switch (option) {
            case 'e':
                encrypt_flag = 1;
                break;
            case 'd':
                encrypt_flag = 0;
                break;
            case 's':
                shift = atoi(optarg);
                if (shift < 0 || shift > 95) {
                    fprintf(stderr, "Error: Shift value must be between 0 and 95.\n");
                    return 1;
                }
                break;
            default:
                fprintf(stderr, "Usage: %s [-e] [-d] [-s shift]\n", argv[0]);
                return 1;
        }
    }

    if (encrypt_flag) {
        encrypt(stdin, stdout, shift);
    } else {
        decrypt(stdin, stdout, shift);
    }

    return 0;
}

void encrypt(FILE *input, FILE *output, int shift) {
    int ch;
    while ((ch = fgetc(input)) != EOF) {
        if (ch >= ASCII_MIN && ch <= ASCII_MAX) {
            int encrypted_char = ((ch - ASCII_MIN + shift) % ASCII_RANGE) + ASCII_MIN;
            fputc(encrypted_char, output);
        } else {
            fputc(ch, output);
        }
    }
}

void decrypt(FILE *input, FILE *output, int shift) {
    int ch;
    while ((ch = fgetc(input)) != EOF) {
        if (ch >= ASCII_MIN && ch <= ASCII_MAX) {
            int decrypted_char = ((ch - ASCII_MIN - shift + ASCII_RANGE) % ASCII_RANGE) + ASCII_MIN;
            fputc(decrypted_char, output);
        } else {
            fputc(ch, output);
        }
    }
}
