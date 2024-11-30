// rchaney@pdx.edu

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <crypt.h>

#define BUF_SIZE 1000

// Run this with
//   ./uncrypt_example < key10.txt
// or
//   ./uncrypt_example 1 < key10.txt

    int
main(int argc, __attribute__((unused)) char *argv[])
{
    char buf[BUF_SIZE] = {'\0'};
    char *plain_text = NULL;
    char *setting = NULL;
    char *crypt_return = NULL;
    struct crypt_data crypt_stuff;

    while(fgets(buf, BUF_SIZE, stdin) != NULL) {
        // This time, I make use of the pesky newline.
        // get the plaintext passwprd
        plain_text = strtok(buf, ":");
        if (argc > 1) {
            // this is to make sure the crypt check fails.
            plain_text[0] = 'q';
        }
        // the hashed password
        setting = strtok(NULL, "\n");

        memset(&crypt_stuff, 0, sizeof(crypt_stuff));
        strncpy(crypt_stuff.setting, setting, CRYPT_OUTPUT_SIZE);
        strncpy(crypt_stuff.input, plain_text, CRYPT_MAX_PASSPHRASE_SIZE);
        crypt_return = crypt_rn(plain_text, setting, &crypt_stuff, sizeof(crypt_stuff));

        if (strcmp(crypt_stuff.setting, crypt_return) == 0) {
            printf("cracked %s\t%s\n", plain_text, crypt_stuff.output);
            printf("\t%s\t%s\n", crypt_stuff.setting, crypt_stuff.output);
        }
        else {
            printf("*** failed to crack %s\t%s\n", plain_text, crypt_stuff.output);
            printf("\t%s\t%s\n", crypt_stuff.setting, crypt_stuff.output);
        }
    }

    return EXIT_SUCCESS;
}
