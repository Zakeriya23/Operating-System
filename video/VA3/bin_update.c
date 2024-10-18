#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "bin_file.h"

#define OPTIONS "i:g:"

int main(int argc, char * argv[])
{
    int ofd = -1;
    int record = -1;
    double gpa = -1.0;
    off_t offset = 0;
    off_t r_offset  = 0;
    off_t size = sizeof(bin_file_t);

    {
        int opt = 0;
        while ((opt = getopt(argc, argv, OPTIONS)) != -1)
        {
            switch (opt)
            {
            case 'i':
                if(sscanf(optarg, "%d", &record) != 1)
                {
                    perror("cannot parse record");
                    exit(EXIT_FAILURE);
                }
                break;
            case 'g':
                if (sscanf(optarg, "%lf", &gpa) != 1)
                {
                    perror("cannot parse gpa");
                    exit(EXIT_FAILURE);
                }
                break;
            default:
                fprintf(stderr, "unknown option %c\n", opt);
                exit(EXIT_FAILURE);
                break;
            }
        }
        if((record < 0) || (gpa < 0.0))
        {
            fprintf(stderr, "must specify record and gpa\n");
            exit(EXIT_FAILURE);
        }
        ofd = open(FILE_NAME, O_RDWR);
        if(ofd < 0)
        {
            perror("Cannot open " FILE_NAME " for output");
            exit(EXIT_FAILURE);
        }
    }
    r_offset = offset = record * size;
    if(lseek(ofd, offset, SEEK_SET) != r_offset)
    {
        perror("lseek() failed");
        exit(EXIT_FAILURE);
    }
    else
    {
        bin_file_t student = {0, 0.0, "", ""};
        read(ofd, &student, sizeof(bin_file_t));
        student.gpa = gpa;
        lseek(ofd, -1 * size, SEEK_CUR);
        write(ofd, &student, sizeof(bin_file_t));
    }
    close(ofd);
    return EXIT_SUCCESS;
}