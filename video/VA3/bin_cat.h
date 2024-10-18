#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "bin_file.h"

int main(void)
{
    bin_file_t student = {0, 0.0, "", ""};
    int ifd = -1;

    ifd = open(FILE_NAME, O_RDONLY);
    if(ifd < 0)
    {
        perror("Cannot open" FILE_NAME " for output");
        exit(EXIT_FAILURE);
    }
    while (read(ifd, &student, sizeof(bin_file_t)) > 0)
    {
        printf("ID: %d\n\tGiven name:  %s\n\tFamily name: %s\n\tGPA          %.4lf\n",
                student.id, student.g_name, student.f_name, student.gpa); 
    }
    close (ifd);
    return EXIT_SUCCESS;
}