#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "bin_file.h"

int main(void)
{
    bin_file_t students[] = 
    {
        {0, 3.99, "Kevin", "McGrath"},
        {0, 4.00, "Mark", "Jones"},
        {0, 3.91, "Mike", "Wilson"},
        {0, 3.85, "Jesse", "Chaney"}
    };
    int nelms = sizeof(students) / sizeof(bin_file_t);
    int ofd = -1;
    mode_t old_mode = 0;

    old_mode = umask(0);
    ofd = open(FILE_NAME, O_WRONLY | O_TRUNC | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    //chmod(FILE_NAME, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH );

    if(ofd < 0)
    {
        perror("Cannot open " FILE_NAME " for output");
        exit(EXIT_FAILURE);
    }
    for(int i = 0; i < nelms; ++i)
    {
        students[i].id = i;
        write(ofd, &students[i], sizeof(bin_file_t));
    } 
    close(ofd);
    umask(old_mode);

    return EXIT_SUCCESS;
}