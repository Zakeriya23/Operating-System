#pragma once

#ifndef _BINFILE_H
#define _BINFILE_H

#define FILE_NAME "bin_file.bin"
#define NAME_LEN 25

typedef struct bin_file_s
{
    int id;
    double gpa;
    char g_name[NAME_LEN];
    char f_name[NAME_LEN];
} bin_file_t;

#endif // BINFILE_H