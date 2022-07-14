#ifndef _PRINT_H
#define _PRINT_H

#include <stdio.h>
#include <dlfcn.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>
#include <stdarg.h>
#include <string.h>
#include <iostream>
using namespace std;

void print_usage(char *);

void print_chmod(const char *, mode_t, int);
void print_chown(const char *, uid_t, gid_t, int);

void print_close(char *, int);

void print_creat64(const char *, mode_t, int);
void print_creat(const char *, mode_t, int);

void print_fopen(const char *, const char *, FILE *);
void print_fopen64(const char *, const char *, FILE *);

void print_fclose(char *, int);

void print_fread(void *, size_t, size_t, char *, size_t);
void print_fwrite(const void *, size_t, size_t, char *, size_t);

void print_open(const char *, int, mode_t, int);
void print_open64(const char *, int, mode_t, int);

void print_rename(char *, char *, int);

void print_write(char *, const void *, size_t, ssize_t);
void print_read(char *, const void *, size_t, ssize_t);

void print_tmpfile(FILE *);
void print_tmpfile64(FILE *);

void print_remove(char *, int);
#endif