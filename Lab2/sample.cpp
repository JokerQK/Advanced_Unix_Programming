#include "print.h"
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

//typedef int     (*open_t)(const char*, int, ...);
//typedef int     (*open64_t)(const char*, int, ...);

#define OLDNAME "aaaa"
#define NEWNAME "bbbb"
#define BUFSIZE 1024

int main(){
    int fd;
    FILE *file;
    char buf1[BUFSIZE], buf2[BUFSIZE];

    close(2);
    creat(OLDNAME, 0600);
    chmod(OLDNAME, 0666);
    chown(OLDNAME, 65534, 65534);
    rename(OLDNAME, NEWNAME);
    fd = open(NEWNAME, O_CREAT|O_RDWR, 0666);
    write(fd, "cccc", 5);
    close(fd);

    fd = open(NEWNAME, O_RDONLY);
    read(fd, buf1, 100);
    close(fd);
    
    file = tmpfile();
    fwrite("cccc", 1, 5, file);
    fclose(file);

    file = fopen(NEWNAME, "r");
    fread(buf2, 1, 100, file);
    fclose(file);

    remove(NEWNAME);
    //cout << "sample done." << endl;
    return 0;
}