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

#define DEFAULT_SO  "./logger.so"
#define DEFAULT_OUT "2"
#define SHLIB       "libc.so.6"

int main(const int argc, char *argv[]){
    int i, j;
    char *file, *sopath, *cmd, buf[10];
    char **cmd_arg;

    if(argc==1){
        printf("no command given.\n");
        exit(1);
    }
    setenv("LD_PRELOAD", DEFAULT_SO, 1);
    setenv("LOGGER_OUT", DEFAULT_OUT, 1);
    for(i=1; i<argc; i++){
        if(strcmp("-p", argv[i])==0){
            int size = strlen(argv[++i]);
            sopath = new char[size];
            strcpy(sopath, argv[i]);
            setenv("LD_PRELOAD", sopath, 1);
        }
        else if(strcmp("-o", argv[i])==0){
            int size = strlen(argv[++i]);
            file = new char[size];
            strcpy(file, argv[i]);
            void *handled = dlopen(SHLIB, RTLD_LAZY);
            int (*old_open)(const char *, int, ...);
            *(void **)(&old_open) = dlsym(handled, "open");
            int fd = (*old_open)(file, O_RDWR|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH);
            /*
            void *handle = dlopen(SHLIB, RTLD_LAZY);
            open_t o_open = (int(*)(const char*, int, ...))dlsym(handle, "open");
            int fd = o_open(file, O_RDWR|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH);
            */
            sprintf(buf, "%d", fd);
            setenv("LOGGER_OUT", buf, 1);
        }
        else if(strcmp("--", argv[i])==0 || argv[i][0]!='-'){
            int size = (strcmp("--", argv[i])==0) ? (strlen(argv[++i])) : (strlen(argv[i]));
            cmd = new char[size];
            strcpy(cmd, argv[i]);

            size = 2 + argc - (++i);
            if(size>=0){
                cmd_arg = new char *[size];
                cmd_arg[0] = new char[strlen(cmd)];
                strcpy(cmd_arg[0], cmd);
                for(j=1; i<argc; i++, j++){
                    size = strlen(argv[i]);
                    cmd_arg[j] = new char[size];
                    strcpy(cmd_arg[j], argv[i]);
                }
                cmd_arg[j] = NULL;
            }
            execvp(cmd, cmd_arg);
        }
        else{
            char *pch = strtok(argv[i], "-");
            print_usage(pch);
            exit(1);
        }
    }
    
    return 0;
}