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

#define SHLIB       "libc.so.6"
#define PRINT_SIZE  32

int chmod(const char *pathname, mode_t mode){ // m
    int (*old_chmod)(const char *, mode_t);
    void *handled = dlopen(SHLIB, RTLD_LAZY);
    *(void **)(&old_chmod) = dlsym(handled, "chmod");
    int retval = (*old_chmod)(pathname, mode);
    
    print_chmod(pathname, mode, retval);
    return retval;
}
int chown(const char *pathname, uid_t owner, gid_t group){ // m
    int (*old_chown)(const char *, uid_t, gid_t);
    void *handled = dlopen(SHLIB, RTLD_LAZY);
    *(void **)(&old_chown) = dlsym(handled, "chown");
    int retval = (*old_chown)(pathname, owner, group);
    
    print_chown(pathname, owner, group, retval);
    return retval;
}
int close(int fd){ // m
    int (*old_close)(int);
    void *handled;
    char name[4096] = {'\0'};
    string fd_path = "/proc/self/fd/" + to_string(fd);
    readlink(fd_path.c_str(), name, sizeof(name) - 1);
    
    int retval;
    if(fd!=2){
        handled = dlopen(SHLIB, RTLD_LAZY);
        *(void **)(&old_close) = dlsym(handled, "close");
        retval = (*old_close)(fd);
    }
    else
        retval = 0;
    
    print_close(name, retval);
    return retval;
}
int creat64(const char *pathname, mode_t mode){ // m ??
    int (*old_creat)(const char *, mode_t);
    void *handled = dlopen(SHLIB, RTLD_LAZY);
    *(void **)(&old_creat) = dlsym(handled, "creat");
    int retval = (*old_creat)(pathname, mode);
    
    print_creat64(pathname, mode, retval);
    return retval;
}
int creat(const char *pathname, mode_t mode){ // m
    int (*old_creat)(const char *, mode_t);
    void *handled = dlopen(SHLIB, RTLD_LAZY);
    *(void **)(&old_creat) = dlsym(handled, "creat");
    int retval = (*old_creat)(pathname, mode);
    
    print_creat(pathname, mode, retval);
    return retval;
}
FILE *fopen(const char *pathname, const char *mode){ // m
    FILE* (*old_fopen)(const char *,  const char *);
    void *handled = dlopen(SHLIB, RTLD_LAZY);
    *(void **)(&old_fopen) = dlsym(handled, "fopen");
    FILE *retval = (*old_fopen)(pathname, mode);    

    print_fopen(pathname, mode, retval);
    return retval;
}
FILE *fopen64(const char *pathname, const char *mode){ // m ??
    FILE* (*old_fopen)(const char *,  const char *);
    void *handled = dlopen(SHLIB, RTLD_LAZY);
    *(void **)(&old_fopen) = dlsym(handled, "fopen");
    FILE *retval = (*old_fopen)(pathname, mode);    
    
    print_fopen64(pathname, mode, retval);
    return retval;
}
int fclose(FILE *stream){ // m
    int (*old_fclose)(FILE *);
    void *handled = dlopen(SHLIB, RTLD_LAZY);
    *(void **)(&old_fclose) = dlsym(handled, "fclose");
    
    char str_buf[1024]={'\0'};
    int fno;
    fno = fileno(stream);
    string fd_path = "/proc/self/fd/" + to_string(fno);
    readlink(fd_path.c_str(), str_buf, sizeof(str_buf)-1);

    int retval = (*old_fclose)(stream);
    
    print_fclose(str_buf, retval);
    return retval;
}
size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream){ // m ??!!
    size_t (*old_fread)(void *, size_t, size_t, FILE *);
    void *handled = dlopen(SHLIB, RTLD_LAZY);
    *(void **)(&old_fread) = dlsym(handled, "fread");
    size_t retval = (*old_fread)(ptr, size, nmemb, stream);
    
    char str_buf[4096]={'\0'};
    int fno;
    fno = fileno(stream);
    string fd_path = "/proc/self/fd/" + to_string(fno);
    readlink(fd_path.c_str(), str_buf, sizeof(str_buf)-1);
    
    print_fread(ptr, size, nmemb, str_buf, retval);
    return retval;
}
size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream){ // m ??!!
    size_t (*old_fwrite)(const void*, size_t, size_t, FILE*);
    void *handled = dlopen(SHLIB, RTLD_LAZY);
    *(void **)(&old_fwrite) = dlsym(handled, "fwrite");
    size_t retval = (*old_fwrite)(ptr, size, nmemb, stream);
    
    char str_buf[4096]={'\0'};
    int fno;
    fno = fileno(stream);
    string fd_path = "/proc/self/fd/" + to_string(fno);
    readlink(fd_path.c_str(), str_buf, sizeof(str_buf)-1);
    
    print_fwrite(ptr, size, nmemb, str_buf, retval);
    return retval;
}
int open(const char *pathname, int flags, ...){ // m
    void *handled = dlopen(SHLIB, RTLD_LAZY);
    int (*old_open)(const char *, int, mode_t);
    *(void **)(&old_open) = dlsym(handled, "open");
    int retval;
    /*   
        The  mode  argument  specifies  the  file  mode  bits be applied when a new file is created.  
        This argument must be supplied when O_CREAT or O_TMPFILE is specified in flags; 
        if neither  O_CREAT nor O_TMPFILE is specified, then mode is ignored.   
    */
    mode_t mode = 0;
    /*
    va_list args;
    va_start(args, flags);
    
    if((flags&O_CREAT) || (flags&O_TMPFILE)){
        mode = va_arg(args, mode_t);
        retval = (*old_open)(pathname, flags, mode);
    }
    else    
        retval = (*old_open)(pathname, flags);
    */
    if(__OPEN_NEEDS_MODE(flags)){
        va_list arg;
        va_start(arg, flags);
        mode = va_arg(arg, mode_t);
        va_end (arg);
    }
    retval = (*old_open)(pathname, flags, mode);
    
    print_open(pathname, flags, mode, retval);
    return retval;
}
int open64(const char *pathname, int flags, ...){ // m
    void *handled = dlopen(SHLIB, RTLD_LAZY);
    int (*old_open)(const char *, int, mode_t);
    *(void **)(&old_open) = dlsym(handled, "open");
    int retval;
    /*   
        The  mode  argument  specifies  the  file  mode  bits be applied when a new file is created.  
        This argument must be supplied when O_CREAT or O_TMPFILE is specified in flags; 
        if neither  O_CREAT nor O_TMPFILE is specified, then mode is ignored.   
    */
    mode_t mode = 0;
    /*
    va_list args;
    va_start(args, flags);
    
    if((flags&O_CREAT) || (flags&O_TMPFILE)){
        mode = va_arg(args, mode_t);
        retval = (*old_open64)(pathname, flags, mode);
    }
    else    
        retval = (*old_open64)(pathname, flags);
    */
    if(__OPEN_NEEDS_MODE(flags)){
        va_list arg;
        va_start(arg, flags);
        mode = va_arg(arg, mode_t);
        va_end (arg);
    }
    retval = (*old_open)(pathname, flags, mode);
    
    print_open64(pathname, flags, mode, retval);
    return retval;
}
int rename(const char *oldpath, const char *newpath){ // m
    char *path1 = realpath(oldpath, NULL);
    if(path1 == NULL){
        path1 = new char[10];
        //path1 = (char*)malloc(sizeof(char)*sizeof("untouched"));
        strcpy(path1, "untouched");
    }
    int (*old_rename)(const char *, const char *);
    void *handled = dlopen(SHLIB, RTLD_LAZY);
    *(void **)(&old_rename) = dlsym(handled, "rename");
    int retval = (*old_rename)(oldpath, newpath);
    
    char *path2 = realpath(newpath, NULL);
    if(path2 == NULL){
        path2 = new char[10];
        //path2 = (char*)malloc(sizeof(char)*sizeof("untouched"));
        strcpy(path2, "untouched");
    }
    
    print_rename(path1, path2, retval);
    delete [] path1;
    delete [] path2;
    //free(path1);
    //free(path2);
    return retval;
}
ssize_t write(int fd, const void *buf, size_t count){ // m ??
    ssize_t (*old_write)(int, const void*, size_t);
    void *handled = dlopen(SHLIB, RTLD_LAZY);
    *(void **)(&old_write) = dlsym(handled, "write");
    ssize_t retval = (*old_write)(fd, buf, count);

    char str_buf[4096]={'\0'};
    string fd_path = "/proc/self/fd/" + to_string(fd);
    readlink(fd_path.c_str(), str_buf, sizeof(str_buf)-1);
    
    print_write(str_buf, buf, count, retval);
    return retval;
}
ssize_t read(int fd, void *buf, size_t count){ // m ??
    ssize_t (*old_read)(int, void*, size_t);
    void *handled = dlopen(SHLIB, RTLD_LAZY);
    *(void **)(&old_read) = dlsym(handled, "read");
    ssize_t retval = (*old_read)(fd, buf, count);
    
    char str_buf[4096]={'\0'};
    string fd_path = "/proc/self/fd/" + to_string(fd);
    readlink(fd_path.c_str(), str_buf, sizeof(str_buf)-1);
    
    print_read(str_buf, buf, count, retval);
    return retval;
}
FILE* tmpfile(void){
    FILE* (*old_tmpfile)(void);
    void *handled = dlopen(SHLIB, RTLD_LAZY);
    *(void **)(&old_tmpfile) = dlsym(handled, "tmpfile");
    FILE* retval = (*old_tmpfile)();
    
    print_tmpfile(retval);
    return retval;
}
FILE* tmpfile64(void){
    //
    FILE* (*old_tmpfile)(void);
    void *handled = dlopen(SHLIB, RTLD_LAZY);
    *(void **)(&old_tmpfile) = dlsym(handled, "tmpfile");
    FILE* retval = (*old_tmpfile)();
    
    print_tmpfile64(retval);
    return retval;
}
int remove(const char *pathname){
    char *path = realpath(pathname, NULL);
    if(path == NULL){
        path = new char[10];
        //path = (char*)malloc(sizeof(char)*sizeof("untouched"));
        strcpy(path, "untouched");
    }
    int (*old_remove)(const char *);
    void *handled = dlopen(SHLIB, RTLD_LAZY);
    *(void **)(&old_remove) = dlsym(handled, "remove");
    int retval = (*old_remove)(pathname);
    
    print_remove(path, retval);
    delete [] path;
    //free(path);
    return retval;
}