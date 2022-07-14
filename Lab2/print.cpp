#include "print.h"

void print_usage(char *pch){
    cout << "./logger: invalid option -- '" << pch << "'" << endl;
    cout << "usage: ./logger [-o file] [-p sopath] [--] cmd [cmd args ...]" << endl;
    cout << "        -p: set the path to logger.so, default = ./logger.so" << endl;
    cout << "        -o: print output to file, print to \"stderr\" if no file specified" << endl;
    cout << "        --: separate the arguments for logger and for the command" << endl;
}

void print_chmod(const char *pathname, mode_t mode, int retval){
    char *path = realpath(pathname, NULL);
    if(path == NULL){
        path = new char [10];
        //path = (char*)malloc(sizeof(char)*sizeof("untouched"));
        strcpy(path, "untouched");
    }
    char* fd = getenv("LOGGER_OUT");
    dprintf(atoi(fd), "[logger] chmod(\"%s\", %o) = %d\n", path, mode, retval);

    delete [] path;
    //free(path);
}

void print_chown(const char *pathname, uid_t owner, gid_t group, int retval){
    char *path = realpath(pathname, NULL);
    if(path == NULL){
        path = new char [10];
        //path = (char*)malloc(sizeof(char)*sizeof("untouched"));
        strcpy(path, "untouched");
    }
    char* fd = getenv("LOGGER_OUT");
    dprintf(atoi(fd), "[logger] chown(\"%s\", %d, %d) = %d\n", path, owner, group, retval);

    delete [] path;
    //free(path);
}

void print_close(char *name, int retval){
    char* out_fd = getenv("LOGGER_OUT");
    dprintf(atoi(out_fd), "[logger] close(\"%s\") = %d\n", name, retval);
}

void print_creat64(const char *pathname, mode_t mode, int retval){
    char *path = realpath(pathname, NULL);
    if(path == NULL){
        path = new char [10];
        //path = (char*)malloc(sizeof(char)*sizeof("untouched"));
        strcpy(path, "untouched");
    }

    char *fd = getenv("LOGGER_OUT");
    dprintf(atoi(fd), "[logger] creat(\"%s\", %o) = %d\n",path, mode, retval);

    delete [] path;
    //free(path);
}

void print_creat(const char *pathname, mode_t mode, int retval){
    char *path = realpath(pathname, NULL);
    if(path == NULL){
        path = new char [10];
        //path = (char*)malloc(sizeof(char)*sizeof("untouched"));
        strcpy(path, "untouched");
    }

    char *fd = getenv("LOGGER_OUT");
    dprintf(atoi(fd), "[logger] creat(\"%s\", %o) = %d\n",path, mode, retval);

    delete [] path;
    //free(path);
}

void print_fopen(const char *pathname, const char *mode, FILE *retval){
    char *path = realpath(pathname, NULL);
    if(path == NULL){ 
        path = new char[10];
        //path = (char*)malloc(sizeof(char)*sizeof("untouched"));
        strcpy(path, "untouched");
    }

    char *out_fd = getenv("LOGGER_OUT");
    dprintf(atoi(out_fd), "[logger] fopen(\"%s\", \"%s\") = %p\n", path, mode, retval);

    delete [] path;
    //free(path);
}

void print_fopen64(const char *pathname, const char *mode, FILE *retval){
    char *path = realpath(pathname, NULL);
    if(path == NULL){ 
        path = new char[10];
        //path = (char*)malloc(sizeof(char)*sizeof("untouched"));
        strcpy(path, "untouched");
    }

    char *out_fd = getenv("LOGGER_OUT");
    dprintf(atoi(out_fd), "[logger] fopen(\"%s\", \"%s\") = %p\n", path, mode, retval);

    delete [] path;
    //free(path);
}

void print_fclose(char *str_buf, int retval){
    char *out_fd = getenv("LOGGER_OUT");
    dprintf(atoi(out_fd), "[logger] fclose(\"%s\") = %d\n", str_buf, retval);
}

void print_fread(void *ptr, size_t size, size_t nmemb, char *str_buf, size_t retval){
    size_t i;
    ptr = (char*)ptr;
    int out = atoi(getenv("LOGGER_OUT"));
    dprintf(out, "[logger] fread(\"");
    for(i = 0; i < size * nmemb && i < 32 && i < retval; i++){
        if(isprint((int)*((char*)ptr + i)) == 0)    
            dprintf(out, ".");
        else                                    
            dprintf(out, "%c", *((char*)ptr + i));
    }
    dprintf(out, "\", %ld, %ld, \"%s\") = %ld\n", size, nmemb, str_buf, retval);
}

void print_fwrite(const void *ptr, size_t size, size_t nmemb, char *str_buf, size_t retval){
    size_t i;
    int out = atoi(getenv("LOGGER_OUT"));
    dprintf(out, "[logger] fwrite(\"");
    for(i = 0; i < size * nmemb && i < 32 && i < retval; i += size){
        if(isprint((int)*((char*)ptr + i)) == 0)    
            dprintf(out, ".");
        else                                    
            dprintf(out, "%c", *((char*)ptr + i));
    }
    dprintf(out, "\", %ld, %ld, \"%s\") = %ld\n", size, nmemb, str_buf, retval);
}

void print_open(const char *pathname, int flags, mode_t mode, int retval){
    char *path = realpath(pathname, NULL);
    if(path == NULL){
        path = new char[10];
        //path = (char*)malloc(sizeof(char)*sizeof("untouched"));
        strcpy(path, "untouched");
    }
    char* fd = getenv("LOGGER_OUT");
    dprintf(atoi(fd), "[logger] open(\"%s\", %o, %o) = %d\n", path, flags, mode, retval);

    delete [] path;
    //free(path);
}

void print_open64(const char *pathname, int flags, mode_t mode, int retval){
    char *path = realpath(pathname, NULL);
    if(path == NULL){
        path = new char[10];
        //path = (char*)malloc(sizeof(char)*sizeof("untouched"));
        strcpy(path, "untouched");
    }
    char* fd = getenv("LOGGER_OUT");
    dprintf(atoi(fd), "[logger] open(\"%s\", %o, %o) = %d\n", path, flags, mode, retval);

    delete [] path;
    //free(path);
}

void print_rename(char *path1, char *path2, int retval){
    char *fd = getenv("LOGGER_OUT");
    dprintf(atoi(fd), "[logger] rename(\"%s\", \"%s\") = %d\n", path1, path2, retval);
}

void print_write(char *str_buf, const void *buf, size_t count, ssize_t retval){
    size_t i;
    char* out_fd = getenv("LOGGER_OUT");
    dprintf(atoi(out_fd), "[logger] write(%s, \"", str_buf);
    for(i = 0; i < count && i < 32 && i < retval; i++){
        if(isprint((int)*((char*)buf + i)) == 0)    
            dprintf(atoi(out_fd), ".");
        else                                    
            dprintf(atoi(out_fd), "%c", *((char*)buf + i));
    }
    dprintf(atoi(out_fd), "\", %ld) = %ld\n", count, retval);
}

void print_read(char *str_buf, const void *buf, size_t count, ssize_t retval){
    size_t i;
    char* out_fd = getenv("LOGGER_OUT");
    dprintf(atoi(out_fd), "[logger] read(%s, \"", str_buf);
    for(i = 0; i < count && i < 32 && i < retval; i++){
        if(isprint((int)*((char*)buf + i)) == 0)    
            dprintf(atoi(out_fd), ".");
        else                                    
            dprintf(atoi(out_fd), "%c", *((char*)buf + i));
    }
    dprintf(atoi(out_fd), "\", %ld) = %ld\n", count, retval);
}

void print_tmpfile(FILE *retval){
    char* out_fd = getenv("LOGGER_OUT");
    dprintf(atoi(out_fd), "[logger] tmpfile() = \"%p\"\n", retval);
}

void print_tmpfile64(FILE *retval){
    char* out_fd = getenv("LOGGER_OUT");
    dprintf(atoi(out_fd), "[logger] tmpfile() = \"%p\"\n", retval);
}

void print_remove(char *path, int retval){
    char* fd = getenv("LOGGER_OUT");
    dprintf(atoi(fd), "[logger] remove(\"%s\") = %d\n", path, retval);
}