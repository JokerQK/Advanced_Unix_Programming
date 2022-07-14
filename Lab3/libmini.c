#include "libmini.h"

long errno;

#define WRAPPER_RETval(type) \
    errno = 0;               \
    if (ret < 0)             \
    {                        \
        errno = -ret;        \
        return -1;           \
    }                        \
    return ((type)ret);
#define WRAPPER_RETptr(type) \
    errno = 0;               \
    if (ret < 0)             \
    {                        \
        errno = -ret;        \
        return NULL;         \
    }                        \
    return ((type)ret);

ssize_t	read(int fd, char *buf, size_t count) {
	long ret = sys_read(fd, buf, count);
	WRAPPER_RETval(ssize_t);
}
/* open is implemented in assembly, because of variable length arguments */

int	close(unsigned int fd) {
	long ret = sys_close(fd);
	WRAPPER_RETval(int);
}

void *	mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off) {
	long ret = sys_mmap(addr, len, prot, flags, fd, off);
	WRAPPER_RETptr(void *);
}

int	mprotect(void *addr, size_t len, int prot) {
	long ret = sys_mprotect(addr, len, prot);
	WRAPPER_RETval(int);
}

int	munmap(void *addr, size_t len) {
	long ret = sys_munmap(addr, len);
	WRAPPER_RETval(int);
}

int	pipe(int *filedes) {
	long ret = sys_pipe(filedes);
	WRAPPER_RETval(int);
}

int	dup(int filedes) {
	long ret = sys_dup(filedes);
	WRAPPER_RETval(int);
}

int	dup2(int oldfd, int newfd) {
	long ret = sys_dup2(oldfd, newfd);
	WRAPPER_RETval(int);
}

int	nanosleep(struct timespec *rqtp, struct timespec *rmtp) {
	long ret = sys_nanosleep(rqtp, rmtp);
	WRAPPER_RETval(int);
}

pid_t	fork(void) {
	long ret = sys_fork();
	WRAPPER_RETval(pid_t);
}

char *	getcwd(char *buf, size_t size) {
	long ret = sys_getcwd(buf, size);
	WRAPPER_RETptr(char *);
}

int	chdir(const char *pathname) {
	long ret = sys_chdir(pathname);
	WRAPPER_RETval(int);
}

int	rename(const char *oldname, const char *newname) {
	long ret = sys_rename(oldname, newname);
	WRAPPER_RETval(int);
}

int	mkdir(const char *pathname, int mode) {
	long ret = sys_mkdir(pathname, mode);
	WRAPPER_RETval(int);
}

int	rmdir(const char *pathname) {
	long ret = sys_rmdir(pathname);
	WRAPPER_RETval(int);
}

int	creat(const char *pathname, int mode) {
	long ret = sys_creat(pathname, mode);
	WRAPPER_RETval(int);
}

int	link(const char *oldname, const char *newname) {
	long ret = sys_link(oldname, newname);
	WRAPPER_RETval(int);
}

int	unlink(const char *pathname) {
	long ret = sys_unlink(pathname);
	WRAPPER_RETval(int);
}

ssize_t	readlink(const char *path, char *buf, size_t bufsz) {
	long ret = sys_readlink(path, buf, bufsz);
	WRAPPER_RETval(ssize_t);
}

int	chmod(const char *filename, mode_t mode) {
	long ret = sys_chmod(filename, mode);
	WRAPPER_RETval(int);
}

int	chown(const char *filename, uid_t user, gid_t group) {
	long ret = sys_chown(filename, user, group);
	WRAPPER_RETval(int);
}

int	umask(int mask) {
	long ret = sys_umask(mask);
	WRAPPER_RETval(int);
}

int	gettimeofday(struct timeval *tv, struct timezone *tz) {
	long ret = sys_gettimeofday(tv, tz);
	WRAPPER_RETval(int);
}

uid_t	getuid() {
	long ret = sys_getuid();
	WRAPPER_RETval(uid_t);
}

gid_t	getgid() {
	long ret = sys_getgid();
	WRAPPER_RETval(uid_t);
}

int	setuid(uid_t uid) {
	long ret = sys_setuid(uid);
	WRAPPER_RETval(int);
}

int	setgid(gid_t gid) {
	long ret = sys_setgid(gid);
	WRAPPER_RETval(int);
}

uid_t	geteuid() {
	long ret = sys_geteuid();
	WRAPPER_RETval(uid_t);
}

gid_t	getegid() {
	long ret = sys_getegid();
	WRAPPER_RETval(uid_t);
}

// HW3 Implementation
// 1.?  2.?  3.V  4.V  5.V  6.V  7.V  8.?  9.?  10.?  11.V  12.V
// alarm: setup a timer for the current process. V
unsigned int alarm(unsigned int seconds){
    long ret = sys_alarm(seconds);
    WRAPPER_RETval(unsigned int);
}
/*
functions to handle sigset_t data type: sigemptyset, sigfillset,
sigaddset, sigdelset, and sigismember. V
*/
int sigemptyset(sigset_t *set){
	if(set == NULL){
        set_errno(EINVAL);
		return -1;
	}
	memset(set, 0, sizeof(sigset_t));
	return 0;
}
int sigfillset(sigset_t *set){
	if(set == NULL){
        set_errno(EINVAL);
		return -1;
	}
	memset(set, 0xff, sizeof(sigset_t));
	return 0;
}
int sigaddset(sigset_t *set, int signum){
	if(set == NULL || signum <= 0 || signum > 64){
        set_errno(EINVAL);
		return -1;
	}
	set->sig[0] |= sigmask(signum);
	return 0;
}
int sigdelset(sigset_t *set, int signum){
	if(set == NULL || signum <= 0 || signum > 64){
        set_errno(EINVAL);
		return -1;
	}
	set->sig[0] &= ~sigmask(signum);
	return 0;
}
int sigismember(const sigset_t *set, int signum){
	/*
	if(set == NULL || signum <= 0 || signum > 64){
        set_errno(EINVAL);
		return -1;
	}
	*/
	unsigned long sig = signum - 1;
	return 1 & (set->sig[0] >> sig);
}
// sigprocmask: can be used to block/unblock signals, and get/set the current signal mask. V
int sigprocmask(int how, const sigset_t *set, sigset_t *oldset){
	long ret = sys_rt_sigprocmask(how, set, oldset, sizeof(sigset_t));
	WRAPPER_RETval(int);
}
// sigpending: check if there is any pending signal. V
int sigpending(sigset_t *set){
	long ret = sys_rt_sigpending(set, sizeof(sigset_t));
    WRAPPER_RETval(int);
}
// signal and sigaction: setup the handler of a signal. V
sighandler_t signal(int signum, sighandler_t handler){
	if(handler == SIG_ERR || signum < 0 || signum > 64){
        set_errno(EINVAL);
		return SIG_ERR;
	}
	struct sigaction oact, act;
	act.sa_handler = handler;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
    if (signum == SIGALRM){
		act.sa_flags |= SA_INTERRUPT;
	}else{
        act.sa_flags |= SA_RESTART;
	}
	if(sigaction(signum, &act, &oact)  == -1) 
		return SIG_ERR;
	else 
	    return oact.sa_handler;
}
int sigaction(int signum, struct sigaction *act, struct sigaction *oldact){
	act->sa_flags |= SA_RESTORER;
	act->sa_restorer = __myrt;
	long ret = sys_rt_sigaction(signum, act, oldact, sizeof(sigset_t));
	WRAPPER_RETval(int);
}
// write: write to a file descriptor.
ssize_t	write(int fd, const void *buf, size_t count) {
	long ret = sys_write(fd, buf, count);
	WRAPPER_RETval(ssize_t);
}
// pause: wait for signal
int	pause() {
	long ret = sys_pause();
	WRAPPER_RETval(int);
}
// sleep: sleep for a specified number of seconds

// exit: cause normal process termination
void exit(int error_code) {
	sys_exit(error_code);
	/* never returns? */
}

void *memset(void *ptr, int val, size_t num){
	char *src = (char*)ptr;
	while(num--){	
		*src++ = (char)val;
	}
	return ptr;
}

void bzero(void *s, size_t size) {
	char *ptr = (char *) s;
	while(size-- > 0) *ptr++ = '\0';
}
// strlen: calculate the length of the string, excluding the terminating null byte ('\0').
size_t strlen(const char *s) {
	size_t count = 0;
	while(*s != '\0'){
        count++;
		s++;
	}
	return count;
}

#define	PERRMSG_MIN	0
#define	PERRMSG_MAX	34

static const char *errmsg[] = {
	"Success",
	"Operation not permitted",
	"No such file or directory",
	"No such process",
	"Interrupted system call",
	"I/O error",
	"No such device or address",
	"Argument list too long",
	"Exec format error",
	"Bad file number",
	"No child processes",
	"Try again",
	"Out of memory",
	"Permission denied",
	"Bad address",
	"Block device required",
	"Device or resource busy",
	"File exists",
	"Cross-device link",
	"No such device",
	"Not a directory",
	"Is a directory",
	"Invalid argument",
	"File table overflow",
	"Too many open files",
	"Not a typewriter",
	"Text file busy",
	"File too large",
	"No space left on device",
	"Illegal seek",
	"Read-only file system",
	"Too many links",
	"Broken pipe",
	"Math argument out of domain of func",
	"Math result not representable"
};

void perror(const char *prefix) {
	const char *unknown = "Unknown";
	long backup = errno;
	if(prefix) {
		write(2, prefix, strlen(prefix));
		write(2, ": ", 2);
	}
	if(errno < PERRMSG_MIN || errno > PERRMSG_MAX) write(2, unknown, strlen(unknown));
	else write(2, errmsg[backup], strlen(errmsg[backup]));
	write(2, "\n", 1);
	return;
}

#if 0	/* we have an equivalent implementation in assembly */
unsigned int sleep(unsigned int seconds) {
	long ret;
	struct timespec req, rem;
	req.tv_sec = seconds;
	req.tv_nsec = 0;
	ret = sys_nanosleep(&req, &rem);
	if(ret >= 0) return ret;
	if(ret == -EINTR) {
		return rem.tv_sec;
	}
	return 0;
}
#endif
