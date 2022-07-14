#ifndef __SDB_H__
#define __SDB_H__
#include <iostream>
#include <iomanip>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <string.h>
#include <vector>
#include <sys/stat.h>
#include <capstone/capstone.h>
#include <algorithm>

#include "ptools.h"

using namespace std;

#define NOLOAD  0
#define LOADED  1
#define RUNNING 2

class instruction1 {
public:
	unsigned long long addr;
	unsigned char bytes[16];
	int size;
	string opr, opnd;
};

struct breakpoint {
	unsigned long long addr;
	unsigned char orig_patch; // byte data before patch to 0xcc
};

struct prog_info
{
	int state = NOLOAD;
	pid_t pid;
	unsigned long long entry; // entry point
	unsigned long long size;
	std::string path;
	vector<breakpoint> bp_vec;
};

void errquit(const char *msg);
vector<string> splitStr2Vec(string s, string splitSep);
void print_instruction(long long addr, instruction1 *in);
void disassemble(pid_t proc, csh cshandle, unsigned long long rip, const char *module);
void set_bp(vector<breakpoint>& bp_vec, prog_info info, unsigned long long addr);
void cont(prog_info& info);
void del_bp(prog_info& info, int idx);
int disassemble(pid_t pid, csh cshandle, unsigned long long addr);
void dump(prog_info info, long long start_addr);
void quit(prog_info info);
void print_reg(const prog_info info, string reg);
void print_all_regs(const prog_info info);
void help();
void list(const prog_info info);
void load(prog_info& info, string path);
void run(prog_info& info);
void vmmap(const prog_info info);
void set(prog_info& info, string reg, long long val);
void si(const prog_info& info);
void start(prog_info& info);

#endif /* __SDB_H__ */
