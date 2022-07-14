#include "ptools.h"
#include "sdb.h"
using namespace std;

#define	PEEKSIZE 8

static vector<instruction1> orig_instructions;
static breakpoint bp_restore = {};

void errquit(const char *msg){ // X
	perror(msg);
	exit(-1);
}

void print_instruction(instruction1 *in){ // M
	int i;
	char bytes[128] = "";
	if(in != NULL){
        for(i = 0; i < in->size; i++) {
			snprintf(&bytes[i*3], 4, "%2.2x ", in->bytes[i]);
		}
		cerr << hex << right << setw(12) << in -> addr << ": "
		     << left << setw(32) << bytes
			 << left << setw(7) << in -> opr
			 << left << setw(7) << in -> opnd << endl;
	}
	else{
        cout << "** cannot disassemble " << hex << right << setw(12) << in -> addr << endl;
	    //fprintf(stderr, "%012llx:\t<cannot disassemble>\n",in-> addr);
	}
}

int disassemble(pid_t pid, csh cshandle, unsigned long long addr){ // ?
	int count;
	char buf[64] = { 0 };
	unsigned long long ptr = addr;
	cs_insn *insn;

	for(ptr = addr; ptr < addr + sizeof(buf); ptr += PEEKSIZE){
		long long peek;
		errno = 0;
		peek = ptrace(PTRACE_PEEKTEXT, pid, ptr, NULL);
		if(errno != 0) break;
		memcpy(&buf[ptr-addr], &peek, PEEKSIZE);
	}

	if((count = cs_disasm(cshandle, (uint8_t*) buf, sizeof(buf)-1, addr, 0, &insn)) > 0){
		instruction1 in;
		in.addr = addr;
		in.size = insn[0].size;
		in.opr  = insn[0].mnemonic;
		in.opnd = insn[0].op_str;
		memcpy(in.bytes, insn[0].bytes, insn[0].size);

		orig_instructions.push_back(in);
		// print_instruction(addr, &in);
		// addr += insn[0].size;
	}
	else{
		cout << "** cs_disasm error." << endl;
		//fprintf(stderr, "** cs_disasm error.\n");
		return -1;
	}	
	cs_free(insn, count);
	return 0;
}

void set_bp(prog_info& info, unsigned long long addr){ // M
	// if(info.entry + info.size <= addr)
	// {
	// 	fprintf(stderr, "** addr out of range\n");
	// 	return;
	// }
	if (info.state != RUNNING){
    	cout << "** state must be RUNNING." << endl;
        return;
    }
	/* get original text*/
	long long code = ptrace(PTRACE_PEEKTEXT, info.pid, addr, NULL);
	unsigned char *ptr = (unsigned char *) &code;
	if(ptrace(PTRACE_POKETEXT, info.pid, addr, (code & 0xffffffffffffff00) | 0xcc) != 0)
		errquit("ptrace(POKETEXT)");
	for(int i = 0; i < (int)info.bp_vec.size(); i++){
        if(info.bp_vec[i].addr == addr)
		    return;
	}
	/* set break point */
	breakpoint bp;
	bp.addr = addr;
	bp.orig_patch = ptr[0];
	info.bp_vec.push_back(bp);
}

void dump(prog_info info, unsigned long long start_addr){ // M
	//dump 80 bytes data
	unsigned long long addr = start_addr;
	unsigned long code1, code2;
    for(int i = 0; i < 5; i++, addr += 16){
        code1 = ptrace(PTRACE_PEEKTEXT, info.pid, addr, 0);
        code2 = ptrace(PTRACE_PEEKTEXT, info.pid, addr + 8, 0);
        cerr << hex << setw(12) << setfill(' ') << right << addr << ": ";
		for(int j = 0; j < 8; j++)
            cerr<<hex<<setw(2)<<setfill('0')<<(int)((unsigned char *) (&code1))[j]<<" ";
        cerr<<setfill(' ');
		for(int j = 0; j < 8; j++)
            cerr<<hex<<setw(2)<<setfill('0')<<(int)((unsigned char *) (&code2))[j]<<" ";
        cerr<<setfill(' ');
        cerr << "|";
		for(int j = 0; j < 8; j++){
            if(isprint((int)((char *) (&code1))[j]))
                cerr<<((char *) (&code1))[j];
            else
                cerr<<".";
        }
		for(int j = 0; j < 8; j++){
            if(isprint((int)((char *) (&code2))[j]))
                cerr<<((char *) (&code2))[j];
            else
                cerr<<".";
        }
        cerr << "|\n";
    }
}

void cont(prog_info& info){ // m
	int status;
	if (info.state != RUNNING){
        cout << "** state must be RUNNING." << endl;
		//fprintf(stderr, "** state must be RUNNING.\n");
        return;
    }
	struct user_regs_struct regs_struct;

	// firstly, check if need to restore breakpoint 
	if(ptrace(PTRACE_GETREGS, info.pid, NULL, &regs_struct) != 0)
		errquit("ptrace(PTRACE_GETREGS)");
	
	if(regs_struct.rip == bp_restore.addr){	
		// restore the orig patch and rip
		long long code = ptrace(PTRACE_PEEKTEXT, info.pid, bp_restore.addr, NULL);
		if(ptrace(PTRACE_POKETEXT, info.pid, bp_restore.addr, (code & 0xffffffffffffff00) | bp_restore.orig_patch) != 0)
			errquit("ptrace(POKETEXT)");
		// regs_struct.rip = regs_struct.rip-1;
		// if(ptrace(PTRACE_SETREGS, info.pid, 0, &regs_struct) != 0) errquit("ptrace(SETREGS)");

		// single step
		if(ptrace(PTRACE_SINGLESTEP, info.pid, 0, 0) < 0) errquit("ptrace@SINGLESTEP");
		if(waitpid(info.pid, &status, 0) < 0) errquit("waitpid");

		// set break point 
		if(ptrace(PTRACE_POKETEXT, info.pid, bp_restore.addr, (code & 0xffffffffffffff00) | 0xcc) != 0)
			errquit("ptrace(POKETEXT)");
		
		bp_restore={};
	}
    
    ptrace(PTRACE_CONT, info.pid, 0, 0);

	waitpid(info.pid, &status, 0);
    if (WIFEXITED(status)){
		if (WIFSIGNALED(status))
		    cout << "** child process " << dec << info.pid << " terminated by signal (code " << WTERMSIG(status) << ")" << endl;
		else
			cout << "** child process " << dec << info.pid << " terminated normally (code" << status << ")" << endl;
		info.pid = 0;
		//info = {};
		info.state = LOADED;
		//info.state = NOLOAD;
	}
	if(WIFSTOPPED(status)){
		if(ptrace(PTRACE_GETREGS, info.pid, NULL, &regs_struct) != 0)
			errquit("ptrace(PTRACE_GETREGS)");
		// check if stop by breakpoint
		for(auto & it : info.bp_vec){
			if(it.addr == regs_struct.rip-1){
				fprintf(stderr, "** breakpoint @\t");
				// find and print disasm addr in orig_instructions
				for(long unsigned int i=0;i<orig_instructions.size();i++){
					if(orig_instructions[i].addr == it.addr){
						print_instruction(&orig_instructions[i]);
						bp_restore.addr = it.addr;
						bp_restore.orig_patch = it.orig_patch;

						regs_struct.rip = regs_struct.rip-1;
						if(ptrace(PTRACE_SETREGS, info.pid, 0, &regs_struct) != 0) errquit("ptrace(SETREGS)");
						return;
					}
				}
			}
		}
	}
}

void del_bp(prog_info& info, int idx){ // M
	if(idx >= (int)info.bp_vec.size()){
        cout << "** Not found index: " << idx << " breakpoint." << endl;
	}
	else{
		// restore the orig patch
		long long code = ptrace(PTRACE_PEEKTEXT, info.pid, (info.bp_vec.begin()+idx)->addr, NULL);
		if(ptrace(PTRACE_POKETEXT, info.pid, (info.bp_vec.begin()+idx)->addr, (code & 0xffffffffffffff00) | (info.bp_vec.begin()+idx)->orig_patch) != 0)
			errquit("ptrace(POKETEXT)");
		
		cout << "** breakpoint @ 0x" << hex << (info.bp_vec.begin() + idx)->addr << " deleted." << endl;
		info.bp_vec.erase(info.bp_vec.begin() + idx);
		if(bp_restore.addr == (info.bp_vec.begin() + idx)->addr)
		    bp_restore = {};
	}
}

void disasm(prog_info& info, unsigned long long addr){ // M
	if (info.state != RUNNING){
        fprintf(stderr, "** state must be RUNNING.\n");
        return;
    }
	csh cshandle;
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &cshandle) != CS_ERR_OK){
       	fprintf(stderr, "** cs_open error.\n");
        return;
    }
	int idx = -1;
	vector<instruction1>::iterator it;
    for(it = orig_instructions.begin(); it != orig_instructions.end(); it++){
		idx++;
		if(it -> addr == addr)
			break;
	}
	if(idx == (int)orig_instructions.size()){
        cout << "** error addr given." << endl;
		return;
	}
	for(int i = idx; i < idx + 10; i++){
		if(i >= (int)orig_instructions.size())
			break;
		print_instruction(&orig_instructions[i]);
	}
}

void quit(prog_info info){ // X
	exit(0);
}

void print_reg(const prog_info info, string reg){ // M
	if (info.state != RUNNING){
        cout << "** state must be RUNNING." << endl;
        return;
    }
    unsigned long long val;
	struct user_regs_struct regs_struct;
	if(ptrace(PTRACE_GETREGS, info.pid, NULL, &regs_struct) != 0)
		errquit("ptrace(PTRACE_GETREGS)");
	if(reg=="rax")      val = regs_struct.rax;
    else if(reg=="rbx") val = regs_struct.rbx;
    else if(reg=="rcx") val = regs_struct.rcx;
    else if(reg=="rdx") val = regs_struct.rdx;
    else if(reg=="r8")  val = regs_struct.r8;
    else if(reg=="r9")  val = regs_struct.r9;
    else if(reg=="r10") val = regs_struct.r10;
    else if(reg=="r11") val = regs_struct.r11;
    else if(reg=="r12") val = regs_struct.r12;
    else if(reg=="r13") val = regs_struct.r13;
    else if(reg=="r14") val = regs_struct.r14;
    else if(reg=="r15") val = regs_struct.r15;
    else if(reg=="rdi") val = regs_struct.rdi;
    else if(reg=="rsi") val = regs_struct.rsi;
    else if(reg=="rbp") val = regs_struct.rbp;
    else if(reg=="rsp") val = regs_struct.rsp;
    else if(reg=="rip") val = regs_struct.rip;
    else if(reg=="flags") val = regs_struct.eflags;
    else{
        cout << "** " << reg << " not found." << endl;
        return;
    }
    cerr<<reg<<" = "<<dec<<val<<" (0x"<<hex<<val<<")\n";
}

void print_all_regs(const prog_info info){ // M
	if (info.state != RUNNING){
        cout << "** state must be RUNNING." << endl;
        return;
    }

	struct user_regs_struct regs_struct;
	if(ptrace(PTRACE_GETREGS, info.pid, NULL, &regs_struct) != 0)
		errquit("ptrace(PTRACE_GETREGS)");
	// print all regs
	unsigned long long int *ptr = (unsigned long long int *) &regs_struct;
    cerr<< hex
        << left << setw(4) << "RAX " << left << setw(18) << ptr[10] << "\t"
        << left << setw(4) << "RBX " << left << setw(18) << ptr[4] << "\t"
        << left << setw(4) << "RCX " << left << setw(18) << ptr[11] << "\t"
        << left << setw(4) << "RDX " << left << setw(18) << ptr[12] << endl;
    cerr<< left << setw(4) << "R8 "  << left << setw(18) << ptr[9] << "\t"
        << left << setw(4) << "R9 "  << left << setw(18) << ptr[8] << "\t"
        << left << setw(4) << "R10 " << left << setw(18) << ptr[7] << "\t"
        << left << setw(4) << "R11 " << left << setw(18) << ptr[6] << endl;
    cerr<< left << setw(4) << "R12 " << left << setw(18) << ptr[3] << "\t"
        << left << setw(4) << "R13 " << left << setw(18) << ptr[2] << "\t"
        << left << setw(4) << "R14 " << left << setw(18) << ptr[1] << "\t"
        << left << setw(4) << "R15 " << left << setw(18) << ptr[0] << endl;
    cerr<< left << setw(4) << "RDI " << left << setw(18) << ptr[14] << "\t"
        << left << setw(4) << "RSI " << left << setw(18) << ptr[13] << "\t"
        << left << setw(4) << "RBP " << left << setw(18) << ptr[4] << "\t"
        << left << setw(4) << "RSP " << left << setw(18) << ptr[19] << endl;
    cerr<< left << setw(4) << "RIP " << left << setw(18) << ptr[16] <<"\t"
        << left << setw(6) << "FLAGS " << left << setw(16) << setfill('0') << right << ptr[18] << endl;
    cerr<<setfill(' ');
}

void help(){ // M
    cerr << "- break {instruction-address}: add a break point" << endl;
    cerr << "- cont: continue execution" << endl;
    cerr << "- delete {break-point-id}: remove a break point" << endl;
    cerr << "- disasm addr: disassemble instructions in a file or a memory region" << endl;
    cerr << "- dump addr: dump memory content" << endl;
    cerr << "- exit: terminate the debugger" << endl;
    cerr << "- get reg: get a single value from a register" << endl;
    cerr << "- getregs: show registers" << endl;
    cerr << "- help: show this message" << endl;
    cerr << "- list: list break points" << endl;
    cerr << "- load {path/to/a/program}: load a program" << endl;
    cerr << "- run: run the program" << endl;
    cerr << "- vmmap: show memory layout" << endl;
    cerr << "- set reg val: get a single value to a register" << endl;
    cerr << "- si: step into instruction" << endl;
    cerr << "- start: start the program and stop at the first instruction" << endl;
}

void list(const prog_info info){ // M
	if(!info.bp_vec.empty()){
		for(long unsigned int i=0; i<info.bp_vec.size(); i++){
			cerr << i << ": " << hex << info.bp_vec[i].addr << endl;
		}
	}
	else
		cerr << "** No breakpoint." << endl;
}

void load(prog_info& info, string path){ // M
	if(info.state != NOLOAD){
		cout << "** the state is already LOADED." << endl;
		return;
	}
    FILE *fp;
	Elf64_Ehdr elf_header;
	if((fp = fopen(path.c_str(),"r")) == NULL){ 
		cout << "** Unable to open '" << path << "': " << strerror(errno) << endl;
		exit(-1);
	}
	if(fread(&elf_header, sizeof(Elf64_Ehdr), 1, fp) != 1){
		cout << "** fread: " << strerror(errno) << endl;
		//fprintf(stderr, "** fread: %s\n", strerror(errno));
		fclose(fp);
		exit(-1);
	}
	if(elf_header.e_ident[0] == 0x7F || elf_header.e_ident[1] == 'E'){
		int temp, shnum;
		Elf64_Shdr *shdr = (Elf64_Shdr*)malloc(sizeof(Elf64_Shdr) * elf_header.e_shnum);
		temp = fseek(fp, elf_header.e_shoff, SEEK_SET);
		temp = fread(shdr, sizeof(Elf64_Shdr) * elf_header.e_shnum, 1, fp);
		rewind(fp);
		fseek(fp, shdr[elf_header.e_shstrndx].sh_offset, SEEK_SET);
		char shstrtab[shdr[elf_header.e_shstrndx].sh_size];
		char *names = shstrtab;
		temp = fread(shstrtab, shdr[elf_header.e_shstrndx].sh_size, 1, fp);
		// printf("Type\tAddr\tOffsset\tSize\tName\n");
		for(shnum = 0; shnum < elf_header.e_shnum; shnum++){
			names = shstrtab;
			names=names+shdr[shnum].sh_name;
			if(strcmp(names,".text")==0){
				info.entry = elf_header.e_entry;
				info.size = shdr[shnum].sh_size;
				// printf("%x\t%x\t%x\t%x\t%s \n",shdr[shnum].sh_type,shdr[shnum].sh_addr,shdr[shnum].sh_offset,shdr[shnum].sh_size,names);
			}
		}
	}
	cout << "** program '" << path << "' loaded. entry point 0x" << hex << info.entry << endl;
	info.state = LOADED;
	info.path = path;
}

void run(prog_info& info){ // M
	if (info.state == RUNNING){
		cout << "** program '" << info.path << "' is already running." << endl;
		cont(info);
    }
    else if (info.state == LOADED){
        start(info);
        cont(info);
    }
    else{
		cout << "** state must be LOADED ro RUNNING." << endl;
    }
}

void vmmap(const prog_info info){ // M
	if(info.state != RUNNING){
		cout << "** state must be running!" << endl;
		return;
	}
    //char fn[128];
	char *line, *token;
	string dir = "/proc/" + to_string(info.pid) + "/maps";
	size_t len;
	FILE *fp;
	//snprintf(fn, sizeof(fn), "/proc/%u/maps", info.pid);
	if((fp = fopen(dir.c_str(), "rt")) == NULL){
        cout << "** cannot load memory mappings." << endl;
		//fprintf(stderr, "** cannot load memory mappings.\n");
		return;
	}
	while(getline(&line, &len, fp) != EOF){
		if((token = strtok(line, "-")) != NULL)     // 00600000 address
			cerr << setw(16) << setfill('0') << right << string(token) << "-";
		if((token = strtok(NULL, " ")) != NULL)     // 00601000 address
            cerr << setw(16) << setfill('0') << right << string(token) << " ";
        if((token = strtok(NULL, " p")) != NULL)    // rw-p     perms
            cerr << setfill(' ') << string(token) << " ";
        token = strtok(NULL, " ");                // 00000000 offset
        token = strtok(NULL, " ");                // 08:02    dev
        if((token = strtok(NULL, " ")) != NULL)       // 2622929  inode
            cerr << setw(9) << left << string(token);           
        if((token = strtok(NULL, " ")) != NULL)     // /home/unix110/hw4/sample/hello64    pathname
            cerr << string(token);
	}
}

void set(prog_info& info, string reg, long long val){ // M
	if(info.state != RUNNING){
		cout << "** program must be RUNNING." << endl;
		return;
	}

	struct user_regs_struct regs_struct;
	if(ptrace(PTRACE_GETREGS, info.pid, NULL, &regs_struct) != 0)
		errquit("ptrace(PTRACE_GETREGS)");
	if(reg=="rax")      regs_struct.rax = val;
    else if(reg=="rbx") regs_struct.rbx = val;
    else if(reg=="rcx") regs_struct.rcx = val;
    else if(reg=="rdx") regs_struct.rdx = val;
    else if(reg=="r8")  regs_struct.r8 = val;
    else if(reg=="r9")  regs_struct.r9 = val;
    else if(reg=="r10") regs_struct.r10 = val;
    else if(reg=="r11") regs_struct.r11 = val;
    else if(reg=="r12") regs_struct.r12 = val;
    else if(reg=="r13") regs_struct.r13 = val;
    else if(reg=="r14") regs_struct.r14 = val;
    else if(reg=="r15") regs_struct.r15 = val;
    else if(reg=="rdi") regs_struct.rdi = val;
    else if(reg=="rsi") regs_struct.rsi = val;
    else if(reg=="rbp") regs_struct.rbp = val;
    else if(reg=="rsp") regs_struct.rsp = val;
    else if(reg=="rip") regs_struct.rip = val;
    else if(reg=="flags") regs_struct.eflags = val;
    else    cout << "** " << reg << " not found." << endl;
	
	ptrace(PTRACE_SETREGS, info.pid, NULL, &regs_struct);
}

void si(const prog_info& info){ // M
	int status;
	if(info.state!=RUNNING){
		fprintf(stderr,  "** state must be RUNNING.\n");
		return;
	}

	struct user_regs_struct regs_struct;
	if(ptrace(PTRACE_GETREGS, info.pid, NULL, &regs_struct) != 0)
		errquit("ptrace(PTRACE_GETREGS)");
	if(regs_struct.rip == bp_restore.addr){	
		long long code = ptrace(PTRACE_PEEKTEXT, info.pid, bp_restore.addr, NULL);
		if(ptrace(PTRACE_POKETEXT, info.pid, bp_restore.addr, (code & 0xffffffffffffff00) | bp_restore.orig_patch) != 0)
			errquit("ptrace(POKETEXT)");
		if(ptrace(PTRACE_SINGLESTEP, info.pid, 0, 0) < 0) errquit("ptrace@SINGLESTEP");
		if(waitpid(info.pid, &status, 0) < 0) errquit("waitpid");

		if(ptrace(PTRACE_POKETEXT, info.pid, bp_restore.addr, (code & 0xffffffffffffff00) | 0xcc) != 0)
			errquit("ptrace(POKETEXT)");
		
		bp_restore={};
	}

	if(ptrace(PTRACE_SINGLESTEP, info.pid, 0, 0) < 0) errquit("ptrace@SINGLESTEP");
	
	waitpid(info.pid, &status, 0);
    if (WIFEXITED(status)){
		if (WIFSIGNALED(status))
		    cout << "** child process " << dec << info.pid << " terminated by signal (code " << WTERMSIG(status) << ")" << endl;
		else
			cout << "** child process " << dec << info.pid << " terminated normally (code" << status << ")" << endl;
	}
	if(WIFSTOPPED(status)){
		if(ptrace(PTRACE_GETREGS, info.pid, NULL, &regs_struct) != 0)
			errquit("ptrace(PTRACE_GETREGS)");
		// check if stop by breakpoint
		for(auto & it : info.bp_vec){
			if(it.addr == regs_struct.rip-1){
				fprintf(stderr, "** breakpoint @\t");
				// find and print disasm addr in orig_instructions
				for(long unsigned int i=0;i<orig_instructions.size();i++){
					if(orig_instructions[i].addr == it.addr){
						print_instruction(&orig_instructions[i]);
						bp_restore.addr = it.addr;
						bp_restore.orig_patch = it.orig_patch;

						regs_struct.rip = regs_struct.rip-1;
						if(ptrace(PTRACE_SETREGS, info.pid, 0, &regs_struct) != 0) errquit("ptrace(SETREGS)");
						return;
					}
				}
			}
		}
	}
}

void start(prog_info& info){ // M
	pid_t child;
	if (info.state != LOADED){
		cout << "** state is not LOADED." << endl;
        //fprintf(stderr,  "** state must be LOADED.\n");
		return;
    }
	if(info.state == RUNNING){
		cerr << "** program '" << info.pid << "' is already running." << endl;
		//fprintf(stderr,  "** program '%d' is already running.\n", info.pid);
		return;
	}
	// fork
	if((child = fork()) < 0) errquit("** fork error");
	else if(child == 0){
		if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) errquit("** ptrace error");
		execlp(info.path.c_str(), info.path.c_str(), NULL);
		errquit("** execvp error");
	}
	else{
		int status;
		if(waitpid(child, &status, 0) < 0) errquit("** waitpid error");
		assert(WIFSTOPPED(status));
		ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);

		cout << "** pid " << dec << child << endl;
		info.state = RUNNING;
		info.pid = child;
		//get_orig_code(info);
		csh cshandle;
	    if (cs_open(CS_ARCH_X86, CS_MODE_64, &cshandle) != CS_ERR_OK){
       	    cout << "** cs_open error." << endl;
            return;
        }
	    cs_option(cshandle, CS_OPT_DETAIL, CS_OPT_ON);
	    cs_option(cshandle, CS_OPT_SKIPDATA, CS_OPT_ON);

	    unsigned long long addr = info.entry;
	    while(addr < info.entry+info.size){
		    int dis = disassemble(info.pid, cshandle, addr);
		    if(dis == -1)
			    return;
		    addr += orig_instructions[orig_instructions.size()-1].size;
	    }
	}
}

int main(int argc, char *argv[]){ // M
	int cmd_opt = 0;
	bool ifprint = false;
	string arg_script;
	string arg_prog;
	prog_info info;
	FILE *fp;

	while((cmd_opt = getopt(argc, argv, "s:")) != -1){
		switch(cmd_opt){
			case 's':
				arg_script = optarg;
				if((fp = freopen(arg_script.c_str(), "r", stdin)) == NULL)
					exit(-1);
				ifprint = true;
				break;
			case '?':
				help();
				return -1;
		}
	}
	
	if(argc > optind){
		arg_prog = argv[optind];
		load(info, arg_prog);
	}

	string line;
	if(!ifprint)
		cout << "sdb> ";
	while(getline(cin, line)){
		vector<string> input;
		int current = 0;
        int next = 0;
        while(next != -1){
            next = line.find_first_of(" ", current);
            if(next != current){
                string tmp = line.substr(current, next - current);
                if(!tmp.empty()){
                    input.push_back(tmp);
                }
            }
            current = next + 1;
        }

		if(input.empty()) continue;
		string cmd = input[0];
		// fprintf(stderr, "cmd: %s\n", cmd.c_str());
		if(cmd == "break"|| cmd == "b"){
			if(input.size()>=2)
				set_bp(info, stoull(input[1], NULL, 16));
			else
				cout << "** no addr given." << endl;
		}
		else if(cmd == "cont" || cmd == "c"){
			cont(info);
		}
		else if(cmd == "delete"){
			del_bp(info, stoi(input[1]));
		}
		else if(cmd == "disasm" || cmd == "d"){
			if(input.size()>=2)
				disasm(info, stoull(input[1], NULL, 16));
			else
				cout << "** no addr given." << endl;
		}
		else if(cmd == "dump" || cmd == "x"){
			if(input.size()>=2)
				dump(info, stoull(input[1], NULL, 16));
			else
				cout << "** no addr given." << endl;
		}
		else if(cmd == "exit" || cmd == "q"){
			quit(info);
		}
		else if(cmd == "get" || cmd == "g"){
			print_reg(info, input[1]);
		}
		else if(cmd == "getregs"){	
			print_all_regs(info);
		}
		else if(cmd == "help" || cmd == "h"){
			help();
		}
		else if(cmd == "list" || cmd == "l"){
			list(info);
		}
		else if(cmd == "load"){
			// fprintf(stderr, "load\n");
			load(info, input[1]);
		}
		else if(cmd == "run" || cmd == "r"){
			run(info);
		}
		else if(cmd == "vmmap" || cmd == "m"){
			vmmap(info);
		}
		else if(cmd == "set"){
			if(input.size()>=3)
				set(info, input[1], stol(input[2], NULL, 16));
			else
				cout << "** input error." << endl;
		}
		else if(cmd == "si"){
			si(info);
		}
		else if(cmd == "start"){
			// fprintf(stderr, "start\n");
			start(info);
		}
		else{
			cout << "error command!" << endl;
		}
		if(!ifprint)
			cout << "sdb> ";
		
	}
	return 0;
}