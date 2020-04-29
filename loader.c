/*
 * Loader Implementation
 * 2018, Operating Systems
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include "exec_parser.h"
#include "utils.h"

static so_exec_t *exec;
static struct sigaction old_action;
static int file_descriptor;
static int page_size;

int init(char **mem_addr, char **file_addr, char *fault_addr, int i)
{
	*mem_addr = (char *)exec->segments[i].vaddr + exec->segments[i].mem_size;
	*file_addr = (char *)exec->segments[i].vaddr + exec->segments[i].file_size;
		 
	return (fault_addr - (char *)exec->segments[i].vaddr) / page_size;
}
char* map_address(char *aligned_addr, unsigned int flags, int i, int pages)
{
	char *mapped_addr;

	off_t offset = exec->segments[i].offset + pages * page_size;
	mapped_addr = mmap(aligned_addr,
				page_size,
				PROT_READ | PROT_EXEC | PROT_WRITE,
				flags,
				file_descriptor,
				offset);
	DIE(mapped_addr == MAP_FAILED, "mmap");

	return mapped_addr;	
}

char* read_page(char *mapped_addr, int i, int pages, int length)
{
	off_t offset = exec->segments[i].offset + pages * page_size;

	lseek(file_descriptor, offset, SEEK_SET);
	read(file_descriptor, mapped_addr, length);

	return mapped_addr;
}

void set_permissions(char **mapped_addr, int i)
{
	int ret = mprotect(*mapped_addr, page_size, exec->segments[i].perm);
	DIE(ret == -1, "mprotect");
}

static void segv_handler(int signum, siginfo_t *info, void *context)
{

	if (signum != SIGSEGV) {
		old_action.sa_sigaction(signum, info, context);
		return;
	}
	
	int i = 0;
	int out_of_segment = 0;
	char *fault_addr = (char *)info->si_addr;
	
	//iterate segments
	do {
		char *mem_addr, *file_addr;

		int pages = init(&mem_addr, &file_addr, fault_addr, i);
		
		if (mem_addr < fault_addr) {
			out_of_segment++;
		} 
		if (mem_addr >= fault_addr) {
			// address not mapped
			if (info->si_code == SEGV_MAPERR) {
				//align memory to be mapped
				char *aligned_addr = (char *)ALIGN_DOWN((uintptr_t)fault_addr, page_size);
				char *mapped_addr;

				if (fault_addr <  mem_addr && fault_addr > file_addr)
					mapped_addr = map_address(aligned_addr, 
									MAP_FIXED | MAP_PRIVATE,
									i,
									pages);

				if (fault_addr >=  mem_addr || fault_addr <= file_addr)
					mapped_addr = map_address(aligned_addr,
									MAP_ANONYMOUS | MAP_PRIVATE,
									i,
									pages);
				//assure zeroed memory 
				memset(mapped_addr, 0, page_size);

				if (aligned_addr < file_addr
					&& exec->segments[i].file_size < exec->segments[i].mem_size
					&& aligned_addr + page_size > file_addr) {
						int length = file_addr - aligned_addr;

						mapped_addr = read_page(mapped_addr,
										i,
										pages,
										length);
				} 
				if (exec->segments[i].file_size >= exec->segments[i].mem_size
					|| aligned_addr + page_size <= file_addr) 
					mapped_addr = read_page(mapped_addr,
									i,
									pages,
									page_size);					

				set_permissions(&mapped_addr, i); //mapped memory -> set permissions
			}
			// seg fault and mapped => invalid permissions => default handler
			if(info->si_code == SEGV_ACCERR)
				old_action.sa_sigaction(signum, info, context);

		}
		// address is outside any segment => default handler
		if (out_of_segment == exec->segments_no)
			old_action.sa_sigaction(signum, info, context);
		++i;
	} while (i < exec->segments_no);
}

int so_init_loader(void)
{
	struct sigaction action;
	int rc;

	page_size = getpagesize();

	action.sa_sigaction = segv_handler;
	sigemptyset(&action.sa_mask);
	sigaddset(&action.sa_mask, SIGSEGV);
	action.sa_flags = SA_SIGINFO;

	rc = sigaction(SIGSEGV, &action, &old_action);
	DIE(rc == -1, "sigaction");
	return -1;
}


int so_execute(char *path, char *argv[])
{
	// needed by mmap
	file_descriptor = open(path, O_RDWR);
	DIE(file_descriptor == -1, "open");
	exec = so_parse_exec(path);
	if (!exec)
		return -1;

	so_start_exec(exec, argv);

	return -1;
}

