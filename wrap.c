/*
 * Copyright 2012 Iain Bullard <iain.bullard@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sub license,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the
 * next paragraph) shall be included in all copies or substantial portions
 * of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Based on code from lima driver wrapper by Luc Verhaegen <libv@codethink.co.uk>
 * and libsegfault by Jerome Glisse <j.glisse@gmail.com>
 */

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <string.h>
#include <signal.h>
#include <ucontext.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <pthread.h>

#include "wrap.h"
#include "log.h"
#include "mappings.h"
#include "instructions.h"
#include "libve.h"
#include "wrap_libve.h"

static pthread_mutex_t serializer[1] = { PTHREAD_MUTEX_INITIALIZER };

/*
 * functions for locking
 */ 
static inline void serialized_start(const char *func)
{
	pthread_mutex_lock(serializer);
}

static inline void serialized_stop(void)
{
	pthread_mutex_unlock(serializer);
}

/*
 * Wrap around the libc calls that are crucial for capturing our
 * command stream, namely, open, ioctl, and mmap.
 */
static void *libc_dl;

static int initalised = 0;
static instruction_info_t *ins_info;

static int
libc_dlopen(void)
{
	libc_dl = dlopen("libc.so.6", RTLD_NOW);
    
	if (!libc_dl) {
		printf("Failed to dlopen %s: %s\n",
		       "libc.so", dlerror());
		exit(-1);
	}

	return 0;
}

static void *
libc_dlsym(const char *name)
{
	void *func;

	if (!libc_dl)
		libc_dlopen();

	func = dlsym(libc_dl, name);

	if (!func) {
		printf("Failed to find %s in %s: %s\n",
		       name, "libc.so", dlerror());
		exit(-1);
	}

	return func;
}

/*
 * wrap open, catch opening /dev/cedar_dev
 */
static int (*orig_open)(const char* path, int mode, ...);

int
open(const char* path, int flags, int mode,...)
{
	int ret;

    serialized_start(__func__);
 
    if (!orig_open) {
        orig_open = libc_dlsym(__func__);
        wrap_init();
    }

    ret = orig_open(path,flags,mode);

	if (!strcmp(path, "/dev/cedar_dev")) {
        // trace this open call and follow the fd returned by open
        mappings_trace_fd(ret);
        wrap_log("func\topen\tfd:%d\n",ret);
	} 

    serialized_stop();

    return ret;
}

/*
 * wrap ioctl
 */
static int (*orig_ioctl)(int fd, unsigned long int request, ...);

int
ioctl(int fd, unsigned long int request, ...)
{
	int ret,trace;

	serialized_start(__func__);

	if (!orig_ioctl)
		orig_ioctl = libc_dlsym(__func__);
    
    trace = mappings_is_fd_traced(fd);

    va_list args;
    void *ptr;

    va_start(args, request);
    ptr = va_arg(args, void *);
    va_end(args);

    if (trace == 1) {
        ret = orig_ioctl(fd, request, ptr);
        wrap_log("func\tioctl\t0x%03x\t0x%08x\t0x%08x\n",request,ptr,ret);
	} else {
        ret = orig_ioctl(fd, request, ptr);
    }

	serialized_stop();

	return ret;
}

/*
 * wrap mmap
 */
void *(*orig_mmap)(void *addr, size_t length, int prot,
		   int flags, int fd, off_t offset);

void *
mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
	void *ret_addr;
    int trace = 0;
    int regs = 0;
    int only_regs = 0;
    int id;

    serialized_start(__func__);

	if (!orig_mmap) {
		orig_mmap = libc_dlsym(__func__);
    }

    /* catch all mmaps against /dev/cedar_dev */
    trace = mappings_is_fd_traced(fd);

    /* don't trace if its not regs and only_regs is 1 */
    if (offset != special_offset && only_regs == 1) {
        trace = 0;
    }

    if (trace == 1) {
        /* tracking this mmap call */
        if (offset == special_offset) {
            regs = 1;
        }

        ret_addr = orig_mmap(addr, length, PROT_NONE, flags, fd, offset);
        mappings_trace_mmap((uint32_t) ret_addr,offset,length,regs);
        id = mappings_get_id((uint32_t) ret_addr); 
        wrap_log("func\tmmap\t%d\taddr:0x%08x\tlen:0x%08x\tflags:%d\tfd:%d\toffset:0x%08x\tto:0x%08x\n",id,addr,length,flags,fd,offset,ret_addr);
    } else {
        ret_addr = orig_mmap(addr, length, prot, flags, fd, offset);
    }

    serialized_stop();

	return ret_addr;
}
/*
 * wrap memcpy
 */

void *(*orig_memcpy)(void *dest, const void *src, size_t n);

void *memcpy(void *dest, const void *src, size_t n)
{

    void *result;
    uint32_t dest_32 = (uint32_t) dest;
    uint32_t src_32  = (uint32_t) src;

    int dest_id,src_id,traced;
    uint32_t dest_base,dest_phy,src_base,src_phy;

	if (!orig_memcpy) {
		orig_memcpy = libc_dlsym(__func__);
    }

    if (initalised == 1) {
        dest_id = mappings_get_id(dest_32);
        src_id  = mappings_get_id(src_32);
        if (dest_id != 0 || src_id != 0) {
            traced = 1;
            if (dest_id != 0) {
                //mappings_unprotect_mapping(dest_32);
                dest_base = mappings_addr_to_base(dest_32);
                dest_phy  = mappings_addr_to_phys(dest_32);
            } else {
                dest_base = 0xFFFFFFFF;
                dest_phy  = 0xFFFFFFFF;
            }
           

            if (src_id != 0 ) { 
                //mappings_unprotect_mapping(src_32);
                src_base = mappings_addr_to_base(src_32);
                src_phy  = mappings_addr_to_phys(src_32);
            } else {
                src_base = 0xFFFFFFFF;
                src_phy  = 0xFFFFFFFF;
            }
            wrap_log("func\tmemcpy\tsrc\t%d\t0x%08x\t0x%08x\tdest\t%d\t0x%08x\t0x%08x\t0x%08x\n",src_id,src_phy,src_base,dest_id,dest_phy,dest_base,n);
        }
    }
    result = orig_memcpy(dest,src,n);
    if (initalised == 1 && traced == 1) {
        //hexdump(dest,n);
        if (dest_id != 0) {
            //mappings_protect_mapping(dest_32);
        }

        if (src_id != 0) {
           // mappings_protect_mapping(src_32);
        }
    }

    return result;
}

/*
 * wrap memset
 */

void *(*orig_memset)(void *s, int c, size_t n);

void *memset(void *s, int c, size_t n)
{
    void *result;
    uint32_t id,dest_addr,dest_base,dest_phy,traced;

    dest_addr = (uint32_t) s;
    
	if (!orig_memset) {
		orig_memset = libc_dlsym(__func__);
    }

    if (initalised == 1) {
        id = mappings_get_id(dest_addr);

        if (id != 0) { 
            serialized_start(__func__);
            traced = 1;
            dest_base = mappings_addr_to_base(dest_addr);
            dest_phy  = mappings_addr_to_phys(dest_addr);
            mappings_unprotect_mapping(dest_addr);
            wrap_log("func\tmemset\t%d\t0x%08x\t0x%08x\t0x%08x\t0x%08x\n",id,dest_phy,dest_base,c, n);
        } else {
            traced = 0;
        }
    }

    result = orig_memset(s,c,n);

    if (initalised == 1 && traced == 1) {
        serialized_stop();
        mappings_protect_mapping(dest_addr);
    }

    return result;
}

/*
 * wrap signal
 */
__sighandler_t (*orig_signal)(int signum, __sighandler_t handler);

__sighandler_t signal(int signum, __sighandler_t handler) 
{
	if (!orig_signal) {
		orig_signal = libc_dlsym(__func__);
    }

    if (signum == SIGSEGV) {
        //wrap_log("signal(SIGSEGV, ...) intercepted [%d]\n", getpid());
        return 0;
    }
    return orig_signal(signum,handler);

}

/*
 * tracing signal handler for segfaults
 */
void trace_sighandler(int sig, siginfo_t *info, void *ptr) 
{

    serialized_start(__func__);

    int i;

    uint32_t fault_address;
    uint32_t* instruction_addr;
    uint32_t instruction;

    uint32_t id,from_base,phys_addr,virt_addr;
    
     
    ucontext_t *uc = (ucontext_t *)ptr;
    fault_address = (uint32_t) info->si_addr;
    instruction_addr = (uint32_t*) uc->uc_mcontext.arm_pc;
    instruction = (uint32_t) *instruction_addr;

    if (!mappings_is_addr_traced(fault_address)) {
        wrap_log("trace_sighandler 0x%08x is not an address we are tracing\n",fault_address);
        wrap_log("trace_sighandler instruction addr: 0x%08x\n", uc->uc_mcontext.arm_pc);
        wrap_log("trace_sighandler\t0x%08x\n",instruction);
        serialized_stop();
        exit(1);
    }

    // set number of memory transfers to zero.   
    ins_info->count = 0; 

    mappings_unprotect_mapping(fault_address);

    handle_instruction(instruction,fault_address,uc,ins_info);

    mappings_protect_mapping(fault_address);

    for (i=0;i < ins_info->count ; i++ ) {
        virt_addr = ins_info->data[i].address;
        id        = mappings_get_id(virt_addr);
        from_base = mappings_addr_to_base(virt_addr);
        phys_addr = mappings_addr_to_phys(virt_addr);
        wrap_log("mem\t%s\t0x%016llx\t%d\t0x%08x\t0x%08x\t0x%08x\n",ins_info->type,ins_info->data[i].value,id,phys_addr,from_base,virt_addr);
    } 
    
    // advnace program counter to next instruction
    uc->uc_mcontext.arm_pc = uc->uc_mcontext.arm_pc + 4;
    serialized_stop();
}
    
void wrap_init(void)
{
    struct sigaction sa;

    // init mappings
    mappings_init();

    // wrap libve
    wrap_libve_init();
    // install sighandler
    sa.sa_sigaction = (void *) trace_sighandler;
    sigemptyset (&sa.sa_mask);
    sa.sa_flags = SA_RESTART | SA_SIGINFO;

    sigaction(SIGSEGV, &sa, NULL);    

    ins_info = malloc(sizeof(instruction_info_t));
    memset(ins_info,0,sizeof(instruction_info_t));

    initalised = 1;
}
