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
 */
#include <stdint.h>
#include <sys/types.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>
#include <ctype.h>

#include "mappings.h"
#include "log.h"

int file_descriptors[NUM_MAPPINGS];
int next_free_mapping = 1;

/*
 *  mappings_trace_fd adds a file descriptor to an array of fd's we are tracing
 */
void mappings_trace_fd(int fd)
{
    int i,set;

    set = 0;
    for (i=0;i<NUM_MAPPINGS;i++) {
        if(file_descriptors[i] == 0) {
            file_descriptors[i] = fd;
            set = 1;
            break;
        } else if (file_descriptors[i] == fd) {
            wrap_log("already tracing file descriptor %d",fd);
            exit(1);
        }
    } 

    if (set == 0) {
        wrap_log("ran out of slots to store file descriptors\n");
        exit(1);        
    }
}

/*
 *  mappings_is_fd_traced returns 1 if this is a fd we are tracing
 */
int mappings_is_fd_traced(int fd)
{
    int i;
    for(i=0;i<NUM_MAPPINGS;i++) {
        if (file_descriptors[i] == fd) {
            return 1;
        }
    }    
    return 0;
}

/*
 * add_mmap_region add a memory mapping to our array of traced regions 
 */
void mappings_trace_mmap(uint32_t address,uint32_t phyaddr,size_t length, int regs)
{
    int new_mapping;
    new_mapping = next_free_mapping;

    if (new_mapping > NUM_MAPPINGS) {
        wrap_log("mappings error: ran out of space to store new mappings\n");
        exit(1);
    }

    mappings[new_mapping]->size    = length;
    mappings[new_mapping]->addr    = address;
    if (regs == 1) {
        // taken from cedarx kernel driver.
        mappings[new_mapping]->phyaddr = 0x01C0E000;
    } else {
        mappings[new_mapping]->phyaddr = (phyaddr & 0x0FFFFFFF);
    }
    mappings[new_mapping]->saddr   = mappings[new_mapping]->addr;
    mappings[new_mapping]->eaddr   =  mappings[new_mapping]->addr + mappings[new_mapping]->size;
    mappings[new_mapping]->in_use  = 1;
    mappings[new_mapping]->regs    = regs;

    next_free_mapping++;
}

/*
 *  mappings_is_addr_traced returns true if the address is one we are tracing
 */
uint32_t mappings_is_addr_traced(uint32_t address)
{
    int id = mappings_get_id(address);
    if (id != 0) {
        return 1;
    } else {
        return 0;
    }
}

/*
 * mappings_get_id returns the id associated with the address or 0 if no mapping is found
 */
int mappings_get_id(uint32_t address)
{
    int i;
    unsigned long cmp_addr = (unsigned long) address;

    for(i=1;i<NUM_MAPPINGS;i++) {
        if (cmp_addr >= mappings[i]->saddr && cmp_addr <= mappings[i]->eaddr) {
            return i;
        }
    } 
    return 0;
}


/*
 * mappings_addr_to_base convrts a address to an offset from the base of a region
 */
uint32_t mappings_addr_to_base(uint32_t address)
{
    int id = mappings_get_id(address);
    uint32_t ret_addr;

    if (id != 0) {
        ret_addr = address - mappings[id]->addr;        
    } else {
        ret_addr = 0xFFFFFFFF;
    }

    return ret_addr;
}

/*
 *  mappings_addr_to_phys returns a physical address 
 */ 
uint32_t mappings_addr_to_phys(uint32_t address)
{
    int id = mappings_get_id(address);
    uint32_t ret_addr;

    if (id != 0) {
        ret_addr = mappings[id]->phyaddr + (address - mappings[id]->addr);        
    } else {
        ret_addr = 0xFFFFFFFF;
    }

    return ret_addr;
}

/*
 * is_regs returns 1 if a mmap address maps to cedarx registers
 */
int mappings_is_regs(uint32_t address)
{
    int id = mappings_get_id(address);
    if (id != 0) {
        return mappings[id]->regs;
    } else {
        return 0;
    }    
}

/*
 * Protect mmap memory
 */
void mappings_protect_all()
{
    int i;
    for(i=1;i<NUM_MAPPINGS;i++) {
        if (mappings[i]->in_use == 1) {
            if (mprotect((void *) mappings[i]->addr, mappings[i]->size, PROT_NONE) < 0) {
                wrap_log("mappings_protect_all: mprotect(0x%08X|0x%08X) failed\n",(unsigned int) mappings[i]->addr,mappings[i]->size);
		        exit(1);
	        }    
        }
    }
}

/*
 * protect specific mmap region
 */
void mappings_protect_mapping(uint32_t address) 
{
    int i;

    for(i=1;i<NUM_MAPPINGS;i++) {
        if (mappings[i]->in_use == 1) {
            if (address >= mappings[i]->saddr && address <= mappings[i]->eaddr) {
                 if (mprotect((void *) mappings[i]->addr, mappings[i]->size, PROT_NONE) < 0) {
                    wrap_log("mappings_protect_mapping: mprotect(0x%08X|0x%08X) failed\n",(unsigned int) mappings[i]->addr,mappings[i]->size);
		            exit(1);
                 }    
                return;
            }
        }
    }

    wrap_log("mappings_protect_mapping: couldn't find region\n");
    exit(1);
}

/*
 * Unprotect mmap memory
 */
void mappings_unprotect_all()
{
    int i;

    for(i=1;i<NUM_MAPPINGS;i++) {
        if (mappings[i]->in_use == 1) {
            if (mprotect((void *) mappings[i]->addr, mappings[i]->size, PROT_READ | PROT_WRITE) < 0) {
                wrap_log("mappings_unprocted_all mprotect(0x%08X|0x%08X) failed\n",(unsigned int) mappings[i]->addr,mappings[i]->size);
		        exit(1);
	        }    
        }
    }    
}

/*
 * unprotect specific mmap region
 */
void mappings_unprotect_mapping(uint32_t address) 
{
    int i;

    for(i=1;i<NUM_MAPPINGS;i++) {
        if (mappings[i]->in_use == 1) {
            if (address >= mappings[i]->saddr && address <= mappings[i]->eaddr) {
                 if (mprotect((void *) mappings[i]->addr, mappings[i]->size,PROT_READ | PROT_WRITE) < 0) {
                    wrap_log("mappings_unprotect_mapping region mprotect(0x%08X|0x%08X) failed\n",(unsigned int) mappings[i]->addr,mappings[i]->size);
		            exit(1);
                 }    
                return;
            }
        }
    }

    wrap_log("mappings_unprotect_mapping couldn't find mapping\n");
    exit(1);
}

/*
 * init storage for mmap memory regions
 */
void mappings_init()
{
    int i;
    mappings = (mapping_t **) malloc(sizeof(mapping_t) * NUM_MAPPINGS);
    for(i = 0; i < NUM_MAPPINGS; i++)
    {
        mappings[i] = (mapping_t *) malloc(sizeof(mapping_t));
        memset(mappings[i],0,sizeof(mapping_t));
        mappings[i]->in_use = 0;
    }    
}

/*
 * hexdump dumps a region of memory for a given size
 */
void hexdump(const void *data, int size)
{
	unsigned char *buf = (void *) data;
	char alpha[17];
	int i;

	for (i = 0; i < size; i++) {
		if (!(i % 16))
			wrap_log("mem\tdump\t0x%08x", (unsigned int) buf + i);

		if (((void *) (buf + i)) < ((void *) data)) {
			wrap_log("   ");
			alpha[i % 16] = '.';
		} else {
			wrap_log(" %02x", buf[i]);

			if (isprint(buf[i]) && (buf[i] < 0xA0))
				alpha[i % 16] = buf[i];
			else
				alpha[i % 16] = '.';
		}

		if ((i % 16) == 15) {
			alpha[16] = 0;
			wrap_log("\t|%s|\n", alpha);
		}
	}

	if (i % 16) {
		for (i %= 16; i < 16; i++) {
			wrap_log("   ");
			alpha[i] = '.';

			if (i == 15) {
				alpha[16] = 0;
				wrap_log("\t|%s|\n", alpha);
			}
		}
	}
}
