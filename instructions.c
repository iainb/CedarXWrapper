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
#define _GNU_SOURCE

#include <ucontext.h>
#include <sys/types.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>


#include "instructions.h"

static inline void * find_register_address(ucontext_t *uc,int reg) __attribute__((always_inline));;
void ldrh_strh(uint32_t instruction,uint32_t fault_address,ucontext_t *uc,instruction_info_t *res);
void ldr_str(uint32_t instruction,uint32_t fault_address,ucontext_t *uc,instruction_info_t *res);
void ldm_stm(uint32_t instruction,uint32_t fault_address,ucontext_t *uc,instruction_info_t *res);

/*
 * handle_instruction - will decode an arm instruction, perform the required operation and update
 * the ucontext structure with the required information. A record of the loads and stores along with 
 * the type of instruction will be stored in the instruction_info_t structure for logging after the
 * instruction has been handled.
 *
 * @param instruction   - instruction to decode
 * @param fault_address - memory fault address
 * @param uc            - user contet pointer
 * @param res           - resulting information about instruction processed
 */
void handle_instruction(uint32_t instruction,uint32_t fault_address,ucontext_t *uc, instruction_info_t *res)
{
    int ins_type;
   
    /* 
     * handle instruction is only called after a memory fault has been triggered - because of this we 
     * can ignore the condition portion of the instruction and assume the condition has been met.
     */ 
    ins_type = (instruction & 0x0E000000) >> 26;
    switch (ins_type) {
        case 0x0: /* half word data / signed and double transfer */
            ldrh_strh(instruction,fault_address,uc,res);
            break;
        case 0x1: /* single data transfer */
            ldr_str(instruction,fault_address,uc,res);
            break;    
        case 0x2: /* block data transfer */
            ldm_stm(instruction,fault_address,uc,res);
            break;
        default: /* unhanlded instruction */
            fprintf(stderr,"unhandled instruction: 0x%08x\n",instruction);
            exit(1);
            break;
    }

}

/* half word data / signed and double transfer */
void ldrh_strh(uint32_t instruction,uint32_t fault_address,ucontext_t *uc,instruction_info_t *res)
{
    int immediate,pre,up,write_back,load,base,src_dst,addr_mode1,type,addr_mode2,offset;

    uint32_t* offset_reg;
    uint32_t* actual_base;
    uint32_t base_address;

    /* storage when performing instructions */
    uint16_t  temp_16;
    uint16_t* source_16;
    uint16_t* dest_16;

    uint32_t  temp_32;
    uint32_t  temp_32b;
    uint32_t* source_32;
    uint32_t* source_32b; // storage for ldrd strd instructions
    uint32_t* dest_32;
    uint32_t* dest_32b; // storage for ldrd strd instructions

    uint64_t  temp_64;
    uint64_t* source_64;
    uint64_t* dest_64;


    immediate   = (instruction & 0x00400000) >> 22;
    pre         = (instruction & 0x01000000) >> 24;
    up          = (instruction & 0x00800000) >> 23;
    write_back  = (instruction & 0x00200000) >> 21;
    load        = (instruction & 0x00100000) >> 20;
    base        = (instruction & 0x000f0000) >> 16;
    src_dst     = (instruction & 0x0000f000) >> 12;
    addr_mode1  = (instruction & 0x00000f00) >> 8;
    type        = (instruction & 0x00000060) >> 5;
    addr_mode2  = (instruction & 0x0000000f);

    if (immediate == 0x1) {
        offset = (addr_mode1 << 4) | addr_mode2;
    } else {
        offset_reg = find_register_address(uc,addr_mode2);
        offset = *offset_reg;
    }

    actual_base = find_register_address(uc,base);
    if (pre == 0x1) {
        if (up == 0x1) {
            base_address = *actual_base + offset;  
        } else {
            base_address = *actual_base - offset;
        }
    } else {
        base_address = *actual_base;
    }

    /* sanity check */ 
    if (base_address != fault_address) {
        fprintf(stderr,"ldrh_strh error - ins:%08x base_address:0x%08x != fault_address:0x%08x offset:0x%08x\n",instruction,base_address,fault_address,offset);
        exit(1);
    }
        
    if (load == 0x1) {
        source_32 = (uint32_t *) base_address;
        dest_32   = find_register_address(uc,src_dst);   
        switch (type) {
            case 0x1:
                /* ldrh instruction */
                asm volatile (
                    "ldrh %[out], [%[in]]\n\t"
                    : [out] "=r" (temp_32)
                    : [in]  "r"  (source_32)
                    : "memory"
                );                
                *dest_32 = temp_32;
                strcpy(res->type,"ldrh");
                res->data[0].value   = temp_32;
                res->data[0].address = base_address;
                res->count = 1;
                break;
            case 0x2:
                /* ldrsb instruction */ 
                asm volatile (
                    "ldrsb %[out], [%[in]]\n\t"
                    : [out] "=r" (temp_32)
                    : [in]  "r"  (source_32)
                    : "memory"
                );
                *dest_32 = temp_32;
                strcpy(res->type,"ldrsb");
                res->data[0].value   = temp_32;
                res->data[0].address = base_address;
                res->count = 1;
                break;
            case 0x3:
                /* ldrsh instruction */
                asm volatile (
                    "ldrsh %[out], [%[in]]\n\t"
                    : [out] "=r" (temp_32)
                    : [in]  "r"  (source_32)
                    : "memory"
                );
                *dest_32 = temp_32; 
                strcpy(res->type,"ldrsh");
                res->data[0].value   = temp_32;
                res->data[0].address = base_address;
                res->count = 1;
                break;
            default:
                fprintf(stderr,"error: unknown load type: %08x type: 0x%08x\n",instruction,type);
                exit(1);
                break;
        }
    } else {
        switch (type) {
            case 0x1:
                /* strh instruction */
                source_16 = find_register_address(uc,src_dst);
                dest_16   = (uint16_t *) base_address;
                temp_16 = *source_16;
                asm volatile (
                    "strh %[in], [%[out]]\n\t"
                    : [out] "+r" (dest_16)
                    : [in]  "r"  (temp_16)
                    : "memory"
                );    
                strcpy(res->type,"strh");
                res->data[0].value   = temp_16;
                res->data[0].address = base_address;
                res->count = 1;
                break;
            case 0x2:
                /* ldrd instruction */
                source_64   = (uint64_t *) base_address;
                temp_64 = *source_64;
                dest_32  = find_register_address(uc,src_dst);
                dest_32b = find_register_address(uc,src_dst + 1);
                temp_32  = temp_64 >> 32;
                temp_32b = temp_64;

                *dest_32 = temp_32b;
                *dest_32b = temp_32;
                
                strcpy(res->type,"ldrd");
                res->data[0].value = temp_64;
                res->data[0].address = base_address;
                res->count = 1;
                
                break;
            case 0x3:
                /* strd instruction */
                dest_64 = (uint64_t *) base_address;
                source_32   = find_register_address(uc,src_dst);
                source_32b  = find_register_address(uc,src_dst + 1);
                temp_32 = *source_32;
                temp_32b = *source_32b;
                temp_64 = (uint64_t) temp_32b << 32 |  temp_32;
                *dest_64 = temp_64;
                strcpy(res->type,"strd");
                res->data[0].value = temp_64;
                res->data[0].address = base_address;
                res->count = 1;
                break;
            default:
                fprintf(stderr,"error: unknown store/double word type: %08x type: 0x%08x\n",instruction,type);
                exit(1);
                break;
        }
    }
    
    /* handle post indexing of base address */
    if (pre == 0x0) {
        if (up == 0x1) {
            *actual_base = base_address + offset;
        } else {
            *actual_base = base_address - offset;
        }
    } 

    /* handle write back */
    if (write_back == 0x1) {
        *actual_base = base_address;
    }

}

/* single data transfer */
void ldr_str(uint32_t instruction,uint32_t fault_address,ucontext_t *uc,instruction_info_t *res) 
{
    /* decoded instruction */
    int immediate,pre,up,byte,write_back,load,base,src_dst,offset,offset_reg,offset_shift,shift_ammount,shift_type;

    /* temp storage */
    void* destination;
    void* source;
    uint32_t* actual_base;
    uint32_t base_address;
    uint32_t* offset_register;
   
    /* storage when performing instructions */
    uint8_t  temp_8;
    uint8_t* source_8;
    uint8_t* dest_8;

    uint32_t  temp_32;
    uint32_t* source_32;
    uint32_t* dest_32;

 
    immediate  = (instruction & 0x02000000) >> 25;
    pre        = (instruction & 0x01000000) >> 24;
    up         = (instruction & 0x00800000) >> 23;
    byte       = (instruction & 0x00400000) >> 22;
    write_back = (instruction & 0x00200000) >> 21;
    load       = (instruction & 0x00100000) >> 20;
    base       = (instruction & 0x000f0000) >> 16;
    src_dst    = (instruction & 0x0000f000) >> 12;

    /* determine offset */ 
    if (immediate == 0x0) {
        offset    = (instruction & 0x00000fff);
    } else {
        offset_reg   = (instruction & 0x0000000f);
        offset_register = find_register_address(uc,offset_reg);

        offset_shift  = (instruction & 0x00000ff0) >> 4;

        offset = *offset_register;
        if (offset_shift != 0x0) {
            shift_ammount = (offset_shift & 0x000000f8) >> 3;
            shift_type    = (offset_shift & 0x00000007) >> 1;
            /* shift_ type 0 = logical left, 1 = logical right, 2 = arithmetic right, 3 = rotate right */
            offset = *offset_register;
            switch (shift_type) {
                case 0x0: /* logical left */
                    asm volatile (
                        "mov %[in], %[out], LSL %[ammount]\n\t"
                        : [out] "=r" (offset)
                        : [in]  "r"  (offset), [ammount] "r" (shift_ammount)
                        : "memory"
                    );
                    break;
                case 0x1: /* logical right */
                    asm volatile (
                        "mov %[in], %[out], LSR %[ammount]\n\t"
                        : [out] "=r" (offset)
                        : [in]  "r"  (offset), [ammount] "r" (shift_ammount)
                        : "memory"
                    );
                    break;
                case 0x2: /* arithmetic right */
                    asm volatile (
                        "mov %[in], %[out], ASR %[ammount]\n\t"
                        : [out] "=r" (offset)
                        : [in]  "r"  (offset), [ammount] "r" (shift_ammount)
                        : "memory"
                    );
                    break;
                case 0x3: /* rotate right */
                    asm volatile (
                        "mov %[in], %[out], ROR %[ammount]\n\t"
                        : [out] "=r" (offset)
                        : [in]  "r"  (offset), [ammount] "r" (shift_ammount)
                        : "memory"
                    );
                    break;
            }
        }
    }
   
    /* perform pre manipulation of base address */ 
    actual_base  = find_register_address(uc,base);
    if (pre == 0x1) {
        if (up == 0x1) {
            base_address = *actual_base + offset;
        } else {
            base_address = *actual_base - offset;
        }
    } else {
        base_address = *actual_base;
    }

    /* sanity check */ 
    if (base_address != fault_address) {
        fprintf(stderr,"ldr_str error - ins:%08x base_address:0x%08x != fault_address:0x%08x immediate:0x%08x\n",instruction,base_address,fault_address,immediate);
        exit(1);
    }
   
    /* perform instruction */ 
    if (load == 0x1) {
        source      = (void *) base_address;
        destination = find_register_address(uc,src_dst);
        if (byte == 0x0) { 
            /* ldr word */
            dest_32 = destination;
            /* load source addres into temp_32 */ 
            asm volatile (
                "ldr %[out], [%[in]]\n\t"
                : [out] "=r" (temp_32)
                : [in]  "r"  (source)
                : "memory"
            );
            *dest_32 = temp_32;
            strcpy(res->type,"ldr");
            res->data[0].value   = temp_32;
            res->data[0].address = base_address;
            res->count = 1;
        } else {          
             /* ldr byte */
            dest_32 = destination;

            asm volatile (
                "ldrb %[out], [%[in]]\n\t"
                : [out] "=r" (temp_32)
                : [in]  "r"  (source)
                : "memory"
            );
            *dest_32 = temp_32;            
            strcpy(res->type,"ldrb");
            res->data[0].value   = temp_32;
            res->data[0].address = base_address;
            res->count = 1;
        }
    } else {
        source      = find_register_address(uc,src_dst);
        destination = (void *) base_address;
        if (byte == 0x0) { 
            /* str word */
            source_32 = source;
            dest_32   = destination;

            temp_32 = *source_32;

            asm volatile (
                "str %[in], [%[out]]\n\t"
                : [out] "+r" (dest_32)
                : [in]  "r"  (temp_32)
                : "memory"
            );            
            strcpy(res->type,"str");
            res->data[0].value   = temp_32;
            res->data[0].address = base_address;
            res->count = 1;
        } else {
            /* str byte */
            source_8 = source;
            dest_8   = destination;

            temp_8 = *source_8;

            asm volatile (
                "strb %[in], [%[out]]\n\t"
                : [out] "+r" (dest_8)
                : [in]  "r"  (temp_8)
                : "memory"
            ); 
            strcpy(res->type,"strb"); 
            res->data[0].value   = temp_8;
            res->data[0].address = base_address;
            res->count = 1;
        }
    }
    
    /* handle post indexing of base address */
    if (pre == 0x0) {
        if (up == 0x1) {
            *actual_base = base_address + offset;
        } else {
            *actual_base = base_address - offset;
        }
    }

    /* handle write back */
    if (write_back == 0x1) {
        *actual_base = base_address;
    }
}

/* block data transfer */
void ldm_stm(uint32_t instruction,uint32_t fault_address,ucontext_t *uc,instruction_info_t *res)
{
    int pre,up,psr,write_back,load,base,registers;

    int i,count,reg;

    uint32_t* actual_base;
    uint32_t base_address;

    /* storage when performing instructions */
    uint32_t  temp_32;
    uint32_t* source_32;
    uint32_t* dest_32;

    pre         = (instruction & 0x01000000) >> 24;
    up          = (instruction & 0x00800000) >> 23;
    psr         = (instruction & 0x00400000) >> 22;
    write_back  = (instruction & 0x00200000) >> 21;
    load        = (instruction & 0x00100000) >> 20;
    base        = (instruction & 0x000f0000) >> 16;
    registers   = (instruction & 0x0000ffff);

    actual_base = find_register_address(uc,base);
    base_address = *actual_base;

    if (pre == 0x1) {
        if (up == 0x1) {
            base_address = base_address + 4;        
        } else {
            base_address = base_address - 4;
        }
    } 

    /* sanity check */ 
    if (base_address != fault_address) {
        fprintf(stderr,"ldm_stm error - ins:%08x base_address:0x%08x != fault_address:0x%08x\n",instruction,base_address,fault_address);
        exit(1);
    }

    /* setup output */
    if (load == 0x1) {
        strcpy(res->type,"ldm");
    } else {
        strcpy(res->type,"stm");
    }

    count = 0;
    if (up == 0x1) {
        /* increment */
        reg = 1;
        for(i=0;i<15;i++) {
            if ((registers & reg) == reg) {
                if (load == 0x1) {
                    /* ldm */
                    source_32 = (uint32_t *) base_address;
                    dest_32   = find_register_address(uc,i);
                    /* load source addres into temp_32 */ 
                    asm volatile (
                        "ldr %[out], [%[in]]\n\t"
                        : [out] "=r" (temp_32)
                        : [in]  "r"  (source_32)
                        : "memory"
                    );                    
                    *dest_32 = temp_32;
                    res->data[count].value   = temp_32;
                    res->data[count].address = base_address; 
                    count++;
                } else { 
                    /* stm */
                    source_32 = find_register_address(uc,i); 
                    dest_32   = (uint32_t *) base_address;
                    temp_32 = *source_32;
                    asm volatile (
                        "str %[in], [%[out]]\n\t"
                        : [out] "+r" (dest_32)
                        : [in]  "r"  (temp_32)
                        : "memory"
                    );  
                    res->data[count].value   = temp_32;
                    res->data[count].address = base_address;
                    count++;
                }
                base_address = base_address + 4;
            }
            reg = reg * 2;
        }            
    } else {
        /* decrement */
        reg = 16384;
        for (i=15;i>=0;i++) {
            if ((registers & reg) == reg) {
                if (load == 0x1) {
                    /* ldm */
                    source_32 = (uint32_t *) base_address;
                    dest_32   = find_register_address(uc,i);
                    /* load source addres into temp_32 */ 
                    asm volatile (
                        "ldr %[out], [%[in]]\n\t"
                        : [out] "=r" (temp_32)
                        : [in]  "r"  (source_32)
                        : "memory"
                    );                    
                    *dest_32 = temp_32;
                    res->data[count].value   = temp_32;
                    res->data[count].address = base_address; 
                    count++;
                } else {
                    /* stm */
                    source_32 = find_register_address(uc,i); 
                    dest_32   = (uint32_t *) base_address;
                    temp_32 = *source_32;
                    asm volatile (
                        "str %[in], [%[out]]\n\t"
                        : [out] "+r" (dest_32)
                        : [in]  "r"  (temp_32)
                        : "memory"
                    );  
                    res->data[count].value   = temp_32;
                    res->data[count].address = base_address;
                    count++;
                }
                base_address = base_address - 4;
            }
            reg = reg / 2;   
        }
    }

    if (write_back == 0x1) {
        *actual_base = base_address;
    }

    /* store number of loads / stores */
    res->count = count;
}

/*
 * find_register_address returns a pointer to the register address
 */
static inline void * find_register_address(ucontext_t *uc,int reg) 
{
    void * register_address =  &uc->uc_mcontext.arm_r0;
    register_address = register_address + (reg * 4);
    return register_address;
}
