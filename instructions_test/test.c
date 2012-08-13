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
 */
#include <stdio.h> 
#include <stdlib.h>
#include <stdint.h>
#include <sys/mman.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

void set_memory(void *mmap_region)
{
    uint32_t *test = mmap_region;
    *test = 0xFFFFFFFF;

    test = mmap_region + 4;
    *test = 0xFFFFFFFF;
}

void str_ldr_test(void *mmap_region)
{
    uint32_t *test = mmap_region;
    uint32_t in_value = 0xDEADBEEF;
    uint32_t out_value;

    *test = in_value;
    out_value = *test;

    if(in_value != out_value) {
        exit(1);
    }
}

void strb_ldrb_test(void *mmap_region)
{
    uint8_t *test = mmap_region;
    uint8_t in_value = 0xBA;
    uint8_t out_value;
    
    *test = in_value;
    out_value = *test;

    if (in_value != out_value) {
        exit(1);
    }
}

void strh_ldrh_test(void *mmap_region)
{
    uint16_t *test = mmap_region;
    uint16_t in_value = 0xDEAD;
    uint16_t out_value;

    *test = in_value;
    out_value = *test;

    if (in_value != out_value) {
        exit(1);
    }
}

void strd_ldrd_test(void *mmap_region)
{
    unsigned long long *test = mmap_region;
    unsigned long long  in_value = 0xDEADBEEFCAFEBABEULL;
    unsigned long long  out_value;

    *test = in_value;
    out_value = *test;

    if (in_value != out_value) {
        exit(1);
    }
}

void ldrsb_test_negative(void *mmap_region)
{
    signed short *test = mmap_region;
    signed short in_value = -127;
    signed short out_value;

    *test = in_value;

    asm volatile (
        "ldrsb %[out], [%[in]]"
        : [out] "=r" (out_value)
        : [in]  "r" (test)
    );

    if (in_value != out_value) {
        printf("in: 0x%08x out: 0x%08x\n",in_value,out_value);
        exit(1);
    }
}

void ldrsb_test_positive(void *mmap_region)
{
    signed short *test = mmap_region;
    signed short in_value = 127;
    signed short out_value;

    *test = in_value;

    asm volatile (
        "ldrsb %[out], [%[in]]"
        : [out] "=r" (out_value)
        : [in]  "r" (test)
    );

    if (in_value != out_value) {
        printf("in: 0x%08x out: 0x%08x\n",in_value,out_value);
        exit(1);
    }
}

void memcpy_stm_ldm_test(void* mmap_region)
{
    int i,count;
    uint32_t *source = malloc(65536);
    uint32_t *write_test = malloc(65536);
    memset(write_test,0,65536);

    count = 50;
    uint32_t *source_pos;
    uint32_t *dest_pos;
    uint32_t temp_a,temp_b;

    /* create source data */
    source_pos = source;
    for(i=0;i<count;i++) {
        *source_pos = i;
        source_pos++; 
    }

    /* null dest data using str instructions*/
    dest_pos = mmap_region;
    for(i=0;i<count;i++) {
        *dest_pos = 0x00000000;
        dest_pos++;
    }

    memcpy(mmap_region,source,1400);

    /* memcpy implemented with only str and ldr */
    /*
    dest_pos = mmap_region;
    source_pos = source;
    for(i=0;i<count;i++) {
        *dest_pos = *source_pos;
        dest_pos++;
        source_pos++;
    }
    */

    /* verify */
    dest_pos   = mmap_region;
    source_pos = source;
    for(i=0;i<count;i++) {
        temp_a = *source_pos;
        temp_b = *dest_pos;

        if (temp_a != temp_b) {
            fprintf(stderr,"%d stm fail  source: 0x%08x != mmaped: 0x%08x\n",i,temp_a,temp_b);
            exit(1);
        } 

        source_pos++;
        dest_pos++;
    }

    memcpy(write_test,mmap_region,1400);

    dest_pos   = write_test;
    source_pos = source;
    for(i=0;i<count;i++) {
        temp_a = *source_pos;
        temp_b = *dest_pos;

        if (temp_a != temp_b) {
            fprintf(stderr,"%d ldm fail source: 0x%08x != mmaped: 0x%08x\n",i,temp_a,temp_b);
            exit(1);
        }

        source_pos++;
        dest_pos++;
    }
}

int main()
{
    int cedar_fd;
    void *mmap_region;

    cedar_fd = open("/dev/cedar_dev", O_RDWR);

    if (cedar_fd == -1) 
    {
        printf("unable to open /dev/cedar_dev\n");
        return 1;
    }

    mmap_region = mmap(NULL,524288,PROT_READ|PROT_WRITE, MAP_SHARED,cedar_fd,0xc4000000);

    printf("str_ldr_test\n");
    set_memory(mmap_region);
    str_ldr_test(mmap_region);

    printf("strb_ldrb_test\n");
    set_memory(mmap_region);
    strb_ldrb_test(mmap_region);

    printf("strh_ldrh_test\n");
    set_memory(mmap_region);
    strh_ldrh_test(mmap_region);

    printf("strd_ldrd_test\n");
    set_memory(mmap_region);
    strd_ldrd_test(mmap_region);

    printf("ldrsb_test_negative\n");
    set_memory(mmap_region);
    ldrsb_test_negative(mmap_region);    

    printf("ldrsb_test_positive\n");
    set_memory(mmap_region);
    ldrsb_test_positive(mmap_region);    

    printf("memcpy_stm_ldm_test\n");
    memcpy_stm_ldm_test(mmap_region);

    return 0;
}
