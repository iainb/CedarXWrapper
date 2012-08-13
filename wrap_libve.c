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
#include "libve.h"
#include "wrap_libve.h"
#include "mappings.h"



/*
 * wrap calls to libvecore.so
 */

static void *libve_dl;

static int
libve_dlopen(void)
{
	libve_dl = dlopen("libvecore.so", RTLD_NOW);
    
	if (!libve_dl) {
		printf("Failed to dlopen %s: %s\n",
		       "libve.so", dlerror());
		exit(-1);
	}

	return 0;
}

static void *
libve_dlsym(const char *name)
{
	void *func;

	if (!libve_dl)
		libve_dlopen();

	func = dlsym(libve_dl, name);

	if (!func) {
		printf("Failed to find %s in %s: %s\n",
		       name, "libvecore.so", dlerror());
		exit(-1);
	}

	return func;
}

/**
  * wrap libve_decode
  */ 
vresult_e (*libve_decode_orig)(u8 keyframe_only, u8 skip_bframe, u64 cur_time, Handle libve);

vresult_e libve_decode(u8 keyframe_only, u8 skip_bframe, u64 cur_time, Handle libve)
{
    vresult_e result;
    if (!libve_decode_orig) {
		libve_decode_orig = libve_dlsym(__func__);
    }
    wrap_log("func\tlibve_decode enter\tkeyframe_only\t0x%08x\tskip_bframe\t0x%08x\tcur_time\t0x%08x\n",keyframe_only,skip_bframe,cur_time);
    result = libve_decode_orig(keyframe_only,skip_bframe,cur_time,libve);
    wrap_log("func\tlibve_decode exit\t%08x\n",result);
    return result;
}

/**
  * wrap libve_open
  */ 

static void* libve_handle;

Handle (*libve_open_orig)(vconfig_t* config, vstream_info_t* stream_info, void* parent);

Handle libve_open(vconfig_t* config, vstream_info_t* stream_info, void* parent)
{
    Handle result;
    if (!libve_open_orig) {
		libve_open_orig = libve_dlsym(__func__);
    }

    wrap_log("func\tlibve_open\tenter\n");   
    result = libve_open_orig(config,stream_info,parent);
    dump_stream_info(stream_info);
    libve_handle = result;
    wrap_log("func\tlibve_open\texit\n");
    return result; 
}


void dump_stream_info(vstream_info_t* info) 
{
    wrap_log("stream_info:\tw\t0x%08x\th\t0x%08x\tfr\t0x%08x\tfd\t0x%08x\tar\t0x%08x\tlen\t0x%08x\tpts_c\t0%08x\n",
             info->video_width,info->video_height,info->frame_rate,info->frame_duration,info->aspec_ratio,
             info->init_data_len,info->is_pts_correct);
}

vresult_e (*libve_set_vbv_orig) (void* vbv, void* libve);

vresult_e libve_set_vbv(void* vbv, void* libve)
{
    vresult_e result;
    if (!libve_set_vbv_orig) {
		libve_set_vbv_orig = libve_dlsym(__func__);
    }

    wrap_log("func\tlibve_set_vbv\tenter\n");
    result = libve_set_vbv_orig(vbv,libve);
    wrap_log("func\tlibve_set_vbv\texit\n");    
    return result;    
}

Handle (*libve_get_fbm_orig) (Handle ve);

Handle libve_get_fbm (Handle ve)
{
    if (!libve_get_fbm_orig) {
        libve_get_fbm_orig = libve_dlsym(__func__);
    } 

    wrap_log("func\tlibve_get_fbm\n");
    return libve_get_fbm_orig(ve);
}


/* start wrap IVE functions */

memtype_e wrap_ve_get_memtype(void )
{
   memtype_e result;
   result = ORIG_IVE.ve_get_memtype();
   wrap_log("func\tve_get_memtype\t0x%08x\n"),(unsigned int)result;
   return result;
}

void wrap_ve_reset_hardware(void )
{
   wrap_log("func\tve_reset_hardware\tenter\n");
   ORIG_IVE.ve_reset_hardware();
   wrap_log("func\tve_reset_hardware\texit\n");
}

u32 wrap_ve_get_reg_base_addr(void )
{
   //wrap_log("ve_get_reg_base_addr\tenter\n");
   u32 result;
   result = ORIG_IVE.ve_get_reg_base_addr();
   //wrap_log("ve_get_reg_base_addr\texit 0x%08x\n",result);
   return result;
}

void wrap_ve_enable_clock(u8 enable,u32 frequency)
{
   wrap_log("func\tve_enable_clock\n");
   ORIG_IVE.ve_enable_clock(enable,frequency);
   //wrap_log("ve_enable_clock\texit\n");
}

s32 wrap_ve_wait_intr(void )
{
   wrap_log("func\tve_wait_intr\tenter\n");
   s32 result;
   result = ORIG_IVE.ve_wait_intr();
   wrap_log("func\tve_wait_intr\texit\n");
   return result;
}

void wrap_ve_enable_intr(u8 enable)
{
   wrap_log("func\tve_enable_intr\tenter\n");
   ORIG_IVE.ve_enable_intr(enable);
   wrap_log("func\tve_enable_intr\texit\n");
}


/* end wrap IVE functions */

/* start wrap IOS functions */

void* wrap_mem_alloc(u32 size)
{
   void* result;
   result = ORIG_IOS.mem_alloc(size);
   wrap_log("func\tmem_alloc\t0x%08x\t0x%08x\n",(unsigned int)result,size);
   return result;
}

u32 wrap_mem_get_phy_addr(u32 virtual_addr)
{
   u32 result;
   result = ORIG_IOS.mem_get_phy_addr(virtual_addr);
   wrap_log("func\tmem_get_phy_addr\t0x%08x\t0x%08x\n",virtual_addr,result);
   return result;
}

void wrap_mem_free(void* p)
{
   wrap_log("func\tmem_free\tenter\n");
   ORIG_IOS.mem_free(p);
   wrap_log("func\tmem_free\texit\n");
}

void wrap_mem_set(void* mem,u32 value,u32 size)
{
   wrap_log("func\tmem_set\t0x%08x\t0x%08x\t0x%08x\n",(unsigned int)mem,value,size);
   mappings_unprotect_all();
   ORIG_IOS.mem_set(mem,value,size);
   mappings_protect_all();
}

void wrap_mem_cpy(void* dst,void* src,u32 size)
{
   wrap_log("func\tmem_cpy\t0x%08x\t0x%08x\t0x%08x\n",(unsigned int) dst,(unsigned int)src,size);
   hexdump(src,size);
   ORIG_IOS.mem_cpy(dst,src,size);
}

void wrap_mem_flush_cache(u8* mem,u32 size)
{
   wrap_log("func\tmem_flush_cache\tenter\n");
   ORIG_IOS.mem_flush_cache(mem,size);
   wrap_log("func\tmem_flush_cache\texit\n");
}

void wrap_mem_pfree(void* p)
{
   wrap_log("func\tmem_pfree\tenter\n");
   ORIG_IOS.mem_pfree(p);
   wrap_log("func\tmem_pfree\texit\n");
}

void wrap_sys_sleep(u32 ms)
{
   wrap_log("func\tsys_sleep\tenter\n");
   ORIG_IOS.sys_sleep(ms);
   wrap_log("func\tsys_sleep\texit\n");
}

void* wrap_mem_palloc(u32 size,u32 align)
{
   wrap_log("func\tmem_palloc\tenter\n");
   void* result;
   result = ORIG_IOS.mem_palloc(size,align);
   wrap_log("func\tmem_palloc\texit\n");
   return result;
}


/* end wrap IOS functions */

/* start wrap IFBM functions */
vpicture_t* wrap_fbm_request_frame(Handle h)
{
   vpicture_t* r;
   r = ORIG_IFBM.fbm_request_frame(h);
   return r;
}

void wrap_fbm_share_frame(vpicture_t* frame,Handle h)
{
   wrap_log("func\tfbm_share_frame\tenter\n");
   ORIG_IFBM.fbm_share_frame(frame,h);
   wrap_log("func\tfbm_share_frame\texit\n");
}

void wrap_fbm_return_frame(vpicture_t* frame,u8 valid,Handle h)
{
    ORIG_IFBM.fbm_return_frame(frame,valid,h);
    wrap_log("func\tfbm_return_frame\t0x%08x\t0x%08x\t0x%08x\n",frame->id,frame->pts);
    wrap_log("func\tfbm_return_frame\t0x%08x\t0x%08x\t0x%08x\n",frame->y,frame->u,frame->v,frame->alpha);
}

void wrap_fbm_release(Handle h,void* parent)
{
   wrap_log("func\tfbm_release\tenter\n");
   ORIG_IFBM.fbm_release(h,parent);
   wrap_log("func\tfbm_release\texit\n");
}

Handle wrap_fbm_init_ex(u32 max_frame_num,u32 min_frame_num,u32 size_y[],u32 size_u[],u32 size_v[],u32 size_alpha[],_3d_mode_e out_3d_mode,pixel_format_e format,void* parent)
{
   Handle result;
   wrap_log("func\tfbm_init_ex\t0\t0x%08x\t0x%08x\t0x%08x\t0x%08x\n",size_y[0],size_u[0],size_v[0],size_alpha[0]);
   wrap_log("func\tfbm_init_ex\t1\t0x%08x\t0x%08x\t0x%08x\t0x%08x\n",size_y[1],size_u[1],size_v[1],size_alpha[1]);
   result = ORIG_IFBM.fbm_init_ex(max_frame_num,min_frame_num,size_y,size_u,size_v,size_alpha,out_3d_mode,format,parent);
   return result;
}

/* end wrap IFBM functions*/

/* start wrap IVBV functions */

u8* wrap_vbv_get_base_addr(Handle vbv)
{
   //wrap_log("vbv_get_base_addr\tenter\n");
   u8* result;
   result = ORIG_IVBV.vbv_get_base_addr(vbv);
   //wrap_log("vbv_get_base_addr\texit\n");
   return result;
}

vstream_data_t* wrap_vbv_request_bitstream_frame(Handle vbv)
{
    vstream_data_t* r;
    r = ORIG_IVBV.vbv_request_bitstream_frame(vbv);
    //wrap_log("vbv_request_bistream_frame\t0x%08x\t0x%16lx\t0x%16lx\t0x%08x\t0x%08x\n",r->length,r->pts,r->pcr,r->valid,r->id); 
    wrap_log("func\tvbv_request_bitstream_frame\t0x%08x\t0x%016llx\n",r->data,r->pts);
    return r;
}

void wrap_vbv_return_bitstream_frame(vstream_data_t* stream,Handle vbv)
{
   wrap_log("func\tvbv_return_bitstream_frame\tenter\n");
   ORIG_IVBV.vbv_return_bitstream_frame(stream,vbv);
   wrap_log("func\tvbv_return_bitstream_frame\texit\n");
}

u32 wrap_vbv_get_size(Handle vbv)
{
   u32 result;
   result = ORIG_IVBV.vbv_get_size(vbv);
   wrap_log("func\tvbv_get_size\t0x%08x\n",result);
   return result;
}

void wrap_vbv_flush_bitstream_frame(vstream_data_t* stream,Handle vbv)
{
   wrap_log("func\tvbv_flush_bitstream_frame\t0x%08x\t0x%16lx\t0x%16lx\t0x%08x\t0x%08x\n",stream->length,stream->pts,stream->pcr,stream->valid,stream->id);
   ORIG_IVBV.vbv_flush_bitstream_frame(stream,vbv);
}

/* end wrap IVBV functions */

void wrap_libve_init() 
{
    /* wrap IVE */
    if (&IVE) { 
        wrap_log("info\twrap_libve_init\tIVE\n");
        memcpy(&ORIG_IVE,&IVE,sizeof(IVEControl_t));
        IVE.ve_get_memtype = &wrap_ve_get_memtype;
        IVE.ve_reset_hardware = &wrap_ve_reset_hardware;
        IVE.ve_get_reg_base_addr = &wrap_ve_get_reg_base_addr;
        IVE.ve_enable_clock = &wrap_ve_enable_clock;
        IVE.ve_wait_intr = &wrap_ve_wait_intr;
        IVE.ve_enable_intr = &wrap_ve_enable_intr;
    }
    
    /* wrap IOS */
    if (&IOS) { 
        wrap_log("info\twrap_libve_init\tIOS\n");
        memcpy(&ORIG_IOS,&IOS,sizeof(IOS_t));
        IOS.mem_alloc = &wrap_mem_alloc;
        IOS.mem_get_phy_addr = &wrap_mem_get_phy_addr;
        IOS.mem_free = &wrap_mem_free;
        IOS.mem_set = &wrap_mem_set;
        IOS.mem_cpy = &wrap_mem_cpy;
        IOS.mem_flush_cache = &wrap_mem_flush_cache;
        IOS.mem_pfree = &wrap_mem_pfree;
        IOS.sys_sleep = &wrap_sys_sleep;
        IOS.mem_palloc = &wrap_mem_palloc;
    }

    /* wrap IFBM */
    if (&IFBM) { 
        wrap_log("info\twrap_libve_init\tIFBM\n");
        memcpy(&ORIG_IFBM,&IFBM,sizeof(IFBM_t));   
        IFBM.fbm_request_frame = &wrap_fbm_request_frame;
        IFBM.fbm_share_frame = &wrap_fbm_share_frame;
        IFBM.fbm_return_frame = &wrap_fbm_return_frame;
        IFBM.fbm_release = &wrap_fbm_release;
        IFBM.fbm_init_ex = &wrap_fbm_init_ex;
    }

    /* wrap IVBV */
    if (&IVBV) {
        wrap_log("info\twrap_libve_init\tIVBV\n");
        memcpy(&ORIG_IVBV,&IVBV,sizeof(IVBV_t));
        IVBV.vbv_get_base_addr = &wrap_vbv_get_base_addr;
        IVBV.vbv_request_bitstream_frame = &wrap_vbv_request_bitstream_frame;
        IVBV.vbv_return_bitstream_frame = &wrap_vbv_return_bitstream_frame;
        IVBV.vbv_get_size = &wrap_vbv_get_size;
        IVBV.vbv_flush_bitstream_frame = &wrap_vbv_flush_bitstream_frame;
    }
}
