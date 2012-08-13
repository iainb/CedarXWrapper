#!/usr/bin/env python


ve_funcs = { 've_reset_hardware' : { 'type' : 'void',
                                     'args' : [('void','')] },
             've_enable_clock' :   { 'type' : 'void',
                                     'args' : [('u8','enable'),('u32','frequency')] },
             've_enable_intr' :    { 'type' : 'void',
                                     'args' : [('u8','enable')] },
             've_wait_intr' :      { 'type' : 's32',
                                     'args' : [('void','')] },
            
             've_get_reg_base_addr' : { 'type' : 'u32',
                                        'args' : [('void','')] },
             've_get_memtype' :     { 'type' : 'memtype_e',
                                      'args' : [('void','')] }
          }

ios_funcs = { 'mem_alloc'        : { 'type' : 'void*',
                                     'args' : [('u32','size')] },
              'mem_free'         : { 'type' : 'void',
                                     'args' : [('void*','p')] },
              'mem_palloc'       : { 'type' : 'void*',
                                     'args' : [('u32','size'),('u32','align')] },
              'mem_pfree'        : { 'type' : 'void',
                                     'args' : [('void*','p')] },
              'mem_set'          : { 'type' : 'void',
                                     'args' : [('void*','mem'),('u32','value'),('u32','size')] },
              'mem_cpy'          : { 'type' : 'void',
                                     'args' : [('void*','dst'),('void*','src'),('u32','size')] },
              'mem_flush_cache'  : { 'type' : 'void',
                                     'args' : [('u8*','mem'),('u32','size')] },
              'mem_get_phy_addr' : { 'type' : 'u32',
                                     'args' : [('u32','virtual_addr')] },
              'sys_sleep'        : { 'type' : 'void',
                                     'args' : [('u32','ms')] }
            }

fbm_funcs = {'fbm_init_ex'     : { 'type' : 'Handle',
                                  'args' : [('u32','max_frame_num'),('u32','min_frame_num'),('u32','size_y[]'),('u32','size_u[]'),('u32','size_v[]'),('u32','size_alpha[]'),('_3d_mode_e','out_3d_mode'),('pixel_format_e','format'),('void*','parent')] },
            'fbm_release'     : { 'type' : 'void',
                                  'args' : [('Handle','h'),('void*','parent')] },
            'fbm_request_frame' : { 'type' : 'vpicture_t*',
                                    'args' : [('Handle','h')] },
            'fbm_return_frame'  : { 'type' : 'void',
                                    'args' : [('vpicture_t*','frame'),('u8','valid'),('Handle','h')] },
            'fbm_share_frame'   : { 'type' : 'void',
                                    'args' : [('vpicture_t*','frame'),('Handle','h')] }
}

vbv_funcs = { 'vbv_request_bitstream_frame' : { 'type' : 'vstream_data_t*',
                                                'args' : [('Handle','vbv')] },
              'vbv_return_bitstream_frame'  : { 'type' : 'void',
                                                'args' : [('vstream_data_t*','stream'),('Handle','vbv')] },
              'vbv_flush_bitstream_frame'   : { 'type' : 'void',
                                                'args' : [('vstream_data_t*','stream'),('Handle','vbv')] },
              'vbv_get_base_addr'           : { 'type' : 'u8*',
                                                'args' : [('Handle','vbv')] },
              'vbv_get_size'                : { 'type' : 'u32',
                                                'args' : [('Handle','vbv')] }
            }

def gen_code(orig,new,funcs):
    # overide methods
    print "/* overide for " + new + "*/"
    for func in funcs:
        print new + "." + func + " = &wrap_" + func + ";"

    print ""

    for func in funcs:
        gen_func(func,orig,funcs[func]['type'],funcs[func]['args'])
    print "/* end overide for " + new + "*/"

    
def gen_func(name,orig,typ,args):
    s =     typ + " wrap_" + name + "(" 
    for arg in args:
        s = s + arg[0] + " " + arg[1] + ","
    s = s[:-1]
    s = s + ")\n"
    s = s + "{\n"
    s = s + "   wrap_log(\"" + name + "\\tenter\\n\");\n"

    if (typ != "void"):
        s = s + "   " + typ + " result;\n"
        s = s + "   result = "
    else:
        s = s + "   "
    s = s + orig + "." + name + "("
    for arg in args:
        s = s + arg[1].replace("[]","") + ","
    s = s[:-1]
    s = s + ");\n"

    s = s + "   wrap_log(\"" + name + "\\texit\\n\");\n"
    if (typ != "void"):
        s = s + "   return result;\n"
    s = s + "}\n"

    print s

gen_code('ORIG_IVE','IVE',ve_funcs)
gen_code('ORIG_IOS','IOS',ios_funcs)
gen_code('ORIG_IFBM','IFBM',fbm_funcs)
gen_code('ORIG_IVBV','IVBV',vbv_funcs)
