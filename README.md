CedarX Wrapper
==============
The CedarX Wrapper library is a built with the aim of understanding how a cedar x player interacts with the video decoder chip of Allwinner A10 devices by intercepting libc function calls and memory access to the dedicated video memory.

The CedarX kernel device driver provides only a limited amount of functionality, the user land library libve (lib video engine?) does the majority of the work. The user land library functions by opening /dev/cedar_dev (handled by the kernel driver) and memory mapping the memory allocated to the registers of the video decoder chip into its address space. A selection of ioctls are also available which are used for some kernel level operations.

Full details of the kernel portion can be found in the source under drivers/media/video/sun4i/

This wrapper deals with tracing the reads and writes that the userland driver performs against the video decoder registers and dedicated memory. This information is then logged in an output that looks as follows:

An example function trace:

func    mmap    2       addr:0x00000000 len:0x00400000  flags:1 fd:6    offset:0xc4000000       to:0x40f88000

An example memory trace:

mem     ldr     0x0000000000130007      1       0x01c0e000      0x00000000      0x4006d000

Libc Functions
--------------
libc functions are intercepted in order to filter out the interesting actions and manage access to the mmaped memory.

The following libc functions are traced mmap,memcpy,memset and signal.

Memory Tracing
--------------
Memory tracing is performed in the same way as libsegfault for x86 but for the arm architecture. This works in the following manner:

1. Interept mmap calls, allocate memory using libc's mmap and then use mprotect to remove all access to the memory.
2. When the application attempts to read or write to an area of protected memory a segfault will be generated
3. A custom segfault handler is run which removes the protection of the memory area via mprotect
4. The instruction handler is then run which decodes the arm instruction, performs the requested operation and logs the details
5. After the instructions has been handled the memory is protected again and the instruction pointer is advanced to the next instruction.

Steps 2 through to 5 are handled for all memory access that the user land driver makes. The instruction handling code is capable of decoding and then performing the following arm instructions (thumb and thumb2 are not supported).

Load from memory

* ldr
* ldrh
* ldrsb
* ldrsh
* ldrd
* ldm

Store to memory

* str
* strh
* strb
* stm

This instruction handling is arm specific and could easily be used to trace memory access for any application which works with memory mapped io with a little bit of work.

usage
-----
The CedarX Wrapper works by using LD_PRELOAD to load libc library functions and replace them with its own. To get debug data you can use the [CedarXPlayerTest](https://github.com/iainb/CedarXPlayerTest).

Be warned the test player is very sensitive to latency during decoding, if it takes too long to decode the first frame then the decoder will get stuck in a loop and fail to decode video properly. That being said I have managed to decoded several minutes of video using the test player and the CedarX Wrapper. There are areas of the library that could be improved in terms of speed.

To play back a video file and dump the log data to a file (called out) the following command can work:

\# LD_PRELOAD=/path/to/libcedarx_wrap.so ./CedarXPlayerTest /path/to/samplemedia/big_buck_bunny_480p_H264_AAC_25fps_1800K_short.MP4 2> out > /dev/null

instruction output is currently in the following form (tab separated):

mem "instruction type" "data read or stored to memory" "physical address" "offset from base of mmaped region" "virtual address"

Building
--------
Execute 'make' in the root of the repository, I have been building and running this on a Mele A1000 running debian:

\#uname -a

Linux debian 3.0.31+ #1 PREEMPT Sat Jul 14 16:39:13 BST 2012 armv7l GNU/Linux

\#gcc --version

gcc (Debian 4.4.5-8) 4.4.5

There are also some very basic unit tests under the instructions_test directory.

I have not attempted to cross compile this library.

