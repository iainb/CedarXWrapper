CFLAGS += -march=armv7-a -O3 -fPIC -g -Wall -DDEBUG

all: libcedarx_wrap.so

log.i: log.c log.h

instructions.o: instructions.c instructions.h

mappings.o: mappings.c mappings.h

wrap_libve.o: wrap_libve.c libve.h wrap_libve.h

wrap.o: wrap.c wrap.h

clean:
	rm -f *.o
	rm -f *.so

libcedarx_wrap.so: log.o mappings.o instructions.o wrap_libve.o wrap.o
	$(CC) -shared -Wl -o $@ $^ -ldl
