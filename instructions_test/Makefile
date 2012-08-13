CFLAGS += -march=armv7-a -g -Wall -DDEBUG

all: test

clean:
	rm -f *.o

runtest:
	LD_PRELOAD=../libcedarx_wrap.so ./test

test: test.o
	$(CC) -o $@ $^
