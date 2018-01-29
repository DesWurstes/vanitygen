LIBS=-lpcre -lcrypto -lm -lpthread
CFLAGS=-ggdb -Wall
OBJS=vanitygen.o oclvanitygen.o oclvanityminer.o oclengine.o keyconv.o pattern.o util.o cashaddr.o
PROGS=vanitygen keyconv oclvanitygen oclvanityminer
# OPTIMIZE
# -O0 = no optimization
# -O3 = good optimization
# -Ofast = aggressive optimization
# -Os = small file size
CFLAGS+=-O0

PLATFORM=$(shell uname -s)
ifeq ($(PLATFORM),Darwin)
	ifneq ($(wildcard /usr/local/Cellar/gcc/7.3.0/bin/*),)
		CC=/usr/local/Cellar/gcc/7.3.0/bin/g++-7
	endif
	OPENCL_LIBS=-framework OpenCL
	LIBS+=-L/usr/local/opt/pcre/lib
	CFLAGS +=-I/usr/local/opt/pcre/include
	LIBS+=-L/usr/local/opt/openssl/lib
	CFLAGS+=-I/usr/local/opt/openssl/include
	CFLAGS+=-D_GLIBCXX_USE_CXX11_ABI=0
else
	OPENCL_LIBS=-lOpenCL
endif

most: vanitygen keyconv

all: $(PROGS)

vanitygen: vanitygen.o pattern.o util.o cashaddr.o
	$(CC) $^ -o $@ $(CFLAGS) $(LIBS)

oclvanitygen: oclvanitygen.o oclengine.o pattern.o util.o cashaddr.o
	$(CC) $^ -o $@ $(CFLAGS) $(LIBS) $(OPENCL_LIBS)

oclvanityminer: oclvanityminer.o oclengine.o pattern.o util.o cashaddr.o
	$(CC) $^ -o $@ $(CFLAGS) $(LIBS) $(OPENCL_LIBS) -lcurl

keyconv: keyconv.o util.o cashaddr.o
	$(CC) $^ -o $@ $(CFLAGS) $(LIBS)

clean:
	rm -f $(OBJS) $(PROGS) $(TESTS)
