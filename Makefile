
OS := $(shell uname)
LIBS := -levent -lm -largp
CFLAGS +=-fPIC -O3
override CFLAGS += -D_BSD_SOURCE -D_DEFAULT_SOURCE -Wall
ifeq ($(OS), Linux)
override CFLAGS += -std=c99 -D_XOPEN_SOURCE=600
endif

OBJ = main.o log.o cfg.o json.o cdns.o dns.o blacklist.o util.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

cdns: $(OBJ)
	$(CC) -o $@ $(CFLAGS) $^ $(LIBS)
	$(CC) -static -static-libgcc -s -o $@-static $(CFLAGS) $^ $(LIBS)

all: cdns

clean:
	rm -f *.o cdns
