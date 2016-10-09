
OS := $(shell uname)
LIBS := -levent -lm
STATIC_LIBS := 
CFLAGS +=-fPIC -O3
override CFLAGS += -D_BSD_SOURCE -D_DEFAULT_SOURCE
ifeq ($(OS), Linux)
override CFLAGS += -std=c99 -D_XOPEN_SOURCE=600
endif

all: main.c log.c cfg.c json.c cdns.c
	$(CC) -o cdns $(CFLAGS) $(LIBS) $^ $(STATIC_LIBS)

clean:
	rm -f *.o cdns
