CFLAGS= -I. -I../ -Werror
LDFLAGS=-lssl -lcrypto            \
        ../lib/khttp/libkhttp.a   \
        ../lib/parson/parson.c    \
        ../src/sm_api.c

all: user_api

user_api: user_api.o
	$(CC) -o user_api.exe user_api.o $(CFLAGS) $(LDFLAGS)

clean:
	rm -rf *.o *.exe

.PHONY: user_api
