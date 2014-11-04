CFLAGS= -I. -I../
LDFLAGS=-lssl -lcrypto            \
        ../lib/khttp/libkhttp.a   \
        ../lib/parson/parson.c    \
        ../src/sm_api.c

all: user_api device_api

user_api: user_api.o
	$(CC) -o user_api.exe user_api.o $(CFLAGS) $(LDFLAGS)

device_api: device_api.o
	$(CC) -o device_api.exe device_api.o $(CFLAGS) $(LDFLAGS)

clean:
	rm -rf *.o *.exe

.PHONY: user_api device_api
