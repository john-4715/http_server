#CC=arm-buildroot-linux-gnueabihf-g++
CC=g++
CFLAGS=-Wall -std=c++11 -g -fsanitize=address -fno-omit-frame-pointer
TARGET=httpserver

LDFLAGS=-L./libjson -L/usr/local/lib
IFLAGS=-I./libjson -I/usr/local/include
LIB=-levent -levent_openssl -lssl -lcrypto -lJsonObjects -liniparser

OBJS = main.o openssl_base.o https_server.o certProtocol.o certMgr.o utils.o ini_wrapper.o 
$(TARGET): $(OBJS)
	$(CC)  $(IFLAGS) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIB)

%.o: %.cpp
	$(CC) $(IFLAGS) $(CFLAGS) -c -o $@ $^ $(LDFLAGS) $(LIB)

clean:
	rm -f app *.o $(TARGET) 
