CC = gcc
CCFLAGS = -Wall -O3
LIBS = -L/usr/lib -lssl -lcrypto
OBJS_CLIENT = client.o
OBJS_SERVER = server.o
TARGET = client server

all: $(TARGET)

client: $(OBJS_CLIENT)
	$(CC) $(CCFLAGS) -o client $(OBJS_CLIENT) $(LIBS)

server: $(OBJS_SERVER)
	$(CC) $(CCFLAGS) -o server $(OBJS_SERVER) $(LIBS)

clean:
	rm -f $(TARGET) *.o *.txt