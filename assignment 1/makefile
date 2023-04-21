CC = gcc
CCFLAGS = -O3
LIBS_RSA = -lgmp -lm
LIBS_DH = -lm
OBJS_RSA = rsa.o
OBJS_DH = dh.o
TARGET = rsa_assign_1 dh_assign_1

all: $(TARGET)

rsa_assign_1: $(OBJS_RSA)
	$(CC) $(CCFLAGS) -o rsa_assign_1 $(OBJS_RSA) $(LIBS_RSA)

dh_assign_1: $(OBJS_DH)
	$(CC) $(CCFLAGS) -o dh_assign_1 $(OBJS_DH) $(LIBS_DH)

clean:
	rm -f $(TARGET) *.o *.txt