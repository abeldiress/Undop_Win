CC = gcc
CFLAGS = -I./Include
LDFLAGS = -L./Lib/x64/ -lwpcap -lws2_32
TARGET = undop.exe
SRCS = undop.c

build:
	$(CC) $(SRCS) -o $(TARGET) $(CFLAGS) $(LDFLAGS)

clean:
	$(RM) $(TARGET)

.PHONY: build clean
