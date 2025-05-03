CC = gcc
CFLAGS = -Wall -Wextra
INCLUDES = -I./minhook/include
LIBS = -L./minhook/lib -lMinHook.x64

# Default target
all: test

# Build the test executable
test: hooks/test.c
	$(CC) $(CFLAGS) $(INCLUDES) -o test.exe hooks/test.c $(LIBS)

# Clean up
clean:
	rm -f test.exe

.PHONY: all clean