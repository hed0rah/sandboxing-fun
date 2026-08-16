CFLAGS ?= -Wall -Wextra -O2
all: sandbox
sandbox: sandbox.c
	$(CC) $(CFLAGS) $< -o $@
clean:
	rm -f sandbox
.PHONY: all clean
