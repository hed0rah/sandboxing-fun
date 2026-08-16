# Hardening is explicit rather than inherited. Ubuntu's gcc enables PIE, RELRO,
# stack protector and FORTIFY through its own spec defaults, so a build here
# looks hardened while the same Makefile on Alma, Debian or Alpine produces a
# binary with none of it. For an example whose subject is security, state it.
CFLAGS  ?= -Wall -Wextra -Wpedantic -O2 -D_FORTIFY_SOURCE=2 \
           -fstack-protector-strong -fPIE
LDFLAGS ?= -pie -Wl,-z,relro,-z,now,-z,noexecstack

all: sandbox
sandbox: sandbox.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)
clean:
	rm -f sandbox
.PHONY: all clean
