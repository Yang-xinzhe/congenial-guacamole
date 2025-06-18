# Makefile for timeout-filter ARM32 instruction checking tools

CC = arm-linux-gnueabihf-gcc
CFLAGS = -marm -march=armv8-a -mfpu=vfpv4 -fomit-frame-pointer -mfloat-abi=hard

# Targets
TARGETS = dispatcher single_check

.PHONY: all clean

all: $(TARGETS)

dispatcher: dispatcher.c
	$(CC) $(CFLAGS) -o $@ $<

single_check: single_check.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGETS)

# Debug versions
debug: CFLAGS += -g -O0 -DDEBUG
debug: $(TARGETS)

# Install target (optional)
install: all
	@echo "Installation not implemented. Copy binaries to target ARM32 system."

.PHONY: debug install 