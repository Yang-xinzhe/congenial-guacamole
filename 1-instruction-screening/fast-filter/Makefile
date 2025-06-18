# Makefile for fast-filter ARM32 instruction checking tools

CC = arm-linux-gnueabihf-gcc
CFLAGS = -marm -march=armv8-a -mfpu=vfpv4 -fomit-frame-pointer -mfloat-abi=hard
LDFLAGS = -static

# Targets
TARGETS = ins_check inst_testframe

.PHONY: all clean

all: $(TARGETS)

ins_check: ins_check.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

inst_testframe: inst_testframe.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGETS)

# Debug version
debug: CFLAGS += -g -O0 -DDEBUG
debug: ins_check

# Install target (optional)
install: all
	@echo "Installation not implemented. Copy binaries to target ARM32 system."

.PHONY: debug install 