# Makefile for register-analysis ARM32 tools

CC = arm-linux-gnueabihf-gcc
CFLAGS = -marm -march=armv8-a -mfpu=vfpv4 -fomit-frame-pointer -mfloat-abi=hard
LDFLAGS = -static

# Targets
TARGETS = reg_compare macro_analyzer

.PHONY: all clean

all: $(TARGETS)

reg_compare: reg_compare.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

macro_analyzer: macro_analyzer.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGETS)

# Debug versions
debug: CFLAGS += -g -O0 -DDEBUG
debug: $(TARGETS)

# Test target for reg_compare with a known instruction
test: reg_compare
	@echo "Testing reg_compare with MOV R3, #0x55 instruction..."
	./reg_compare 0xE3A03055

# Install target (optional)
install: all
	@echo "Installation not implemented. Copy binaries to target ARM32 system."

.PHONY: debug test install 