# Makefile for pmu-analysis ARM32 tools

CC = arm-linux-gnueabihf-gcc
CFLAGS = -marm -march=armv8-a -mfpu=vfpv4 -fomit-frame-pointer -mfloat-abi=hard

# Targets
TARGETS = pmu_test

.PHONY: all clean

all: $(TARGETS)

pmu_test: pmu_test.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGETS)

# Debug version
debug: CFLAGS += -g -O0 -DDEBUG
debug: pmu_test

# Install target (optional)
install: all
	@echo "Installation not implemented. Copy binaries to target ARM32 system."
	@echo "Note: PMU access requires special privileges on target system."

.PHONY: debug install 