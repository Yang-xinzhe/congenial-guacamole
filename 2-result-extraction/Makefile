# Makefile for result-extraction tools (x86 host)

CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2

# Targets
TARGETS = batch_extract filter

.PHONY: all clean

all: $(TARGETS)

batch_extract: batch_extract.c
	$(CC) $(CFLAGS) -o $@ $<

filter: filter.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGETS)
	rm -rf extracted_instructions/

# Debug versions
debug: CFLAGS += -g -O0 -DDEBUG
debug: $(TARGETS)

# Extract all using the shell script
extract: batch_extract
	./extract_all_simple.sh

# Process samples using the shell script
process: all
	./process_samples.sh

# Install target
install: all
	@echo "Copying binaries to /usr/local/bin (requires sudo)"
	sudo cp $(TARGETS) /usr/local/bin/

.PHONY: debug extract process install 