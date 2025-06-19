#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/shm.h>
#include <sys/mman.h> 
#include <string.h>
#include <ucontext.h>
#include <signal.h>
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sched.h>
#include <errno.h>

typedef struct {
    int ld_retired_fd;
    int st_retired_fd;
} PmuCounter;

typedef struct {
    uint64_t ld_count;
    uint64_t st_count;
} TestResult;


static PmuCounter g_pmu = {0};

static int perf_event_open(struct perf_event_attr *hw_event, pid_t pid, int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

int init_memory_monitor(PmuCounter *pmu);
uint64_t test_load_only(uint8_t *insn_bytes, size_t insn_length);
uint64_t test_store_only(uint8_t *insn_bytes, size_t insn_length);
void print_test_result(uint32_t instruction, TestResult *result);