#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/shm.h>
#include <sys/mman.h> 
#include <string.h>

typedef __attribute__((aligned(4))) struct {
    uint32_t r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12;
    uint32_t sp, lr, pc;
    uint32_t cpsr;
} RegisterStates;

// bit mask for registers
#define REG_MASK_R0     (1U << 0)
#define REG_MASK_R1     (1U << 1)
#define REG_MASK_R2     (1U << 2)
#define REG_MASK_R3     (1U << 3)
#define REG_MASK_R4     (1U << 4)
#define REG_MASK_R5     (1U << 5)
#define REG_MASK_R6     (1U << 6)
#define REG_MASK_R7     (1U << 7)
#define REG_MASK_R8     (1U << 8)
#define REG_MASK_R9     (1U << 9)
#define REG_MASK_R10    (1U << 10)
#define REG_MASK_R11    (1U << 11)
#define REG_MASK_R12    (1U << 12)
#define REG_MASK_SP     (1U << 13)
#define REG_MASK_LR     (1U << 14)
#define REG_MASK_PC     (1U << 15)
#define REG_MASK_CPSR   (1U << 16)

// general registers mask (r0-r12)
#define REG_MASK_GENERAL    0x1FFF  // first 13 bits

// CPSR flags mask
#define CPSR_FLAG_N     (1U << 31)  // negative flag
#define CPSR_FLAG_Z     (1U << 30)  // zero flag  
#define CPSR_FLAG_C     (1U << 29)  // carry flag
#define CPSR_FLAG_V     (1U << 28)  // overflow flag
#define CPSR_FLAGS_MASK 0xF0000000  // all condition flags

// Detailed CPSR bit definitions
// Condition flags [31:28]
#define CPSR_N_BIT      31
#define CPSR_Z_BIT      30  
#define CPSR_C_BIT      29
#define CPSR_V_BIT      28

// Other status bits [27:5]
#define CPSR_Q_BIT      27          // Cumulative saturation
#define CPSR_IT1_MASK   (3U << 25)  // IT[1:0] If-Then execution state
#define CPSR_J_BIT      24          // Jazelle state bit
#define CPSR_GE_MASK    (0xFU << 16) // GE[3:0] SIMD Greater than or Equal
#define CPSR_IT2_MASK   (0x3FU << 10) // IT[7:2] If-Then execution state  
#define CPSR_E_BIT      9           // Endianness execution state
#define CPSR_A_BIT      8           // Asynchronous abort disable
#define CPSR_I_BIT      7           // IRQ disable
#define CPSR_F_BIT      6           // FIQ disable
#define CPSR_T_BIT      5           // Thumb execution state

// Processor mode bits [4:0] - Most important!
#define CPSR_MODE_MASK  0x1F        // Mode field mask
#define CPSR_MODE_USR   0x10        // User mode
#define CPSR_MODE_FIQ   0x11        // FIQ mode
#define CPSR_MODE_IRQ   0x12        // IRQ mode
#define CPSR_MODE_SVC   0x13        // Supervisor mode
#define CPSR_MODE_MON   0x16        // Monitor mode
#define CPSR_MODE_ABT   0x17        // Abort mode
#define CPSR_MODE_HYP   0x1A        // Hypervisor mode
#define CPSR_MODE_UND   0x1B        // Undefined mode
#define CPSR_MODE_SYS   0x1F        // System mode

// CPSR detailed analysis result
typedef struct {
    bool changed;                   // CPSR changed
    uint32_t before_value;         // CPSR before value
    uint32_t after_value;          // CPSR after value
    uint32_t changed_bits;         // XOR result: which bits changed
    
    // Condition flags analysis [31:28]
    bool flags_changed;            // Any condition flag changed
    bool n_changed;                // N flag changed
    bool z_changed;                // Z flag changed
    bool c_changed;                // C flag changed
    bool v_changed;                // V flag changed
    
    // Control bits analysis [27:5]
    bool control_changed;          // Any control bit changed
    bool q_changed;                // Q bit changed
    bool j_changed;                // J bit changed
    bool e_changed;                // E bit changed
    bool a_changed;                // A bit changed
    bool i_changed;                // I bit changed (IRQ)
    bool f_changed;                // F bit changed (FIQ)
    bool t_changed;                // T bit changed (Thumb)
    bool it_changed;               // IT field changed
    bool ge_changed;               // GE field changed
    
    // Mode field analysis [4:0] - Critical!
    bool mode_changed;             // Mode field changed
    uint8_t before_mode;           // Mode before (5 bits)
    uint8_t after_mode;            // Mode after (5 bits)
    const char* before_mode_name;  // Mode name before
    const char* after_mode_name;   // Mode name after
    
    // Security assessment
    enum {
        CPSR_SAFE = 0,             // Only condition flags changed
        CPSR_SUSPICIOUS = 1,       // Execution state changed
        CPSR_DANGEROUS = 2,        // System control changed  
        CPSR_CRITICAL = 3          // CPU mode changed
    } security_level;
    
} CpsrAnalysisResult;

// register compare result structure
typedef struct {
    uint32_t changed_mask;        // bit mask: which registers changed
    uint32_t general_changes;     // general registers changes (r0-r12)
    uint32_t special_changes;     // special registers changes (sp,lr,pc)
    bool cpsr_changed;           // CPSR changed
    uint32_t cpsr_flags_changed; // CPSR flags changed mask (NZCV)
    CpsrAnalysisResult cpsr_analysis; // Detailed CPSR analysis
} RegisterCompareResult;

typedef struct {
    uint16_t changed_regs; // R0-R12 which reg changed

    uint8_t SP : 1; // R13 (Stack Pointer)
    uint8_t LR : 1; // R14 (Link Register)
} RegChangeInfo;

typedef struct {
    // [31:28]
    uint8_t N : 1;  // Negative
    uint8_t Z : 1;  // '0'
    uint8_t C : 1;  // Progression
    uint8_t V : 1;  // Overflow
    // [27]
    uint8_t Q : 1; // Cumulative Saturation
    // [26:25]  IT[1:0]
    // [24]
    uint8_t J : 1; // Jazelle
    // [23:20] Reserved
    // [19:16]
    uint8_t GE : 1; // SIMD Greater Than
    // [15:10]  IT[7:2]
    // [9]
    uint8_t E : 1; // Control Load/Store
    // [8]
    uint8_t A : 1; // disables asynchronous abort
    // [7]
    uint8_t I : 1; // IRQ mode
    // [6]
    uint8_t F : 1; // FIQ mode
    // [5]
    uint8_t T : 1; // Thumb state
    // [4:0]
    uint8_t M : 1; // FIQ IRQ SVC ABT UND MON HYP
    // Change details
    uint32_t before_value;
    uint32_t after_value;
    uint32_t changed_mask; // Which bit changed
    enum{
        SAFE = 0, // Only Condition Flags Changed
        SUSPICIOUS = 1, // Execute State Changed
        DANGEROUS = 2, // System Control Changed
        CRITICAL = 3 // CPU Mode Changed
    } security_level;
    
} CpsrChangeInfo;

// function declarations
uint32_t regs_compare(RegisterStates *regs1, RegisterStates *regs2);
RegisterCompareResult regs_compare_detailed(RegisterStates *before, RegisterStates *after);
void print_register_changes(RegisterStates *before, RegisterStates *after, RegisterCompareResult *result);
bool regs_has_change(RegisterCompareResult *result, uint32_t reg_mask);

// CPSR analysis functions
CpsrAnalysisResult analyze_cpsr_changes(uint32_t before_cpsr, uint32_t after_cpsr);
void print_cpsr_analysis(CpsrAnalysisResult *cpsr_result);
const char* get_processor_mode_name(uint8_t mode);


