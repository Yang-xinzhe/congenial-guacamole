#include "regs.h"
#include <stdio.h>

// regs_compare: compare two register states
uint32_t regs_compare(RegisterStates *regs1, RegisterStates *regs2) {
    uint32_t changed_mask = 0;
    
    // check general registers r0-r12
    if (regs1->r0 != regs2->r0) changed_mask |= REG_MASK_R0;
    if (regs1->r1 != regs2->r1) changed_mask |= REG_MASK_R1;
    if (regs1->r2 != regs2->r2) changed_mask |= REG_MASK_R2;
    if (regs1->r3 != regs2->r3) changed_mask |= REG_MASK_R3;
    if (regs1->r4 != regs2->r4) changed_mask |= REG_MASK_R4;
    if (regs1->r5 != regs2->r5) changed_mask |= REG_MASK_R5;
    if (regs1->r6 != regs2->r6) changed_mask |= REG_MASK_R6;
    if (regs1->r7 != regs2->r7) changed_mask |= REG_MASK_R7;
    if (regs1->r8 != regs2->r8) changed_mask |= REG_MASK_R8;
    if (regs1->r9 != regs2->r9) changed_mask |= REG_MASK_R9;
    if (regs1->r10 != regs2->r10) changed_mask |= REG_MASK_R10;
    if (regs1->r11 != regs2->r11) changed_mask |= REG_MASK_R11;
    if (regs1->r12 != regs2->r12) changed_mask |= REG_MASK_R12;
    
    // check special registers
    if (regs1->sp != regs2->sp) changed_mask |= REG_MASK_SP;
    if (regs1->lr != regs2->lr) changed_mask |= REG_MASK_LR;
    if (regs1->cpsr != regs2->cpsr) changed_mask |= REG_MASK_CPSR;
    
    return changed_mask;
}

// get processor mode name
const char* get_processor_mode_name(uint8_t mode) {
    switch(mode) {
        case CPSR_MODE_USR: return "USR (User)";
        case CPSR_MODE_FIQ: return "FIQ (Fast Interrupt)";
        case CPSR_MODE_IRQ: return "IRQ (Interrupt)";
        case CPSR_MODE_SVC: return "SVC (Supervisor)";
        case CPSR_MODE_MON: return "MON (Monitor)";
        case CPSR_MODE_ABT: return "ABT (Abort)";
        case CPSR_MODE_HYP: return "HYP (Hypervisor)";
        case CPSR_MODE_UND: return "UND (Undefined)";
        case CPSR_MODE_SYS: return "SYS (System)";
        default: return "UNKNOWN";
    }
}

// analyze CPSR changes in detail
CpsrAnalysisResult analyze_cpsr_changes(uint32_t before_cpsr, uint32_t after_cpsr) {
    CpsrAnalysisResult result = {0};
    
    result.before_value = before_cpsr;
    result.after_value = after_cpsr;
    result.changed = (before_cpsr != after_cpsr);
    
    if (!result.changed) {
        return result; // No changes
    }
    
    result.changed_bits = before_cpsr ^ after_cpsr;
    
    // Analyze condition flags [31:28]
    result.n_changed = (result.changed_bits & CPSR_FLAG_N) != 0;
    result.z_changed = (result.changed_bits & CPSR_FLAG_Z) != 0;
    result.c_changed = (result.changed_bits & CPSR_FLAG_C) != 0;
    result.v_changed = (result.changed_bits & CPSR_FLAG_V) != 0;
    result.flags_changed = result.n_changed || result.z_changed || 
                          result.c_changed || result.v_changed;
    
    // Analyze control bits [27:5]
    result.q_changed = (result.changed_bits & (1U << CPSR_Q_BIT)) != 0;
    result.j_changed = (result.changed_bits & (1U << CPSR_J_BIT)) != 0;
    result.e_changed = (result.changed_bits & (1U << CPSR_E_BIT)) != 0;
    result.a_changed = (result.changed_bits & (1U << CPSR_A_BIT)) != 0;
    result.i_changed = (result.changed_bits & (1U << CPSR_I_BIT)) != 0;
    result.f_changed = (result.changed_bits & (1U << CPSR_F_BIT)) != 0;
    result.t_changed = (result.changed_bits & (1U << CPSR_T_BIT)) != 0;
    result.it_changed = (result.changed_bits & (CPSR_IT1_MASK | CPSR_IT2_MASK)) != 0;
    result.ge_changed = (result.changed_bits & CPSR_GE_MASK) != 0;
    
    result.control_changed = result.q_changed || result.j_changed || 
                           result.e_changed || result.a_changed ||
                           result.i_changed || result.f_changed ||
                           result.t_changed || result.it_changed ||
                           result.ge_changed;
    
    // Analyze mode field [4:0] - CRITICAL!
    result.before_mode = before_cpsr & CPSR_MODE_MASK;
    result.after_mode = after_cpsr & CPSR_MODE_MASK;
    result.mode_changed = (result.before_mode != result.after_mode);
    result.before_mode_name = get_processor_mode_name(result.before_mode);
    result.after_mode_name = get_processor_mode_name(result.after_mode);
    
    // Security assessment
    if (result.mode_changed) {
        result.security_level = CPSR_CRITICAL;
    } else if (result.control_changed) {
        // Check if system control bits changed
        if (result.i_changed || result.f_changed || result.a_changed) {
            result.security_level = CPSR_DANGEROUS;
        } else {
            result.security_level = CPSR_SUSPICIOUS;
        }
    } else if (result.flags_changed) {
        result.security_level = CPSR_SAFE;
    }
    
    return result;
}

// print detailed CPSR analysis
void print_cpsr_analysis(CpsrAnalysisResult *cpsr_result) {
    if (!cpsr_result->changed) {
        printf("  No CPSR changes\n");
        return;
    }
    
    printf("=== Detailed CPSR Analysis ===\n");
    printf("CPSR: 0x%08X -> 0x%08X (changed bits: 0x%08X)\n",
           cpsr_result->before_value, cpsr_result->after_value, 
           cpsr_result->changed_bits);
    
    // Security level
    const char* security_levels[] = {"SAFE", "SUSPICIOUS", "DANGEROUS", "CRITICAL"};
    printf("Security Level: %s\n", security_levels[cpsr_result->security_level]);
    
    // Condition flags analysis [31:28]
    if (cpsr_result->flags_changed) {
        printf("\nCondition Flags [31:28] Changes:\n");
        if (cpsr_result->n_changed) {
            printf("  N (Negative):  %d -> %d\n",
                   (cpsr_result->before_value & CPSR_FLAG_N) ? 1 : 0,
                   (cpsr_result->after_value & CPSR_FLAG_N) ? 1 : 0);
        }
        if (cpsr_result->z_changed) {
            printf("  Z (Zero):      %d -> %d\n",
                   (cpsr_result->before_value & CPSR_FLAG_Z) ? 1 : 0,
                   (cpsr_result->after_value & CPSR_FLAG_Z) ? 1 : 0);
        }
        if (cpsr_result->c_changed) {
            printf("  C (Carry):     %d -> %d\n",
                   (cpsr_result->before_value & CPSR_FLAG_C) ? 1 : 0,
                   (cpsr_result->after_value & CPSR_FLAG_C) ? 1 : 0);
        }
        if (cpsr_result->v_changed) {
            printf("  V (Overflow):  %d -> %d\n",
                   (cpsr_result->before_value & CPSR_FLAG_V) ? 1 : 0,
                   (cpsr_result->after_value & CPSR_FLAG_V) ? 1 : 0);
        }
    }
    
    // Control bits analysis [27:5]
    if (cpsr_result->control_changed) {
        printf("\nControl Bits [27:5] Changes:\n");
        if (cpsr_result->q_changed) {
            printf("  Q (Saturation): %d -> %d\n",
                   (cpsr_result->before_value & (1U << CPSR_Q_BIT)) ? 1 : 0,
                   (cpsr_result->after_value & (1U << CPSR_Q_BIT)) ? 1 : 0);
        }
        if (cpsr_result->j_changed) {
            printf("  J (Jazelle):    %d -> %d\n",
                   (cpsr_result->before_value & (1U << CPSR_J_BIT)) ? 1 : 0,
                   (cpsr_result->after_value & (1U << CPSR_J_BIT)) ? 1 : 0);
        }
        if (cpsr_result->ge_changed) {
            printf("  GE (SIMD):      0x%X -> 0x%X\n",
                   (cpsr_result->before_value & CPSR_GE_MASK) >> 16,
                   (cpsr_result->after_value & CPSR_GE_MASK) >> 16);
        }
        if (cpsr_result->it_changed) {
            printf("  IT (If-Then):   changed\n");
        }
        if (cpsr_result->e_changed) {
            printf("  E (Endian):     %d -> %d\n",
                   (cpsr_result->before_value & (1U << CPSR_E_BIT)) ? 1 : 0,
                   (cpsr_result->after_value & (1U << CPSR_E_BIT)) ? 1 : 0);
        }
        if (cpsr_result->a_changed) {
            printf("  A (Abort Dis):  %d -> %d\n",
                   (cpsr_result->before_value & (1U << CPSR_A_BIT)) ? 1 : 0,
                   (cpsr_result->after_value & (1U << CPSR_A_BIT)) ? 1 : 0);
        }
        if (cpsr_result->i_changed) {
            printf("  I (IRQ Dis):    %d -> %d\n",
                   (cpsr_result->before_value & (1U << CPSR_I_BIT)) ? 1 : 0,
                   (cpsr_result->after_value & (1U << CPSR_I_BIT)) ? 1 : 0);
        }
        if (cpsr_result->f_changed) {
            printf("  F (FIQ Dis):    %d -> %d\n",
                   (cpsr_result->before_value & (1U << CPSR_F_BIT)) ? 1 : 0,
                   (cpsr_result->after_value & (1U << CPSR_F_BIT)) ? 1 : 0);
        }
        if (cpsr_result->t_changed) {
            printf("  T (Thumb):      %d -> %d\n",
                   (cpsr_result->before_value & (1U << CPSR_T_BIT)) ? 1 : 0,
                   (cpsr_result->after_value & (1U << CPSR_T_BIT)) ? 1 : 0);
        }
    }
    
    // Mode field analysis [4:0] - CRITICAL!
    if (cpsr_result->mode_changed) {
        printf("\n*** CRITICAL: Processor Mode [4:0] Changed! ***\n");
        printf("  Mode: 0x%02X (%s) -> 0x%02X (%s)\n",
               cpsr_result->before_mode, cpsr_result->before_mode_name,
               cpsr_result->after_mode, cpsr_result->after_mode_name);
        printf("  This indicates potential privilege escalation!\n");
    }
    
    printf("\n");
}

// regs_compare_detailed: compare two register states
RegisterCompareResult regs_compare_detailed(RegisterStates *before, RegisterStates *after) {
    RegisterCompareResult result = {0};
    
    // get basic changed mask
    result.changed_mask = regs_compare(before, after);
    
    // count general registers changes
    uint32_t general_mask = result.changed_mask & REG_MASK_GENERAL;
    result.general_changes = 0;
    for (int i = 0; i < 13; i++) {
        if (general_mask & (1U << i)) result.general_changes++;
    }
    
    // count special registers changes
    uint32_t special_mask = (REG_MASK_SP | REG_MASK_LR);
    uint32_t special_changed = result.changed_mask & special_mask;
    result.special_changes = 0;
    if (special_changed & REG_MASK_SP) result.special_changes++;
    if (special_changed & REG_MASK_LR) result.special_changes++;
    
    // check CPSR changes (basic)
    result.cpsr_changed = (before->cpsr != after->cpsr);
    if (result.cpsr_changed) {
        // analyze CPSR flags changes (simple)
        uint32_t cpsr_diff = before->cpsr ^ after->cpsr;
        result.cpsr_flags_changed = cpsr_diff & CPSR_FLAGS_MASK;
        
        // detailed CPSR analysis
        result.cpsr_analysis = analyze_cpsr_changes(before->cpsr, after->cpsr);
    }
    
    return result;
}

// print register changes
void print_register_changes(RegisterStates *before, RegisterStates *after, RegisterCompareResult *result) {
    printf("=== register changes analysis ===\n");
    
    if (result->changed_mask == 0) {
        printf("no register changes\n");
        return;
    }
    
    printf("changes statistics: general registers=%d, special registers=%d\n", 
           result->general_changes, result->special_changes);
    
    // print general registers changes
    if (result->general_changes > 0) {
        printf("\ngeneral registers changes:\n");
        if (result->changed_mask & REG_MASK_R0)  
            printf("  R0:  0x%08X -> 0x%08X\n", before->r0, after->r0);
        if (result->changed_mask & REG_MASK_R1)  
            printf("  R1:  0x%08X -> 0x%08X\n", before->r1, after->r1);
        if (result->changed_mask & REG_MASK_R2)  
            printf("  R2:  0x%08X -> 0x%08X\n", before->r2, after->r2);
        if (result->changed_mask & REG_MASK_R3)  
            printf("  R3:  0x%08X -> 0x%08X\n", before->r3, after->r3);
        if (result->changed_mask & REG_MASK_R4)  
            printf("  R4:  0x%08X -> 0x%08X\n", before->r4, after->r4);
        if (result->changed_mask & REG_MASK_R5)  
            printf("  R5:  0x%08X -> 0x%08X\n", before->r5, after->r5);
        if (result->changed_mask & REG_MASK_R6)  
            printf("  R6:  0x%08X -> 0x%08X\n", before->r6, after->r6);
        if (result->changed_mask & REG_MASK_R7)  
            printf("  R7:  0x%08X -> 0x%08X\n", before->r7, after->r7);
        if (result->changed_mask & REG_MASK_R8)  
            printf("  R8:  0x%08X -> 0x%08X\n", before->r8, after->r8);
        if (result->changed_mask & REG_MASK_R9)  
            printf("  R9:  0x%08X -> 0x%08X\n", before->r9, after->r9);
        if (result->changed_mask & REG_MASK_R10) 
            printf("  R10: 0x%08X -> 0x%08X\n", before->r10, after->r10);
        if (result->changed_mask & REG_MASK_R11) 
            printf("  R11: 0x%08X -> 0x%08X\n", before->r11, after->r11);
        if (result->changed_mask & REG_MASK_R12) 
            printf("  R12: 0x%08X -> 0x%08X\n", before->r12, after->r12);
    }
    
    // print special registers changes
    if (result->special_changes > 0) {
        printf("\nspecial registers changes:\n");
        if (result->changed_mask & REG_MASK_SP)  
            printf("  SP:  0x%08X -> 0x%08X\n", before->sp, after->sp);
        if (result->changed_mask & REG_MASK_LR)  
            printf("  LR:  0x%08X -> 0x%08X\n", before->lr, after->lr);
    }
    
    // print detailed CPSR analysis
    if (result->cpsr_changed) {
        printf("\n");
        print_cpsr_analysis(&result->cpsr_analysis);
    }
}

// check if specific register has changed
bool regs_has_change(RegisterCompareResult *result, uint32_t reg_mask) {
    return (result->changed_mask & reg_mask) != 0;
}