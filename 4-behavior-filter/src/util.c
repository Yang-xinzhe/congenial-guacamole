#include "util.h"

int init_insn_page(void) {
    insn_page = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if(insn_page == MAP_FAILED) {
        perror("insn_mmap failed");
        return 1;
    }

    insn_test_plate_length = (&insn_test_plate_end - &insn_test_plate_begin);
    // printf("Debug: template length = %d bytes\n", insn_test_plate_length);
    memcpy(insn_page, &insn_test_plate_begin, insn_test_plate_length);

    insn_offset = (&insn_location - &insn_test_plate_begin) / 4;
    
    // printf("Debug: insn_offset=%d\n", insn_offset);
    
    return 0;
}

size_t fill_insn_buffer(uint8_t *buf, size_t buf_size, uint32_t insn)
{
    if (buf_size < 4)
        return 0;
 
    else {
        buf[0] = insn & 0xff;
        buf[1] = (insn >> 8) & 0xff;
        buf[2] = (insn >> 16) & 0xff;
        buf[3] = (insn >> 24) & 0xff;
    }
    return 4;
}