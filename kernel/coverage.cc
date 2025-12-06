#include "coverage.h"
#include "task.h"

#include <kern/task.h>
#include <kern/thread.h>
#include <mach/mach_types.h>
#include <sys/proc.h>

#define str(s) #s
#define xstr(s) str(s)
#define REPEAT_COUNT_THUNK 750000

extern "C" {

alignas(16 * 1024) __attribute__((section("__DATA,__cov"))) UInt64
    coverage_bitmap[KCOV_COVERAGE_BITMAP_SIZE / sizeof(UInt64)];

UInt64 curr_location = 0;
UInt64 prev_location = 0;

Bool collect_coverage = false;
// Flag to specify that we're fuzzing from userspace. This adds additional logic to coverage
// collection So that we only track basic block edges coming from the userspace portion of the
// harness When fuzzing inside of the kernel, initiate the harness from userspace by setting the
// FuzzContext This flag will automatically flip to false when triggering the fuzz in kernel logic
// from the IOUserClient
Bool userspace = true;

#ifdef __arm64__
void instrument_thunks() {
    asm volatile(".rept " xstr(
        REPEAT_COUNT_THUNK) "\n"                         // Repeat the following block many times
                            "    STR x30, [sp, #-16]!\n" // save LR. we can't restore it in
                                                         // pop_regs. as we have jumped here.
                            "    BL _push_regs\n"
                            "    MOV x0, #0x0000\n"      // placeholder targeted_kext flag.
                            "    MOV x1, #0x4141\n" // fix the correct numner when instrumenting as
                                                    // arg0.
                            "    MOV x1, #0x4141\n" // placeholder for BB address
                            "    MOV x1, #0x4141\n"
                            "    MOV x1, #0x4141\n"
                            "    BL _sanitizer_cov_trace_pc\n"
                            "    BL _pop_regs\n"
                            "    LDR x30, [sp], #16\n" // restore LR
                            "    NOP\n"                // placeholder for original inst.
                            "    NOP\n"                // placeholder for jump back
                            ".endr\n"                  // End of repetition
    );
}

void push_regs() {
    __asm__ __volatile__("SUB sp, sp, #0x100\n"
                         "STR xzr, [sp, #0xf8]\n"
                         "STR x29, [sp, #0xe8]\n"
                         "STR x28, [sp, #0xe0]\n"
                         "STR x27, [sp, #0xd8]\n"
                         "STR x26, [sp, #0xd0]\n"
                         "STR x25, [sp, #0xc8]\n"
                         "STR x24, [sp, #0xc0]\n"
                         "STR x23, [sp, #0xb8]\n"
                         "STR x22, [sp, #0xb0]\n"
                         "STR x21, [sp, #0xa8]\n"
                         "STR x20, [sp, #0xa0]\n"
                         "STR x19, [sp, #0x98]\n"
                         "STR x18, [sp, #0x90]\n"
                         "STR x17, [sp, #0x88]\n"
                         "STR x16, [sp, #0x80]\n"
                         "STR x15, [sp, #0x78]\n"
                         "STR x14, [sp, #0x70]\n"
                         "STR x13, [sp, #0x68]\n"
                         "STR x12, [sp, #0x60]\n"
                         "STR x11, [sp, #0x58]\n"
                         "STR x10, [sp, #0x50]\n"
                         "STR x9, [sp, #0x48]\n"
                         "STR x8, [sp, #0x40]\n"
                         "STR x7, [sp, #0x38]\n"
                         "STR x6, [sp, #0x30]\n"
                         "STR x5, [sp, #0x28]\n"
                         "STR x4, [sp, #0x20]\n"
                         "STR x3, [sp, #0x18]\n"
                         "STR x2, [sp, #0x10]\n"
                         "STR x1, [sp, #0x8]\n"
                         "STR x0, [sp]\n"
                         "SUB sp, sp, #0x50\n"
                         "RET");
}

void pop_regs() {
    __asm__ __volatile__("ADD sp, sp, #0x50\n"
                         "LDR xzr, [sp, #0xf8]\n"
                         "LDR x29, [sp, #0xe8]\n"
                         "LDR x28, [sp, #0xe0]\n"
                         "LDR x27, [sp, #0xd8]\n"
                         "LDR x26, [sp, #0xd0]\n"
                         "LDR x25, [sp, #0xc8]\n"
                         "LDR x24, [sp, #0xc0]\n"
                         "LDR x23, [sp, #0xb8]\n"
                         "LDR x22, [sp, #0xb0]\n"
                         "LDR x21, [sp, #0xa8]\n"
                         "LDR x20, [sp, #0xa0]\n"
                         "LDR x19, [sp, #0x98]\n"
                         "LDR x18, [sp, #0x90]\n"
                         "LDR x17, [sp, #0x88]\n"
                         "LDR x16, [sp, #0x80]\n"
                         "LDR x15, [sp, #0x78]\n"
                         "LDR x14, [sp, #0x70]\n"
                         "LDR x13, [sp, #0x68]\n"
                         "LDR x12, [sp, #0x60]\n"
                         "LDR x11, [sp, #0x58]\n"
                         "LDR x10, [sp, #0x50]\n"
                         "LDR x9, [sp, #0x48]\n"
                         "LDR x8, [sp, #0x40]\n"
                         "LDR x7, [sp, #0x38]\n"
                         "LDR x6, [sp, #0x30]\n"
                         "LDR x5, [sp, #0x28]\n"
                         "LDR x4, [sp, #0x20]\n"
                         "LDR x3, [sp, #0x18]\n"
                         "LDR x2, [sp, #0x10]\n"
                         "LDR x1, [sp, #0x8]\n"
                         "LDR x0, [sp]\n"
                         "ADD sp, sp, #0x100\n"
                         "RET\n");
}

#endif

UInt8* sanitizer_cov_get_bitmap() {
    return (UInt8*)coverage_bitmap;
}

void sanitizer_cov_enable_coverage() {
    collect_coverage = true;
}

void sanitizer_cov_disable_coverage() {
    collect_coverage = false;
    memset(coverage_bitmap, 0, KCOV_COVERAGE_BITMAP_SIZE);
}

void sanitizer_cov_trace_pc(UInt16 kext, UInt64 address) {
    if (collect_coverage) {
        /* Kernel-only coverage tracking using a bitmap */
        curr_location = address & ((KCOV_COVERAGE_BITMAP_SIZE / sizeof(UInt64)) - 1);
        /* AFL-style edge tracking */
        coverage_bitmap[curr_location ^ prev_location]++;
        prev_location = curr_location >> 1;
    }
}

void sanitizer_cov_trace_lr(UInt16 kext) {}
}
