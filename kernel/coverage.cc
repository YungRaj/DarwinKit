#include "coverage.h"

#define str(s) #s
#define xstr(s) str(s)
#define REPEAT_COUNT_THUNK 120000

void instrument_thunks() {
    asm volatile (
        ".rept " xstr(REPEAT_COUNT_THUNK) "\n"  // Repeat the following block many times
        "    STR x30, [sp, #-16]!\n"            // save LR. we can't restore it in pop_regs. as we have jumped here.
        "    bl _push_regs\n"
        "    mov x0, #0x0000\n"                 // placeholder targeted_kext flag.
        "    mov x1, #0x4141\n"                 // fix the correct numner when instrumenting as arg0.
        "    mov x1, #0x4141\n"                 // placeholder for BB address
        "    mov x1, #0x4141\n"
        "    mov x1, #0x4141\n"
        "    bl _sanitizer_cov_trace_pc\n"
        "    bl _pop_regs\n"
        "    LDR x30, [sp], #16\n"              // restore LR
        "    nop\n"                             // placeholder for original inst.
        "    nop\n"                             // placeholder for jump back
        ".endr\n"                               // End of repetition
    );
}

void push_regs() {
    __asm__ __volatile__  (
        "sub sp, sp, #0x100\n"
        "str xzr, [sp, #0xf8]\n"
        "str x29, [sp, #0xe8]\n"
        "str x28, [sp, #0xe0]\n"
        "str x27, [sp, #0xd8]\n"
        "str x26, [sp, #0xd0]\n"
        "str x25, [sp, #0xc8]\n"
        "str x24, [sp, #0xc0]\n"
        "str x23, [sp, #0xb8]\n"
        "str x22, [sp, #0xb0]\n"
        "str x21, [sp, #0xa8]\n"
        "str x20, [sp, #0xa0]\n"
        "str x19, [sp, #0x98]\n"
        "str x18, [sp, #0x90]\n"
        "str x17, [sp, #0x88]\n"
        "str x16, [sp, #0x80]\n"
        "str x15, [sp, #0x78]\n"
        "str x14, [sp, #0x70]\n"
        "str x13, [sp, #0x68]\n"
        "str x12, [sp, #0x60]\n"
        "str x11, [sp, #0x58]\n"
        "str x10, [sp, #0x50]\n"
        "str x9, [sp, #0x48]\n"
        "str x8, [sp, #0x40]\n"
        "str x7, [sp, #0x38]\n"
        "str x6, [sp, #0x30]\n"
        "str x5, [sp, #0x28]\n"
        "str x4, [sp, #0x20]\n"
        "str x3, [sp, #0x18]\n"
        "str x2, [sp, #0x10]\n"
        "str x1, [sp, #0x8]\n"
        "str x0, [sp]\n"
        "sub sp, sp, #0x50\n"
        "ret"
    );
}

void pop_regs() {
    __asm__ __volatile__ (
        "add sp, sp, #0x50\n"
        "ldr xzr, [sp, #0xf8]\n"
        "ldr x29, [sp, #0xe8]\n"
        "ldr x28, [sp, #0xe0]\n"
        "ldr x27, [sp, #0xd8]\n"
        "ldr x26, [sp, #0xd0]\n"
        "ldr x25, [sp, #0xc8]\n"
        "ldr x24, [sp, #0xc0]\n"
        "ldr x23, [sp, #0xb8]\n"
        "ldr x22, [sp, #0xb0]\n"
        "ldr x21, [sp, #0xa8]\n"
        "ldr x20, [sp, #0xa0]\n"
        "ldr x19, [sp, #0x98]\n"
        "ldr x18, [sp, #0x90]\n"
        "ldr x17, [sp, #0x88]\n"
        "ldr x16, [sp, #0x80]\n"
        "ldr x15, [sp, #0x78]\n"
        "ldr x14, [sp, #0x70]\n"
        "ldr x13, [sp, #0x68]\n"
        "ldr x12, [sp, #0x60]\n"
        "ldr x11, [sp, #0x58]\n"
        "ldr x10, [sp, #0x50]\n"
        "ldr x9, [sp, #0x48]\n"
        "ldr x8, [sp, #0x40]\n"
        "ldr x7, [sp, #0x38]\n"
        "ldr x6, [sp, #0x30]\n"
        "ldr x5, [sp, #0x28]\n"
        "ldr x4, [sp, #0x20]\n"
        "ldr x3, [sp, #0x18]\n"
        "ldr x2, [sp, #0x10]\n"
        "ldr x1, [sp, #0x8]\n"
        "ldr x0, [sp]\n"
        "add sp, sp, #0x100\n"
        "ret\n"
    );
}

void sanitizer_cov_trace_pc(uint16_t kext, uintptr_t address) {

}

void sanitizer_cov_trace_lr(uint16_t kext) {

}
