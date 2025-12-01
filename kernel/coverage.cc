#include "coverage.h"
#include "task.h"

#include <mach/mach_types.h>

#include <kern/thread.h>
#include <kern/task.h>

#include <sys/proc.h>

#define str(s) #s
#define xstr(s) str(s)
#define REPEAT_COUNT_THUNK 750000

extern "C" {

extern task_t current_task();
extern thread_t current_thread();

Int32 current_pid = 0;
task_t client_task = nullptr;

alignas(16 * 1024)
__attribute__((section("__DATA,__cov")))
UInt64 coverage_bitmap[KCOV_COVERAGE_BITMAP_SIZE / sizeof(UInt64)];

UInt64 curr_location = 0;
UInt64 prev_location = 0;

Bool collect_coverage = false;
// Flag to specify that we're fuzzing from userspace. This adds additional logic to coverage collection
// So that we only track basic block edges coming from the userspace portion of the harness
// When fuzzing inside of the kernel, initiate the harness from userspace by setting the FuzzContext
// This flag will automatically flip to false when triggering the fuzz in kernel logic from the IOUserClient
Bool userspace = true;

#ifdef __arm64__
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

#endif

UInt8* sanitizer_cov_get_bitmap() {
    return (UInt8*) coverage_bitmap;
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
        task_t t = current_task();
        thread_t tr = current_thread();
        if(userspace && client_task != t) {
            return;
        }
        /* Kernel-only coverage tracking using a bitmap */
        UInt64 index = address & ((KCOV_COVERAGE_BITMAP_SIZE / sizeof(UInt64)) - 1);
        curr_location = index;
        /* AFL-style edge tracking */
        UInt64 edge = curr_location ^ prev_location;
        coverage_bitmap[edge]++;
        prev_location = curr_location >> 1;
    }
}

void sanitizer_cov_trace_lr(UInt16 kext) {}

}
