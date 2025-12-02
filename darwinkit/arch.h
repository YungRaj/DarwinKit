/*
 * Copyright (c) YungRaj
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include <types.h>

#include <arm64/arm64.h>
#include <x86_64/x86_64.h>

#include "api_util.h"

namespace arch {
class Architecture;

enum Architectures {
    ARCH_unsupported = -1,
    ARCH_none = 0,
    ARCH_i386,
    ARCH_x86_64,
    ARCH_armv7,
    ARCH_arm64,
    ARCH_PowerPC,
    ARCH_SPARC,
    ARCH_MIPS
};

template <bool IsX86, bool IsArm, bool Is64Bit>
struct CurrentArchitecture {
    static_assert((!IsX86 && IsArm) || (IsX86 && !IsArm), "Unsupported Architecture!");

    static constexpr Architectures value = [] {
        if constexpr (IsX86) {
            if constexpr (Is64Bit) {
                return ARCH_x86_64;
            } else {
                return ARCH_i386;
            }
        } else if constexpr (IsArm) {
            if constexpr (Is64Bit) {
                return ARCH_arm64;
            } else {
                return ARCH_armv7;
            }
        } else {
            return ARCH_unsupported;
        }
    }();
};

constexpr enum Architectures GetCurrentArchitecture() {
#ifdef __x86_64__
    return CurrentArchitecture<true, false, true>::value;
#elif __arm64__
    return CurrentArchitecture<false, true, true>::value;
#endif

    return ARCH_unsupported;
}

constexpr enum Architectures current_architecture = arch::GetCurrentArchitecture();

template <enum Architectures ArchType>
concept IsCurrentArchitecture = ArchType == current_architecture;

template <enum Architectures ArchType>
concept IsValidArchitecture = ArchType != ARCH_unsupported && ArchType != ARCH_none;

static_assert(IsValidArchitecture<current_architecture>);

Architecture* InitArchitecture();

extern "C" {
void push_registers_x86_64();
void push_registers_x86_64_end();
void set_argument_x86_64();
void set_argument_x86_64_end();
void check_breakpoint_x86_64();
void check_breakpoint_x86_64_end();
void breakpoint_x86_64();
void breakpoint_x86_64_end();
void pop_registers_x86_64();
void pop_registers_x86_64_end();

void push_registers_arm64();
void push_registers_arm64_end();
void set_argument_arm64();
void set_argument_arm64_end();
void check_breakpoint_arm64();
void check_breakpoint_arm64_end();
void breakpoint_arm64();
void breakpoint_arm64_end();
void pop_registers_arm64();
void pop_registers_arm64_end();
}

#ifdef __x86_64__

#define push_registers push_registers_x86_64
#define push_registers_end push_registers_x86_64_end

#define set_argument set_argument_x86_64
#define set_argument_end set_argument_x86_64_end

#define check_breakpoint check_breakpoint_x86_64
#define check_breakpoint_end check_breakpoint_x86_64_end

#define breakpoint breakpoint_x86_64
#define breakpoint_end breakpoint_x86_64_end

#define pop_registers pop_registers_x86_64
#define pop_registers_end pop_registers_x86_64_end

#elif __arm64__ || __arm64e__

extern "C" {
void push_registers_arm64();
void push_registers_arm64_end();

void set_argument_arm64();
void set_argument_arm64_end();

void check_breakpoint_arm64();
void check_breakpoint_arm64_end();

void breakpoint_arm64();
void breakpoint_arm64_end();

void pop_registers_arm64();
void pop_registers_arm64_end();
}

#define push_registers push_registers_arm64
#define push_registers_end push_registers_arm64_end

#define set_argument set_argument_arm64
#define set_argument_end set_argument_arm64_end

#define check_breakpoint check_breakpoint_arm64
#define check_breakpoint_end check_breakpoint_arm64_end

#define breakpoint breakpoint_arm64
#define breakpoint_end breakpoint_arm64_end

#define pop_registers pop_registers_arm64
#define pop_registers_end pop_registers_arm64_end

#endif

using RegisterState_x86_64 = struct arch::x86_64::x86_64_register_state;
using RegisterState_arm64 = struct arch::arm64::arm64_register_state;

using Jmp_x86_64 = union arch::x86_64::Jump;
using Branch_arm64 = union arch::arm64::Branch;

using FunctionCall_x86_64 = union arch::x86_64::FunctionCall;
using FunctionCall_arm64 = union arch::arm64::FunctionCall;

using Breakpoint_x86_64 = union arch::x86_64::Breakpoint;
using Breakpoint_arm64 = union arch::arm64::Breakpoint;

union RegisterState {
    RegisterState_x86_64 state_x86_64;
    RegisterState_arm64 state_arm64;
};

union Branch {
    Jmp_x86_64 jmp_x86_64;
    Branch_arm64 br_arm64;
};

union FunctionCall {
    FunctionCall_x86_64 call_x86_64;
    FunctionCall_arm64 call_arm64;
};

union Breakpoint {
    Breakpoint_x86_64 breakpoint_x86_64;
    Breakpoint_arm64 breakpoint_arm64;
};

union ThreadState {
    struct x86_64_register_state {
        UInt64 rsp;
        UInt64 rbp;
        UInt64 rax;
        UInt64 rbx;
        UInt64 rcx;
        UInt64 rdx;
        UInt64 rdi;
        UInt64 rsi;
        UInt64 r8;
        UInt64 r9;
        UInt64 r10;
        UInt64 r11;
        UInt64 r12;
        UInt64 r13;
        UInt64 r14;
        UInt64 r15;
    } state_x86_64;

    struct arm64_register_state {
        UInt64 x[29];
        UInt64 fp;
        UInt64 lr;
        UInt64 sp;
        UInt64 pc;
        UInt64 cpsr;
    } state_arm64;
};

using arm64_register_state = ThreadState::arm64_register_state;
using x86_64_register_state = ThreadState::x86_64_register_state;

template <enum Architectures ArchType>
concept _x86_64 = ArchType == ARCH_x86_64;

template <enum Architectures ArchType>
concept _arm64 = ArchType == ARCH_arm64;

template <enum Architectures ArchType>
concept _i386 = ArchType == ARCH_i386;

template <enum Architectures ArchType>
concept _armv7 = ArchType == ARCH_armv7;

template <enum Architectures ArchType>
concept SupportedProcessor =
    _x86_64<ArchType> || _arm64<ArchType> || _i386<ArchType> || _armv7<ArchType>;

#define PAGE_SHIFT_ARM64 14

#define PAGE_SHIFT_X86_64 12

template <enum Architectures ArchType>
static constexpr UInt32 GetPageShift()
    requires SupportedProcessor<ArchType>
{
    if constexpr (ArchType == ARCH_arm64) {
        return PAGE_SHIFT_ARM64;
    }
    if constexpr (ArchType == ARCH_x86_64) {
        return PAGE_SHIFT_X86_64;
    }
}

template <enum Architectures ArchType>
static constexpr UInt64 GetPageSize()
    requires SupportedProcessor<ArchType>
{
    return 1 << arch::GetPageShift<ArchType>();
}

static_assert(arch::GetPageSize<arch::GetCurrentArchitecture()>() % 0x1000 == 0);

template <enum Architectures ArchType>
    requires IsCurrentArchitecture<ArchType>
static inline void GetThreadState(union ThreadState* state) {
    if constexpr (ArchType == ARCH_arm64) {
        arm64_register_state* state_arm64 = &state->state_arm64;
        asm volatile("STP x0, x1, [%[regs], #0]\n"
                     "STP x2, x3, [%[regs], #16]\n"
                     "STP x4, x5, [%[regs], #32]\n"
                     "STP x6, x7, [%[regs], #48]\n"
                     "STP x8, x9, [%[regs], #64]\n"
                     "STP x10, x11, [%[regs], #80]\n"
                     "STP x12, x13, [%[regs], #96]\n"
                     "STP x14, x15, [%[regs], #112]\n"
                     "STP x16, x17, [%[regs], #128]\n"
                     "STP x18, x19, [%[regs], #144]\n"
                     "STP x20, x21, [%[regs], #160]\n"
                     "STP x22, x23, [%[regs], #176]\n"
                     "STP x24, x25, [%[regs], #192]\n"
                     "STP x26, x27, [%[regs], #208]\n"
                     "STR x28, [%[regs], #224]\n"
                     :
                     : [regs] "r"(state_arm64->x)
                     :);
        asm volatile("MOV %0, fp\n"
                     "MOV %1, lr\n"
                     "MOV %2, sp\n"
                     "ADR %x3, 1f\n"
                     "1:\n"
                     "MRS %4, nzcv\n"
                     : "=r"(state_arm64->fp), "=r"(state_arm64->lr), "=r"(state_arm64->sp),
                       "=r"(state_arm64->pc), "=r"(state_arm64->cpsr));
    }
    if constexpr (ArchType == ARCH_x86_64) {
        x86_64_register_state* state_x86_64 = &state->state_x86_64;
        asm volatile("movq %%rsp, %0\n"
                     "movq %%rbp, %1\n"
                     "movq %%rax, %2\n"
                     "movq %%rbx, %3\n"
                     "movq %%rcx, %4\n"
                     "movq %%rdx, %5\n"
                     : "=m"(state_x86_64->rsp), "=m"(state_x86_64->rbp), "=m"(state_x86_64->rax),
                       "=m"(state_x86_64->rbx), "=m"(state_x86_64->rcx), "=m"(state_x86_64->rdx));
        asm volatile("movq %%rdi, %0\n"
                     "movq %%rsi, %1\n"
                     "movq %%r8, %2\n"
                     "movq %%r9, %3\n"
                     "movq %%r10, %4\n"
                     "movq %%r11, %5\n"
                     : "=m"(state_x86_64->rdi), "=m"(state_x86_64->rsi), "=m"(state_x86_64->r8),
                       "=m"(state_x86_64->r9), "=m"(state_x86_64->r10), "=m"(state_x86_64->r11));
        asm volatile("movq %%r12, %0\n"
                     "movq %%r13, %1\n"
                     "movq %%r14, %2\n"
                     "movq %%r15, %3\n"
                     : "=m"(state_x86_64->r12), "=m"(state_x86_64->r13), "=m"(state_x86_64->r14),
                       "=m"(state_x86_64->r15));
    }
}

template <enum Architectures ArchType>
    requires SupportedProcessor<ArchType>
class Instructions {
public:
    constexpr static Size GetBranchSize() {
        if constexpr (ArchType == ARCH_x86_64) {
            return x86_64::SmallJumpSize();
        } else if constexpr (ArchType == ARCH_arm64) {
            return arm64::NormalBranchSize();
        }
    }

    constexpr static Size GetCallSize() {
        if constexpr (ArchType == ARCH_x86_64) {
            return x86_64::FunctionCallSize();
        } else if constexpr (ArchType == ARCH_arm64) {
            return arm64::FunctionCallSize();
        }
    }

    constexpr static Size GetBreakpointSize() {
        if constexpr (ArchType == ARCH_x86_64) {
            return x86_64::BreakpointSize();
        } else if constexpr (ArchType == ARCH_arm64) {
            return arm64::BreakpointSize();
        }
    }

    static void MakeBranch(union Branch* branch, xnu::mach::VmAddress to,
                           xnu::mach::VmAddress from) {
        if constexpr (ArchType == ARCH_x86_64) {
            branch->jmp_x86_64 = x86_64::MakeJump(to, from);
        } else if constexpr (ArchType == ARCH_arm64) {
            branch->br_arm64 = arm64::MakeBranch(to, from);
        }
    }

    static void MakeCall(union FunctionCall* call, xnu::mach::VmAddress to,
                         xnu::mach::VmAddress from) {
        if constexpr (ArchType == ARCH_x86_64) {
            call->call_x86_64 = x86_64::MakeCall(to, from);
        } else if constexpr (ArchType == ARCH_arm64) {
            call->call_arm64 = arm64::MakeCall(to, from);
        }
    }

    static void MakeBreakpoint(union Breakpoint* breakpoint) {
        if constexpr (ArchType == ARCH_x86_64) {
            breakpoint->breakpoint_x86_64 = x86_64::MakeBreakpoint();
        } else if constexpr (ArchType == ARCH_arm64) {
            breakpoint->breakpoint_arm64 = arm64::MakeBreakpoint();
        }
    }
};

class Architecture {
public:
    explicit Architecture() : arch(arch::GetCurrentArchitecture()) {}

    ~Architecture() = default;

    static enum Architectures GetArchitecture();

    constexpr Size GetBranchSize() {
        return Instructions<arch::GetCurrentArchitecture()>::GetBranchSize();
    }

    constexpr Size GetCallSize() {
        return Instructions<arch::GetCurrentArchitecture()>::GetCallSize();
    }

    constexpr Size GetBreakpointSize() {
        return Instructions<arch::GetCurrentArchitecture()>::GetBreakpointSize();
    }

    bool SetInterrupts(bool enable);

    bool SetWPBit(bool enable);

    bool SetNXBit(bool enable);

    bool SetPaging(bool enable);

    void MakeBranch(union Branch* branch, xnu::mach::VmAddress to, xnu::mach::VmAddress from) {
        return Instructions<arch::GetCurrentArchitecture()>::MakeBranch(branch, to, from);
    }

    void MakeCall(union FunctionCall* call, xnu::mach::VmAddress to, xnu::mach::VmAddress from) {
        return Instructions<arch::GetCurrentArchitecture()>::MakeCall(call, to, from);
    }

    void MakeBreakpoint(union Breakpoint* breakpoint) {
        return Instructions<arch::GetCurrentArchitecture()>::MakeBreakpoint(breakpoint);
    }

private:
    enum Architectures arch;
};

namespace i386 {};
namespace x86_64 {};

namespace armv7 {};
namespace arm64 {};
}; // namespace arch