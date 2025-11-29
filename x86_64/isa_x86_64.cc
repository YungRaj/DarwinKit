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

#include "isa_x86_64.h"

namespace arch {
namespace x86_64 {
union Breakpoint MakeBreakpoint() {
    union Breakpoint breakpoint;
    breakpoint.intN.intN = arch::x86_64::BreakpointPrefix;
    return breakpoint;
}

union Jump MakeJump(mach_vm_address_t to, mach_vm_address_t from) {
    union Jump jmp;
    uint32_t insn_length = sizeof(uint8_t) + sizeof(uint32_t);
    int32_t imm;
    mach_vm_address_t max;
    mach_vm_address_t min;

    from = from + insn_length;
    max = (from > to) ? from : to;
    min = (from > to) ? to : from;

    mach_vm_address_t diff = (max - min);
    if (diff > INT32_MAX) {
        DARWIN_KIT_LOG("DarwinKit::arch::x86_64::makeJump() encoding too large!\n");
    }

    imm = static_cast<int32_t>(diff);
    if (from > to) {
        imm *= -1;
    }
    jmp.s.opcode = arch::x86_64::SmallJumpPrefix;
    jmp.s.argument = imm;
    return jmp;
}

union FunctionCall MakeCall(mach_vm_address_t to, mach_vm_address_t from) {
    union FunctionCall call;
    uint32_t insn_length = sizeof(uint8_t) + sizeof(uint32_t);
    int32_t imm;

    mach_vm_address_t max;
    mach_vm_address_t min;
    from = from + insn_length;
    max = (from > to) ? from : to;
    min = (from > to) ? to : from;

    mach_vm_address_t diff = (max - min);
    if (diff > INT32_MAX) {
        DARWIN_KIT_LOG("DarwinKit::arch::x86_64::makeCall() encoding too large!\n");
    }
    imm = static_cast<int32_t>(diff);
    if (from > to) {
        imm *= -1;
    }
    call.c.opcode = arch::x86_64::FunctionCallPrefix;
    call.c.argument = imm;
    return call;
}
} // namespace x86_64
} // namespace arch