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

#include "isa_arm64.h"

namespace arch {
namespace arm64 {
union Breakpoint MakeBreakpoint() {
    union Breakpoint breakpoint;

    breakpoint.brk.op = arch::arm64::BreakpointPrefix;
    breakpoint.brk.imm = 0b0;
    breakpoint.brk.z = 0b0;

    return breakpoint;
}

union Branch MakeBranch(mach_vm_address_t to, mach_vm_address_t from) {
    union Branch branch;
    bool sign;
    mach_vm_address_t imm;
    mach_vm_address_t max;
    mach_vm_address_t min;
    max = (from > to) ? from : to;
    min = (from > to) ? to : from;
    mach_vm_address_t diff = (max - min);
    if (from > to) {
        sign = true;
    } else {
        sign = false;
    }
    branch.branch.mode = 0b0;
    branch.branch.op = arch::arm64::NormalBranchPrefix;
    imm = diff;
    imm >>= 2;
    if (sign) {
        imm = (~(imm - 1) & 0x1FFFFFF) | 0x2000000;
    }
    branch.branch.imm = static_cast<uint32_t>(imm);
    return branch;
}

union FunctionCall MakeCall(mach_vm_address_t to, mach_vm_address_t from) {
    union FunctionCall call;
    bool sign;
    mach_vm_address_t imm;
    mach_vm_address_t max;
    mach_vm_address_t min;
    uint32_t insn_length = sizeof(uint32_t);
    from = from + insn_length;
    max = (from > to) ? from : to;
    min = (from > to) ? to : from;
    mach_vm_address_t diff = (max - min);
    if (from > to) {
        sign = true;
    } else {
        sign = false;
    }
    call.c.mode = 0b1;
    call.c.op = arch::arm64::CallFunctionPrefix;
    imm >>= 2;
    if (sign) {
        imm = (~imm + 1) | 0x2000000;
    }
    call.c.imm = static_cast<uint32_t>(imm);
    return call;
}
} // namespace arm64
} // namespace arch