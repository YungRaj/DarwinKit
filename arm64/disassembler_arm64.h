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

#include <capstone/capstone.h>

#include "vector.h"

struct DisasmSig;

namespace arch {
namespace arm64 {
namespace disassembler {
bool Init();

bool Deinit();

size_t InstructionSize(xnu::mach::VmAddress address, size_t min);

size_t QuickInstructionSize(xnu::mach::VmAddress address, size_t min);

size_t Disassemble(xnu::mach::VmAddress address, size_t size, cs_insn** result);

bool RegisterAccess(cs_insn* insn, cs_regs regs_read, uint8_t* nread, cs_regs regs_write,
                    uint8_t* nwrite);

xnu::mach::VmAddress DisassembleNthBranchLink(xnu::mach::VmAddress address, size_t num,
                                              size_t lookup_size);

xnu::mach::VmAddress DisassembleNthBranch(xnu::mach::VmAddress address, size_t num,
                                          size_t lookup_size);

xnu::mach::VmAddress DisassembleNthInstruction(xnu::mach::VmAddress address, arm64_insn insn,
                                               size_t num, size_t lookup_size);

xnu::mach::VmAddress DisassembleSignature(xnu::mach::VmAddress address,
                                          std::vector<struct DisasmSig*>* signature, size_t num,
                                          size_t lookup_size);
} // namespace disassembler
} // namespace arm64
}; // namespace arch
