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

class MachO;

namespace arch {
namespace arm64 {
namespace disassembler {}
} // namespace arm64
} // namespace arch

using namespace arch::arm64;
using namespace arch::arm64::disassembler;

extern "C" {
char* condition(uint8_t c);
char* shift(aarch64_shift s);
char* ext(aarch64_extend e);
char* reg(uint8_t reg, uint8_t sf);
char* tlbi_op(uint8_t op1, uint8_t CRm, uint8_t op2);
};

namespace arch {
namespace arm64 {
namespace disassembler {
bool Disassemble(MachO* macho, mach_vm_address_t pc, uint32_t op);
void Disassemble(MachO* macho, mach_vm_address_t start, uint64_t* length);
}; // namespace disassembler
}; // namespace arm64
}; // namespace arch
