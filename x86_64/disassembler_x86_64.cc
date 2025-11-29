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

#include "disassembler.h"
#include "disassembler_x86_64.h"

#ifdef __KERNEL__

#include "umm_malloc.h"

#endif

namespace arch {
namespace x86_64 {
namespace disassembler {
bool initialized = false;

size_t handle_x86_64;

static constexpr size_t MaxInstruction = 15;

bool Init() {
    if (initialized) {
        return true;
    }
    static bool detailed = true;
#ifdef __KERNEL__
    static bool capstoneInitialized = false;
    if (!capstoneInitialized) {
        cs_opt_mem setup{umm_malloc, umm_calloc, umm_realloc, umm_free, vsnprintf};
        cs_err err = cs_option(0, CS_OPT_MEM, reinterpret_cast<size_t>(&setup));
        if (err != CS_ERR_OK) {
            return false;
        }
        capstoneInitialized = true;
    }
#endif
    cs_err err = cs_open(CS_ARCH_X86, CS_MODE_64, &handle_x86_64);
    if (err != CS_ERR_OK) {
        return false;
    }
    initialized = true;
    if (detailed) {
        err = cs_option(handle_x86_64, CS_OPT_DETAIL, CS_OPT_ON);
        if (err != CS_ERR_OK) {
            return false;
        }
    }
    return true;
}

bool Deinit() {
    if (initialized) {
        cs_close(&handle_x86_64);
        handle_x86_64 = 0;
        initialized = false;
    }
    return true;
}

size_t InstructionSize(mach_vm_address_t address, size_t min) {
    cs_insn* result = nullptr;
    size_t insns = arch::x86_64::disassembler::Disassemble(address, min + MaxInstruction, &result);
    if (result) {
        size_t size = 0;
        for (size_t i = 0; i < insns && size < min; i++) {
            size += result[i].size;
        }
        cs_free(result, insns);
        if (size >= min) {
            return size;
        }
    }
    return 0;
}

size_t QuickInstructionSize(mach_vm_address_t address, size_t min) {
    return InstructionSize(address, min);
}

size_t Disassemble(mach_vm_address_t address, size_t size, cs_insn** result) {
    size_t insns;
    cs_err err;
    *result = nullptr;
    insns = cs_disasm(handle_x86_64, reinterpret_cast<uint8_t*>(address), size, 0, 0, result);
    err = cs_errno(handle_x86_64);
    if (err != CS_ERR_OK) {
        if (*result) {
            cs_free(*result, insns);
            *result = nullptr;
        }
        return 0;
    }
    return insns;
}

bool RegisterAccess(cs_insn* insn, cs_regs regs_read, uint8_t* nread, cs_regs regs_write,
                    uint8_t* nwrite) {
    return cs_regs_access(handle_x86_64, insn, regs_read, nread, regs_write, nwrite) == 0;
}

mach_vm_address_t DisassembleNthCall(mach_vm_address_t address, size_t num, size_t lookup_size) {
    cs_insn* result = nullptr;
    size_t disasm_size = arch::x86_64::disassembler::Disassemble(address, lookup_size, &result);
    if (disasm_size > 0) {
        size_t counter = 0;
        mach_vm_address_t sub_address = 0;
        for (size_t i = 0; i < disasm_size; i++) {
            if (result[i].id == X86_INS_CALL) {
                if (result[i].detail) {
                    if (result[i].detail->x86.op_count == 1 &&
                        result[i].detail->x86.operands[0].type == X86_OP_IMM) {
                        sub_address = result[i].detail->x86.operands[0].imm + address;
                    }
                } else {
                    break;
                }
            }
            if (counter == num) {
                break;
            } else {
                sub_address = 0;
            }
        }
        cs_free(result, disasm_size);
        return sub_address;
    }
    return 0;
}

mach_vm_address_t DisassembleNthJmp(mach_vm_address_t address, size_t num, size_t lookup_size) {
    cs_insn* result = nullptr;
    size_t disasm_size = arch::x86_64::disassembler::Disassemble(address, lookup_size, &result);
    if (disasm_size > 0) {
        size_t counter = 0;
        mach_vm_address_t sub_address = 0;
        for (size_t i = 0; i < disasm_size; i++) {
            if (result[i].id == X86_INS_JMP) {
                if (result[i].detail) {
                    if (result[i].detail->x86.op_count == 1 &&
                        result[i].detail->x86.operands[0].type == X86_OP_IMM) {
                        sub_address = result[i].detail->x86.operands[0].imm + address;
                    }
                } else {
                    break;
                }
            }
            if (counter == num) {
                break;
            } else {
                sub_address = 0;
            }
        }
        cs_free(result, disasm_size);
        return sub_address;
    }
    return 0;
}

mach_vm_address_t DisassembleNthInstruction(mach_vm_address_t address, x86_insn insn, size_t num,
                                            size_t lookup_size) {
    cs_insn* result = nullptr;
    size_t disasm_size = arch::x86_64::disassembler::Disassemble(address, lookup_size, &result);
    if (disasm_size > 0) {
        size_t counter = 0;
        mach_vm_address_t sub_address = 0;
        for (size_t i = 0; i < disasm_size; i++) {
            if (result[i].id == insn) {
                sub_address = result[i].address + address;
                counter++;
            }
            if (counter == num) {
                break;
            } else {
                sub_address = 0;
            }
        }
        cs_free(result, disasm_size);
        return sub_address;
    }
    return 0;
}

mach_vm_address_t DisassembleSignature(mach_vm_address_t address,
                                       std::vector<DisasmSig*>* signature, size_t num,
                                       size_t lookup_size) {
    return 0;
}
} // namespace Disassembler
} // namespace x86_64
} // namespace arch