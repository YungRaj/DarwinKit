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

#include <capstone/capstone.h>

#include <types.h>

#include "arch.h"

namespace xnu {
class Kernel;
class Task;
} // namespace xnu

using namespace arch;

struct DisasmSig {
    union {
        x86_insn insn_x86_64;

        arm64_insn insn_arm64;
    } insn;

    bool sub;
    bool addr;

    static DisasmSig* Create() {
        return new DisasmSig;
    }

    static void deleter(DisasmSig* sig) {
        delete sig;
    }
};

enum DisassemblerType {
    DisassemblerType_x86_64,
    DisassemblerType_arm64,
    DisassemblerType_Unknown,
    DisassemblerType_None,
};

class Disassembler {
public:
    explicit Disassembler(xnu::Task* task);

    ~Disassembler() = default;

    enum Architectures GetArchitecture() {
        return architecture;
    }

    enum DisassemblerType GetDisassemblerType() {
        return disassembler;
    }

    void InitDisassembler();

    void DeinitDisassembler();

    Size Disassemble(xnu::mach::VmAddress address, Size size, cs_insn** result);

    Size QuickInstructionSize(xnu::mach::VmAddress address, Size min);

    Size InstructionSize(xnu::mach::VmAddress address, Size min);

    xnu::mach::VmAddress DisassembleNthCall(xnu::mach::VmAddress address, Size num,
                                            Size lookup_size);

    xnu::mach::VmAddress DisassembleNthJmp(xnu::mach::VmAddress address, Size num,
                                           Size lookup_size);

    xnu::mach::VmAddress DisassembleNthInstruction(xnu::mach::VmAddress address, UInt32 insn,
                                                   Size num, Size lookup_size);

    xnu::mach::VmAddress DisassembleSignature(xnu::mach::VmAddress address,
                                              std::vector<struct DisasmSig*>* signature, Size num,
                                              Size lookup_size);

private:
    enum Architectures architecture;
    enum DisassemblerType disassembler;
    xnu::Task* task;

    enum DisassemblerType GetDisassemblerFromArch();
};
