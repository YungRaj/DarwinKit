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

#include "Disassembler.hpp"

#include "Task.hpp"

#include <arm64/arm64.hpp>
#include <x86_64/x86_64.hpp>

#include <arm64/Disassembler_arm64.hpp>
#include <x86_64/Disassembler_x86_64.hpp>

using namespace arch;

Disassembler::Disassembler(xnu::Task* task)
    : task(task), architecture(arch::getCurrentArchitecture()),
      disassembler(getDisassemblerFromArch()) {
    initDisassembler();
}

Disassembler::~Disassembler() {}

enum DisassemblerType Disassembler::getDisassemblerFromArch() {
    enum Architectures architecture = arch::getCurrentArchitecture();
    ;

    switch (architecture) {
    case ARCH_x86_64:
        return DisassemblerType_x86_64;
    case ARCH_arm64:
        return DisassemblerType_arm64;
    default:
        return DisassemblerType_None;
    }

    return DisassemblerType_Unknown;
}

void Disassembler::initDisassembler() {
    switch (architecture) {
#ifdef __KERNEL__

    case ARCH_x86_64:
        arch::x86_64::Disassembler::init();

        break;
    case ARCH_arm64:
        arch::arm64::Disassembler::init();

        break;
#endif
    default:
        break;
    }
}

void Disassembler::deinitDisassembler() {}

Size Disassembler::disassemble(xnu::Mach::VmAddress address, Size size, cs_insn** result) {
    switch (architecture) {
#ifdef __KERNEL__
    case ARCH_x86_64:
        return arch::x86_64::Disassembler::disassemble(address, size, result);

        break;
    case ARCH_arm64:
        return arch::arm64::Disassembler::disassemble(address, size, result);

        break;
#endif
    default:
        break;
    }

    return 0;
}

Size Disassembler::quickInstructionSize(xnu::Mach::VmAddress address, Size min) {
    switch (architecture) {
#ifdef __KERNEL__
    case ARCH_x86_64:
        return arch::x86_64::Disassembler::quickInstructionSize(address, min);

        break;
    case ARCH_arm64:
        return arch::arm64::Disassembler::quickInstructionSize(address, min);

        break;
#endif
    default:
        break;
    }

    return 0;
}

Size Disassembler::instructionSize(xnu::Mach::VmAddress address, Size min) {
    switch (architecture) {
#ifdef __KERNEL__
    case ARCH_x86_64:
        return arch::x86_64::Disassembler::instructionSize(address, min);

        break;
    case ARCH_arm64:
        return arch::arm64::Disassembler::instructionSize(address, min);

        break;
#endif
    default:
        break;
    }

    return 0;
}

xnu::Mach::VmAddress Disassembler::disassembleNthCall(xnu::Mach::VmAddress address, Size num,
                                                      Size lookup_size) {
    switch (architecture) {
#ifdef __KERNEL__
    case ARCH_x86_64:
        return arch::x86_64::Disassembler::disassembleNthCall(address, num, lookup_size);

        break;
    case ARCH_arm64:
        return arch::arm64::Disassembler::disassembleNthBranchLink(address, num, lookup_size);

        break;
#endif
    default:
        break;
    }

    return 0;
}

xnu::Mach::VmAddress Disassembler::disassembleNthJmp(xnu::Mach::VmAddress address, Size num,
                                                     Size lookup_size) {
    switch (architecture) {
#ifdef __KERNEL__
    case ARCH_x86_64:
        return arch::x86_64::Disassembler::disassembleNthJmp(address, num, lookup_size);

        break;
    case ARCH_arm64:
        return arch::arm64::Disassembler::disassembleNthBranch(address, num, lookup_size);

        break;
#endif
    default:
        break;
    }

    return 0;
}

xnu::Mach::VmAddress Disassembler::disassembleNthInstruction(xnu::Mach::VmAddress address,
                                                             UInt32 insn, Size num,
                                                             Size lookup_size) {
    switch (architecture) {
#ifdef __KERNEL__
    case ARCH_x86_64:
        return arch::x86_64::Disassembler::disassembleNthInstruction(address, (x86_insn)insn, num,
                                                                     lookup_size);

        break;
    case ARCH_arm64:
        return arch::arm64::Disassembler::disassembleNthInstruction(address, (arm64_insn)insn, num,
                                                                    lookup_size);

        break;
#endif
    default:
        break;
    }

    return 0;
}

xnu::Mach::VmAddress Disassembler::disassembleSignature(xnu::Mach::VmAddress address,
                                                        std::vector<struct DisasmSig*>* signature,
                                                        Size num, Size lookup_size) {
    switch (architecture) {
#ifdef __KERNEL__
    case ARCH_x86_64:
        return arch::x86_64::Disassembler::disassembleSignature(address, signature, num,
                                                                lookup_size);

        break;
    case ARCH_arm64:
        return arch::arm64::Disassembler::disassembleSignature(address, signature, num,
                                                               lookup_size);

        break;
#endif
    default:
        break;
    }

    return 0;
}