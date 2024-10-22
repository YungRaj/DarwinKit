#include "disassembler.h"

#include "task.h"

#include <arm64/arm64.h>
#include <x86_64/x86_64.h>

#include <arm64/disassembler_arm64.h>
#include <x86_64/disassembler_x86_64.h>

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