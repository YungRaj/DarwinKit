#include "disassembler.h"

#include "task.h"

#include <arm64/arm64.h>
#include <x86_64/x86_64.h>

#include <arm64/disassembler_arm64.h>
#include <x86_64/disassembler_x86_64.h>

using namespace arch;

Disassembler::Disassembler(xnu::Task* task)
    : task(task), architecture(arch::GetCurrentArchitecture()),
      disassembler(GetDisassemblerFromArch()) {
    InitDisassembler();
}

enum DisassemblerType Disassembler::GetDisassemblerFromArch() {
    enum Architectures architecture = arch::GetCurrentArchitecture();
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

void Disassembler::InitDisassembler() {
    switch (architecture) {
#ifdef __KERNEL__
    case ARCH_x86_64:
        arch::x86_64::disassembler::Init();
        break;
    case ARCH_arm64:
        arch::arm64::disassembler::Init();
        break;
#endif
    default:
        break;
    }
}

void Disassembler::DeinitDisassembler() {}

Size Disassembler::Disassemble(xnu::mach::VmAddress address, Size size, cs_insn** result) {
    switch (architecture) {
#ifdef __KERNEL__
    case ARCH_x86_64:
        return arch::x86_64::disassembler::Disassemble(address, size, result);
        break;
    case ARCH_arm64:
        return arch::arm64::disassembler::Disassemble(address, size, result);
        break;
#endif
    default:
        break;
    }
    return 0;
}

Size Disassembler::QuickInstructionSize(xnu::mach::VmAddress address, Size min) {
    switch (architecture) {
#ifdef __KERNEL__
    case ARCH_x86_64:
        return arch::x86_64::disassembler::QuickInstructionSize(address, min);
        break;
    case ARCH_arm64:
        return arch::arm64::disassembler::QuickInstructionSize(address, min);
        break;
#endif
    default:
        break;
    }
    return 0;
}

Size Disassembler::InstructionSize(xnu::mach::VmAddress address, Size min) {
    switch (architecture) {
#ifdef __KERNEL__
    case ARCH_x86_64:
        return arch::x86_64::disassembler::InstructionSize(address, min);
        break;
    case ARCH_arm64:
        return arch::arm64::disassembler::InstructionSize(address, min);
        break;
#endif
    default:
        break;
    }
    return 0;
}

xnu::mach::VmAddress Disassembler::DisassembleNthCall(xnu::mach::VmAddress address, Size num,
                                                      Size lookup_size) {
    switch (architecture) {
#ifdef __KERNEL__
    case ARCH_x86_64:
        return arch::x86_64::disassembler::DisassembleNthCall(address, num, lookup_size);
        break;
    case ARCH_arm64:
        return arch::arm64::disassembler::DisassembleNthBranchLink(address, num, lookup_size);
        break;
#endif
    default:
        break;
    }
    return 0;
}

xnu::mach::VmAddress Disassembler::DisassembleNthJmp(xnu::mach::VmAddress address, Size num,
                                                     Size lookup_size) {
    switch (architecture) {
#ifdef __KERNEL__
    case ARCH_x86_64:
        return arch::x86_64::disassembler::DisassembleNthJmp(address, num, lookup_size);
        break;
    case ARCH_arm64:
        return arch::arm64::disassembler::DisassembleNthBranch(address, num, lookup_size);
        break;
#endif
    default:
        break;
    }
    return 0;
}

xnu::mach::VmAddress Disassembler::DisassembleNthInstruction(xnu::mach::VmAddress address,
                                                             UInt32 insn, Size num,
                                                             Size lookup_size) {
    switch (architecture) {
#ifdef __KERNEL__
    case ARCH_x86_64:
        return arch::x86_64::disassembler::DisassembleNthInstruction(address, (x86_insn)insn, num,
                                                                     lookup_size);
        break;
    case ARCH_arm64:
        return arch::arm64::disassembler::DisassembleNthInstruction(address, (arm64_insn)insn, num,
                                                                    lookup_size);
        break;
#endif
    default:
        break;
    }
    return 0;
}

xnu::mach::VmAddress Disassembler::DisassembleSignature(xnu::mach::VmAddress address,
                                                        std::vector<struct DisasmSig*>* signature,
                                                        Size num, Size lookup_size) {
    switch (architecture) {
#ifdef __KERNEL__
    case ARCH_x86_64:
        return arch::x86_64::disassembler::DisassembleSignature(address, signature, num,
                                                                lookup_size);
        break;
    case ARCH_arm64:
        return arch::arm64::disassembler::DisassembleSignature(address, signature, num,
                                                               lookup_size);
        break;
#endif
    default:
        break;
    }
    return 0;
}
