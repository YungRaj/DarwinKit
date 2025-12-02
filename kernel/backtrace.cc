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

#include "backtrace.h"

#include "darwin_kit.h"
#include "kernel.h"
#include "kext.h"
#include "macho.h"
#include "section.h"
#include "segment.h"
#include "symbol.h"
#include "symbol_table.h"

inline bool LooksLikeKernelPointer(xnu::mach::VmAddress address) {
    return (address & 0xfffffe0000000000) > 0;
}

namespace debug {
namespace symbolicate {

void LookForAddressInsideKexts(xnu::mach::VmAddress address, std::vector<xnu::Kext*>& kexts,
                               Symbol** sym, Offset* delta) {
    for (int i = 0; i < kexts.size(); i++) {
        xnu::Kext* kext = kexts.at(i);
        xnu::KextMachO* macho = kext->GetMachO();
        std::vector<Symbol*>& kextSymbols = kext->GetAllSymbols();
        if (!macho->AddressInSegment(address, "__TEXT") ||
            !macho->AddressInSegment(address, "__TEXT_EXEC")) {
            continue;
        }
        for (int j = 0; j < kextSymbols.size(); i++) {
            Symbol* symbol = kextSymbols.at(j);
            if (address > symbol->GetAddress()) {
                Offset new_delta = address - symbol->GetAddress();
                if (*sym) {
                    Offset old_delta = address - (*sym)->GetAddress();
                    if (new_delta < old_delta && LooksLikeKernelPointer(symbol->GetAddress())) {
                        if (new_delta <= arch::GetPageSize<arch::GetCurrentArchitecture()>() * 3) {
                            *sym = symbol;
                            *delta = new_delta;
                        }
                    }
                } else if (LooksLikeKernelPointer(symbol->GetAddress()) &&
                           new_delta <= arch::GetPageSize<arch::GetCurrentArchitecture()>() * 3) {
                    *sym = symbol;
                    *delta = new_delta;
                }
            }
        }
    }
}

void LookForAddressInsideKernel(xnu::mach::VmAddress address, xnu::Kernel* kernel, Symbol** sym,
                                Offset* delta) {
    MachO* macho = kernel->GetMachO();
    std::vector<Symbol*>& kernelSymbols = kernel->GetAllSymbols();
    if (macho->AddressInSegment(address, "__TEXT") ||
        macho->AddressInSegment(address, "__TEXT_EXEC") ||
        macho->AddressInSegment(address, "__PRELINK_TEXT") ||
        macho->AddressInSegment(address, "__KLD")) {
        for (int i = 0; i < kernelSymbols.size(); i++) {
            Symbol* symbol = kernelSymbols.at(i);
            if (address > symbol->GetAddress()) {
                Offset new_delta = address - symbol->GetAddress();
                if (*sym) {
                    Offset old_delta = address - (*sym)->GetAddress();
                    if (new_delta < old_delta && LooksLikeKernelPointer(symbol->GetAddress())) {
                        if (new_delta <= arch::GetPageSize<arch::GetCurrentArchitecture()>() * 3) {
                            *sym = symbol;
                            *delta = new_delta;
                        }
                    }
                } else if (LooksLikeKernelPointer(symbol->GetAddress()) &&
                           new_delta <= arch::GetPageSize<arch::GetCurrentArchitecture()>() * 3) {
                    *sym = symbol;
                    *delta = new_delta;
                }
            }
        }
    }
}

Symbol* GetSymbolFromAddress(xnu::mach::VmAddress address, Offset* delta) {
    Symbol* kernel_sym = nullptr;
    Symbol* kext_sym = nullptr;
    Offset kernel_delta = 0;
    Offset kext_delta = 0;

    darwin::DarwinKit* darwin = darwinkit_get_darwinkit();
    xnu::Kernel* kernel = darwin->GetKernel();
    std::vector<xnu::Kext*>& kexts = darwin->GetKexts();

    debug::symbolicate::LookForAddressInsideKernel(address, kernel, &kernel_sym, &kernel_delta);
    debug::symbolicate::LookForAddressInsideKexts(address, kexts, &kext_sym, &kext_delta);
    if (!kernel_sym && !kext_sym) {
        return nullptr;
    } else if (kernel_sym && kext_sym) {
        *delta = kext_delta > kernel_delta ? kernel_delta : kext_delta;
        return kext_delta > kernel_delta ? kernel_sym : kext_sym;
    } else if (!kext_sym) {
        *delta = kernel_delta;
        return kernel_sym;
    }
    *delta = kext_delta;
    return kext_sym;
}

} // namespace symbolicate

void PrintBacktrace() {
    constexpr arch::Architectures arch = arch::GetCurrentArchitecture();
    union arch::ThreadState thread_state;
    arch::GetThreadState<arch>(&thread_state);
    if constexpr (arch::_arm64<arch>) {
        UInt64 fp = thread_state.state_arm64.fp;
        UInt32 frame = 0;
        while (fp && LooksLikeKernelPointer(fp)) {
            Symbol* symbol;
            Offset delta;
            UInt64 lr = *(UInt64*)(fp + sizeof(UInt64));
            if (LooksLikeKernelPointer(lr)) {
                lr |= 0xfffffe0000000000;
                char buffer[128];
                snprintf(buffer, 128, "0x%llx", fp);
                DARWIN_KIT_LOG("DarwinKit::frame pointer = %s\n", buffer);
                snprintf(buffer, 128, "0x%llx", lr);
                DARWIN_KIT_LOG("DarwinKit::link register = %s\n", buffer);

                symbol = debug::symbolicate::GetSymbolFromAddress(lr, &delta);
                if (symbol) {
                    DARWIN_KIT_LOG("DarwinKit::frame %u: %s %s + %llu\n", frame, buffer,
                                   symbol->GetName(), delta);
                }
                fp = *(UInt64*)fp;
            } else {
                break;
            }
            frame++;
        }
    }
    if constexpr (arch::_x86_64<arch>) {
        UInt64 rbp = thread_state.state_x86_64.rbp;
        UInt32 frame = 0;
        while (rbp && LooksLikeKernelPointer(rbp)) {
            Symbol* symbol;
            Offset delta;
            UInt64 rip = *(UInt64*)(rbp + sizeof(UInt64));
            if (LooksLikeKernelPointer(rip)) {
                symbol = debug::symbolicate::GetSymbolFromAddress(rip, &delta);
                DARWIN_KIT_LOG("frame %u: 0x%x %s + %llu", frame, rip, symbol->GetName(), delta);
                rbp = *(UInt64*)rbp;
            } else {
                break;
            }
            frame++;
        }
    }
}

} // namespace debug