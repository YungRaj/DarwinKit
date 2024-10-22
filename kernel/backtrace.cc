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

inline bool looksLikeKernelPointer(xnu::Mach::VmAddress address) {
    return (address & 0xfffffe0000000000) > 0;
}

void debug::symbolicate::lookForAddressInsideKexts(xnu::Mach::VmAddress address,
                                                   std::vector<xnu::Kext*>& kexts, Symbol** sym,
                                                   Offset* delta) {
    for (int i = 0; i < kexts.size(); i++) {
        xnu::Kext* kext = kexts.at(i);

        xnu::KextMachO* macho = kext->getMachO();

        std::vector<Symbol*>& kextSymbols = kext->getAllSymbols();

        if (!macho->addressInSegment(address, "__TEXT") ||
            !macho->addressInSegment(address, "__TEXT_EXEC"))
            continue;

        for (int j = 0; j < kextSymbols.size(); i++) {
            Symbol* symbol = kextSymbols.at(j);

            if (address > symbol->getAddress()) {
                Offset new_delta = address - symbol->getAddress();

                if (*sym) {
                    Offset old_delta = address - (*sym)->getAddress();

                    if (new_delta < old_delta && looksLikeKernelPointer(symbol->getAddress())) {
                        if (new_delta <= arch::getPageSize<arch::getCurrentArchitecture()>() * 3) {
                            *sym = symbol;
                            *delta = new_delta;
                        }
                    }

                } else if (looksLikeKernelPointer(symbol->getAddress()) &&
                           new_delta <= arch::getPageSize<arch::getCurrentArchitecture()>() * 3) {
                    *sym = symbol;
                    *delta = new_delta;
                }
            }
        }
    }
}

void debug::symbolicate::lookForAddressInsideKernel(xnu::Mach::VmAddress address,
                                                    xnu::Kernel* kernel, Symbol** sym,
                                                    Offset* delta) {
    MachO* macho = kernel->getMachO();

    std::vector<Symbol*>& kernelSymbols = kernel->getAllSymbols();

    if (macho->addressInSegment(address, "__TEXT") ||
        macho->addressInSegment(address, "__TEXT_EXEC") ||
        macho->addressInSegment(address, "__PRELINK_TEXT") ||
        macho->addressInSegment(address, "__KLD")) {
        for (int i = 0; i < kernelSymbols.size(); i++) {
            Symbol* symbol = kernelSymbols.at(i);

            if (address > symbol->getAddress()) {
                Offset new_delta = address - symbol->getAddress();

                if (*sym) {
                    Offset old_delta = address - (*sym)->getAddress();

                    if (new_delta < old_delta && looksLikeKernelPointer(symbol->getAddress())) {
                        if (new_delta <= arch::getPageSize<arch::getCurrentArchitecture()>() * 3) {
                            *sym = symbol;
                            *delta = new_delta;
                        }
                    }

                } else if (looksLikeKernelPointer(symbol->getAddress()) &&
                           new_delta <= arch::getPageSize<arch::getCurrentArchitecture()>() * 3) {
                    *sym = symbol;
                    *delta = new_delta;
                }
            }
        }
    }
}

Symbol* debug::symbolicate::getSymbolFromAddress(xnu::Mach::VmAddress address, Offset* delta) {
    Symbol* kernel_sym = nullptr;
    Symbol* kext_sym = nullptr;

    Offset kernel_delta = 0;
    Offset kext_delta = 0;

    darwin::DarwinKit* darwin = mac_rootkit_get_rootkit();

    xnu::Kernel* kernel = darwin->getKernel();

    std::vector<xnu::Kext*>& kexts = darwin->getKexts();

    debug::symbolicate::lookForAddressInsideKernel(address, kernel, &kernel_sym, &kernel_delta);

    debug::symbolicate::lookForAddressInsideKexts(address, kexts, &kext_sym, &kext_delta);

    if (!kernel_sym && !kext_sym)
        return nullptr;
    else if (kernel_sym && kext_sym) {
        *delta = kext_delta > kernel_delta ? kernel_delta : kext_delta;

        return kext_delta > kernel_delta ? kernel_sym : kext_sym;
    } else if (!kext_sym) {
        *delta = kernel_delta;

        return kernel_sym;
    }

    *delta = kext_delta;

    return kext_sym;
}

void debug::printBacktrace() {
    constexpr arch::Architectures arch = arch::getCurrentArchitecture();

    union arch::ThreadState thread_state;

    arch::getThreadState<arch>(&thread_state);

    if constexpr (arch::_arm64<arch>) {
        UInt64 fp = thread_state.state_arm64.fp;

        UInt32 frame = 0;

        while (fp && looksLikeKernelPointer(fp)) {
            Symbol* symbol;

            Offset delta;

            UInt64 lr = *(UInt64*)(fp + sizeof(UInt64));

            if (looksLikeKernelPointer(lr)) {
                lr |= 0xfffffe0000000000;

                char buffer[128];

                snprintf(buffer, 128, "0x%llx", fp);

                DARWIN_RK_LOG("MacRK::frame pointer = %s\n", buffer);

                snprintf(buffer, 128, "0x%llx", lr);

                DARWIN_RK_LOG("MacRK::link register = %s\n", buffer);

                symbol = debug::symbolicate::getSymbolFromAddress(lr, &delta);

                if (symbol) {

                    DARWIN_RK_LOG("MacRK::frame %u: %s %s + %llu\n", frame, buffer, symbol->getName(),
                               delta);
                }

                fp = *(UInt64*)fp;
            } else
                break;

            frame++;
        }
    }

    if constexpr (arch::_x86_64<arch>) {
        UInt64 rbp = thread_state.state_x86_64.rbp;

        UInt32 frame = 0;

        while (rbp && looksLikeKernelPointer(rbp)) {
            Symbol* symbol;

            Offset delta;

            UInt64 rip = *(UInt64*)(rbp + sizeof(UInt64));

            if (looksLikeKernelPointer(rip)) {
                symbol = debug::symbolicate::getSymbolFromAddress(rip, &delta);

                DARWIN_RK_LOG("frame %u: 0x%x %s + %llu", frame, rip, symbol->getName(), delta);

                rbp = *(UInt64*)rbp;
            } else
                break;

            frame++;
        }
    }
}