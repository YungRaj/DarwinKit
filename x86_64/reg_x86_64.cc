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

#include "reg_x86_64.h"

namespace arch {
namespace x86_64 {
uintptr_t getCR0() {
    uintptr_t cr0;

#if __x86_64__
    __asm__ volatile("mov %%cr0, %0" : "=r"(cr0));
#endif

    return cr0;
}

void setCR0(uintptr_t value) {

#if __x86_64__
    __asm__ volatile("mov %0, %%cr0" : : "r"(value));
#endif
}

uintptr_t getEFER() {
    uintptr_t efer;

#if __x86_64__
    __asm__ volatile("rdmsr" : : "A"(efer), "c"(MSR_IA32_EFER));
#endif

    return efer;
}

void setEFER(uintptr_t value) {
    uintptr_t efer;

#if __x86_64__
    __asm__ volatile("rdmsr" : : "A"(efer), "c"(MSR_IA32_EFER));
    __asm__ volatile("wrmsr" : : "a"(value), "c"(MSR_IA32_EFER));
#endif
}
} // namespace x86_64
} // namespace arch