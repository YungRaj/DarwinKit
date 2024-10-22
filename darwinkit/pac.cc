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

#include "pac.h"

#ifdef defined(__arm64__) || defined(__arm64e__)

UInt64 arch::arm64::pac::signPointerWithAKey(UInt64 pointer) {
    __asm__ volatile("PACIZA %[pac]" : [pac] "+rm"(pointer));

    return pointer;
}

UInt64 arch::arm64::pac::signPointerWithBKey(UInt64 pointer) {
    __asm__ volatile("PACIZB %[pac]" : [pac] "+rm"(pointer));

    return pointer;
}

void arch::arm64::PAC::stripPointerAuthenticationCode(UInt64 pointer) {}

#endif