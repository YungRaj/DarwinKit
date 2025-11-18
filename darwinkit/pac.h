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

#include <types.h>

#include <mach/mach_types.h>

#include <ptrauth.h>

#include "arch.h"

#ifdef defined(__arm64__) || defined(__arm64e__)

static_assert(arch::_arm64<arch::GetCurrentArchitecture()>);

namespace arch {
namespace arm64 {
namespace pac {
UInt64 SignPointerWithAKey(UInt64 pointer);

UInt64 SignPointerWithBKey(UInt64 pointer);

void StripPointerAuthenticationCode(UInt64 pointer);
} // namespace PAC
} // namespace arm64
}; // namespace arch

#define PacSignPointerWithAKey(ptr) arch::arm64::pac::signPointerWithAKey(ptr)
#define PacSignPointerWithBKey(ptr) arch::arm64::pac::signPointerWithBKey(ptr);

#else

#define PacSignPointerWithAKey(ptr) ptr
#define PacSignPointerWithBKey(ptr) ptr

#endif