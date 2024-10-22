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

#include "disassembler_x86_64.h"
#include "isa_x86_64.h"
#include "patch_finder_x86_64.h"

namespace arch {
namespace x86_64 {
bool SetInterrupts(bool enable);

bool SetNXBit(bool enable);

bool SetWPBit(bool enable);
} // namespace x86_64
} // namespace arch