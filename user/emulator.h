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

#include <unicorn/unicorn.h>

namespace emulation {
class Unicorn {
public:
    explicit Unicorn(UInt8* code, Size code_size, UInt64 address)
        : code(code), size(code_size), base(address) {}

private:
    uc_engine* uc;

    UInt64 base;
    UInt64 code;

    Size size;
};

class Panda {
public:
private:
};

template <typename Emu>
class Emulator {
public:
    explicit Emulator();

private:
    Emu* emu;
};
}; // namespace emulation
