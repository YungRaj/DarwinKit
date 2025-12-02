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

#include "arch.h"

#include <capstone/capstone.h>

namespace darwinkit {
namespace ir {

template <typname Bin>
class BasicBlock;

template <typename Bin>
class Instruction {
public:
    explicit Instruction() {}

    ~Instruction() = default;

    Architecture* GetArchitecture() {
        return architecture;
    }

    BasicBlock<Bin>* GetBasicBlock() {
        return basic_block;
    }

    bool IsTerminator() const;

private:
    UInt64 pc;

    Architecture* architecture;

    BasicBlock<Bin>* block;

    cs_insn insn;
};

} // namespace ir
} // namespace darwinkit