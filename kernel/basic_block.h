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

#include "instruction.h"

namespace darwinkit {
namespace ir {

template <typename Bin>
class BasicBlock {
public:
    using InstructionList = std::vector<Instruction*>;
    using BasicBlockList = std::vector<BasicBlock<Bin>*>
    using iterator = InstructionList::iterator;

    explicit BasicBlock() {}

    ~BasicBlock() = default;

    Bin* GetBinary() { return bin; }

    InstructionList& GetInstructions() { return instructions; }

    Instruction* GetTerminator();

    BasicBlockList GetSuccessors();

    BasicBlockList GetPrecedessors():

    inline iterator begin() { return instructions.begin(); }

    inline iterator end() { return instructions.end(); }

private:
    UInt64 pc;

    Bin *bin;

    InstructionList instructions;

    BasicBlockList successors;
    BasicBlockList predecessors;
};

}
}