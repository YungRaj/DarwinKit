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

#include <memory>
#include <types.h>

#include "basic_block.h"
#include "disassembler.h"
#include "macho.h"
#include "symbol.h"

namespace darwinkit {
namespace ir {

template <typename Bin>
struct ControlFlowGraphAttributes {
    using SegmentType = decltype(std::declval<Bin>()->GetSegment(nullptr));
    using SectionType = decltype(std::declval<Bin>()->GetSection(nullptr, nullptr));
    using SymbolType = decltype(std::declval<Bin>()->GetSymbol(nullptr));
};

template <typename Bin>
class ControlFlowGraph {
public:
    using BasicBlockList = std::vector<BasicBlock<Bin>*>;
    using iterator = BasicBlockList::iterator;

    using Seg = typename ControlFlowGraphAttributes<Bin>::SegmentType;
    using Sect = typename ControlFlowGraphAttributes<Bin>::SectionType;
    using Sym = typename ControlFlowGraphAttributes<Bin>::SymbolType;

    explicit ControlFlowGraph() {}

    ~ControlFlowGraph() = default;

    T* GetBinary() const {
        return binary;
    }

    Sym* GetSymbol() const {
        return symbol;
    }

    inline iterator begin() {
        return blocks.begin();
    }
    inline const_iterator const_begin() const {
        return blocks.begin();
    }

    inline iterator end() {
        return blocks.end();
    }
    inline const_iterator const_end() const {
        return blocks.end();
    }

private:
    UInt64 pc;

    Disassembler* disassembler;

    T* binary;

    Bin* symbol;

    BasicBlockList blocks;
};

template <typename Bin>
class PreOrder {
public:
    using BasicBlockList = ControlFlowGraph<Bin>::BasicBlockList;

    explicit PreOrder(ControlFlowGraph<Bin>* cfg);

    PreOrder(const PreOrder&) = delete;
    PreOrder& operator=(const PreOrder&) = delete;

    ~PreOrder() = default;

    BasicBlockList GetBlocks() const {
        return pre_order_blocks_;
    }

    iterator begin() {
        return pre_order_blocks_.begin();
    }
    const_iterator const_begin() const {
        return pre_order_blocks_.begin();
    }

    iterator end() override {
        return pre_order_blocks_.end();
    }
    const_iterator const_end() const {
        return pre_order_blocks_.end();
    }

    bool IsBackEdge(BasicBlock<Bin>* block) {
        return back_edges_.contains(block);
    }

private:
    void Visit(BasicBlockList* seen_on_path, BasicBlockList > *visited, BasicBlock<Bin>* cur_block);

    BasicBlockList pre_order_blocks_;

    BasicBlockList back_edges_;
};

} // namespace ir
} // namespace darwinkit