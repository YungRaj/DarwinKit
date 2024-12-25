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

#include <sys/types.h>

#include "symbol.h"

class Symbol;
class MachO;

class SymbolTable {
public:
    explicit SymbolTable() {}

    explicit SymbolTable(xnu::macho::Nlist64* symtab, UInt32 nsyms, char* strtab, Size strsize)
        : symtab(symtab), nsyms(nsyms), strtab(strtab), strsize(strsize) {}

    ~SymbolTable() = default;

    std::vector<Symbol*>& GetAllSymbols() {
        return symbolTable;
    }

    bool ContainsSymbolNamed(char* name) {
        return GetSymbolByName(name) != nullptr;
    }

    bool ContainsSymbolWithAddress(xnu::mach::VmAddress address) {
        return GetSymbolByAddress(address) != nullptr;
    }

    bool ContainsSymbolWithOffset(Offset offset) {
        return GetSymbolByOffset(offset) != nullptr;
    }

    Symbol* GetSymbolByName(char* name);

    Symbol* GetSymbolByAddress(xnu::mach::VmAddress address);

    Symbol* GetSymbolByOffset(Offset offset);

    void AddSymbol(Symbol* symbol) {
        symbolTable.push_back(symbol);
    }

    void RemoveSymbol(Symbol* symbol) {
        symbolTable.erase(std::remove(symbolTable.begin(), symbolTable.end(), symbol),
                          symbolTable.end());
    }

    void ReplaceSymbol(Symbol* symbol);

private:
    std::vector<Symbol*> symbolTable;

    xnu::macho::Nlist64* symtab;

    UInt32 nsyms;

    char* strtab;

    Size strsize;
};