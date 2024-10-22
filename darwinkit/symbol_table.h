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

#include <Types.h>

#include <sys/types.h>

#include "symbol.h"

class Symbol;
class MachO;

class SymbolTable {
public:
    explicit SymbolTable() {}

    explicit SymbolTable(xnu::Macho::Nlist64* symtab, UInt32 nsyms, char* strtab, Size strsize)
        : symtab(symtab), nsyms(nsyms), strtab(strtab), strsize(strsize) {}

    std::vector<Symbol*>& getAllSymbols() {
        return symbolTable;
    }

    bool containsSymbolNamed(char* name) {
        return getSymbolByName(name) != nullptr;
    }

    bool containsSymbolWithAddress(xnu::Mach::VmAddress address) {
        return getSymbolByAddress(address) != nullptr;
    }

    bool containsSymbolWithOffset(Offset offset) {
        return getSymbolByOffset(offset) != nullptr;
    }

    Symbol* getSymbolByName(char* name);

    Symbol* getSymbolByAddress(xnu::Mach::VmAddress address);

    Symbol* getSymbolByOffset(Offset offset);

    void addSymbol(Symbol* symbol) {
        symbolTable.push_back(symbol);
    }

    void removeSymbol(Symbol* symbol) {
        symbolTable.erase(std::remove(symbolTable.begin(), symbolTable.end(), symbol),
                          symbolTable.end());
    }

    void replaceSymbol(Symbol* symbol);

private:
    std::vector<Symbol*> symbolTable;

    xnu::Macho::Nlist64* symtab;

    UInt32 nsyms;

    char* strtab;

    Size strsize;
};