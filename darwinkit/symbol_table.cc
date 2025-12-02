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

#include "symbol_table.h"

#ifdef __USER__
#include <memory>
#include <cxxabi.h>
#include <dlfcn.h>
#endif

extern "C" {
#ifdef __USER__

char* cxx_demangle(char* mangled) {
    int status;

    char* ret = abi::__cxa_demangle(mangled, 0, 0, &status);

    std::shared_ptr<char> retval;

    retval.reset((char*)ret, [](char* mem) {
        if (mem)
            free((void*)mem);
    });

    return static_cast<char*>(retval.get());
}

typedef char* (*_swift_demangle)(char* mangled, UInt32 length, UInt8* output_buffer,
                                 UInt32 output_buffer_size, UInt32 flags);

char* swift_demangle(char* mangled) {
    void* runtime_loader_default = dlopen(nullptr, RTLD_NOW);

    if (runtime_loader_default) {
        void* sym = dlsym(runtime_loader_default, "swift_demangle");

        if (sym) {
            _swift_demangle f = reinterpret_cast<_swift_demangle>(sym);

            char* cString = f(mangled, strlen(mangled), nullptr, 0, 0);

            if (cString) {
                dlclose(runtime_loader_default);

                return cString;
            }
        }

        dlclose(runtime_loader_default);
    }

    return nullptr;
}

#else

char* cxx_demangle(char* mangled) {
    return nullptr;
}
char* swift_demangle(char* mangled) {
    return nullptr;
}

#endif
}

Symbol* SymbolTable::GetSymbolByName(char* symname) {
    for (int32_t i = 0; i < symbolTable.size(); i++) {
        Symbol* symbol = symbolTable.at(i);
        if (strcmp(symbol->GetName(), symname) == 0) {
            return symbol;
        }
    }

    return nullptr;
}

Symbol* SymbolTable::GetSymbolByAddress(xnu::mach::VmAddress address) {
    for (int32_t i = 0; i < symbolTable.size(); i++) {
        Symbol* symbol = symbolTable.at(i);
        if (symbol->GetAddress() == address) {
            return symbol;
        }
    }

    return nullptr;
}

Symbol* SymbolTable::GetSymbolByOffset(Offset offset) {
    for (int32_t i = 0; i < symbolTable.size(); i++) {
        Symbol* symbol = symbolTable.at(i);
        if (symbol->GetOffset() == offset) {
            return symbol;
        }
    }

    return nullptr;
}

void SymbolTable::ReplaceSymbol(Symbol* symbol) {
    for (int i = ((int)symbolTable.size()) - 1; i >= 0; i--) {
        Symbol* sym = symbolTable.at(i);
        if (strcmp(sym->GetName(), symbol->GetName()) == 0) {
            symbolTable.erase(std::remove(symbolTable.begin(), symbolTable.end(), sym),
                              symbolTable.end());

            i--;
        }
    }
    symbolTable.push_back(symbol);
}