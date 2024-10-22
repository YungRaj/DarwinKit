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

#include <type_traits>

#include <vector>

#include <types.h>

#include "arch.h"

#include "fuzzer.h"

class MachO;
class Symbol;

class Architecture;

namespace Fuzzer {
struct FuzzBinary;

class Harness;
class Loader;

template <typename T>
using GetAllSymbolsReturnType = decltype(std::declval<T>()->getAllSymbols());

class Module {
public:
    explicit Module(Fuzzer::Loader* loader, const char* path, struct FuzzBinary* binary)
        : loader(loader), path(path), mainBinary(binary) {}

    explicit Module(const char* path, xnu::Mach::VmAddress base, Offset slide)
        : path(path), base(base), slide(slide) {}

    ~Module();

    Fuzzer::Loader* getLoader() const {
        return loader;
    }

    const char* getName() const {
        return name;
    }

    const char* getPath() const {
        return path;
    }

    xnu::Mach::VmAddress getEntryPoint();

    template <typename Binary, typename Sym>
        requires AnyBinaryFormat<Binary>
    std::vector<Sym>& getSymbols() const
        requires requires(Binary bin, Sym sym) {
            sym->getName();
            sym->getAddress();
            std::is_same_v<GetAllSymbolsReturnType<Binary>, std::vector<Sym*>&>;
        }
    {
        return getBinary<Binary>()->getAllSymbols();
    }

    template <typename Binary, typename Sym>
        requires AnyBinaryFormat<Binary>
    std::vector<Sym>* getUndefinedSymbols() const
        requires requires(Binary bin, Sym sym) {
            sym->getName();
            sym->getAddress();
            sym->isUndefined();
            std::is_same_v<GetAllSymbolsReturnType<Binary>, std::vector<Sym>*>;
        }
    {
        Binary bin = getBinary<Binary>();

        std::vector<Sym>* syms = new std::vector<Sym>();
        std::vector<Sym>& allsyms = bin->getAllSymbols();

        for (int i = 0; i < allsyms.size(); i++) {
            Sym sym = allsyms.at(i);

            if (sym->isUndefined())
                syms->push_back(sym);
        }

        return syms;
    }

    template <typename Binary, typename Sym>
        requires AnyBinaryFormat<Binary>
    std::vector<Sym>* getExternalSymbols() const
        requires requires(Sym sym) {
            sym->getName();
            sym->getAddress();
            sym->isExternal();
            std::is_same_v<GetAllSymbolsReturnType<Binary>, std::vector<Sym>*>;
        }
    {
        Binary bin = getBinary<Binary>();

        std::vector<Sym>* syms = new std::vector<Sym>();
        std::vector<Sym>& allsyms = bin->getAllSymbols();

        for (int i = 0; i < allsyms.size(); i++) {
            Sym sym = allsyms.at(i);

            if (sym->isExternal())
                syms->push_back(sym);
        }

        return syms;
    }

    struct FuzzBinary* getMainBinary() const {
        return mainBinary;
    }

    struct FuzzBinary* getModuleBinary() const {
        return moduleBinary;
    }

    template <typename T>
    T getBinary() const
        requires AnyBinaryFormat<T> && PointerToClassType<T>
    {
        static_assert(AnyBinaryFormat<T>, "Unsupported type for Module::getBinary()");

        if constexpr (std::is_base_of_v<MachO, std::remove_pointer_t<T>>) {
            return dynamic_cast<T>(moduleBinary->binary.macho);
        }

        if constexpr (std::is_same_v<T, MachO*>) {
            return moduleBinary->binary.macho;
        }

        if constexpr (std::is_same_v<T, RawBinary*>) {
            return moduleBinary->binary.raw;
        }

        return nullptr;
    }

    template <typename T>
        requires CastableType<T>
    T operator[](UInt64 index) const {
        return reinterpret_cast<T>((UInt8*)base + index);
    }

    template <typename T>
        requires IntegralOrPointerType<T>
    T getBase() const {
        return reinterpret_cast<T>(base);
    }

    Size getSize() const {
        return size;
    }

    Offset getSlide() const {
        return slide;
    }

    void load();

    template <typename Seg>
    void mapSegment(Seg segment)
        requires requires(Seg seg) { seg->getAddress(); };

    template <typename Seg>
    void modifySegment(Seg segment)
        requires requires(Seg seg) { seg->getAddress(); };

private:
    Fuzzer::Loader* loader;

    const char* name;
    const char* path;

    struct FuzzBinary* mainBinary;
    struct FuzzBinary* moduleBinary;

    xnu::Mach::VmAddress base;

    Size size;

    Offset slide;
};

class Loader {
public:
    explicit Loader(Fuzzer::Harness* harness, struct FuzzBinary* binary);

    ~Loader();

    Fuzzer::Harness* getHarness() const {
        return harness;
    }

    struct FuzzBinary* getFuzzBinary() const {
        return binary;
    }

    arch::Architecture* getArchitecture() const {
        return arch;
    }

    Fuzzer::Module* getModule(char* name) {
        for (int i = 0; i < modules.size(); i++) {
            Fuzzer::Module* module = modules.at(i);

            if (strcmp(module->getName(), name) == 0) {
                return module;
            }
        }

        return nullptr;
    }

    template <typename Binary>
        requires AnyBinaryFormat<Binary>
    void loadModule(Module* module);

    void loadModuleFromKext(const char* kextPath);

    void loadKextMachO(const char* kextPath, xnu::Mach::VmAddress* loadAddress, Size* loadSize,
                       xnu::Mach::VmAddress* oldLoadAddress);

    template <typename Sym, typename Binary>
        requires AnyBinaryFormat<Binary>
    void linkSymbols(Module* module)
        requires requires(Sym sym) {
            sym->getName();
            sym->getAddress();
            std::is_same_v<GetSymbolReturnType<Binary>, Sym>;
        };

    template <typename Sym, typename Binary>
        requires AnyBinaryFormat<Binary>
    void linkSymbol(Module* module, Sym sym)
        requires requires(Sym sym) {
            sym->getName();
            sym->getAddress();
            std::is_same_v<GetSymbolReturnType<Binary>, Sym>;
        };

    template <typename Sym, typename Binary>
        requires AnyBinaryFormat<Binary>
    void stubFunction(Module* module, Sym sym, xnu::Mach::VmAddress stub)
        requires requires(Sym sym) {
            sym->getName();
            sym->getAddress();
            std::is_same_v<GetSymbolReturnType<Binary>, Sym>;
        };

    template <typename Sym, typename Binary>
        requires AnyBinaryFormat<Binary>
    void shimFunction(Module* module, Sym sym, xnu::Mach::VmAddress stub)
        requires requires(Sym sym) {
            sym->getName();
            sym->getAddress();
            std::is_same_v<GetSymbolReturnType<Binary>, Sym>;
        };

    void* allocateModuleMemory(Size sz, int prot);

private:
    Fuzzer::Harness* harness;

    arch::Architecture* arch;

    struct FuzzBinary* binary;

    std::vector<Module*> modules;
};
}; // namespace Fuzzer
