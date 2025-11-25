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

#include "emu_fuzzer.h"

class MachO;
class Symbol;

class Architecture;

namespace fuzzer {
struct FuzzBinary;

class Harness;
class Loader;

template <typename T>
using GetAllSymbolsReturnType = decltype(std::declval<T>()->GetAllSymbols());

class Module {
public:
    explicit Module(fuzzer::Loader* loader, const char* path, struct FuzzBinary* binary)
        : loader(loader), path(path), mainBinary(binary) {}

    explicit Module(const char* path, xnu::mach::VmAddress base, Offset slide)
        : path(path), base(base), slide(slide) {}

    ~Module() = default;

    fuzzer::Loader* GetLoader() const {
        return loader;
    }

    const char* GetName() const {
        return name;
    }

    const char* GetPath() const {
        return path;
    }

    xnu::mach::VmAddress GetEntryPoint();

    template <typename Binary, typename Sym>
        requires AnyBinaryFormat<Binary>
    std::vector<Sym>& GetSymbols() const
        requires requires(Binary bin, Sym sym) {
            sym->GetName();
            sym->GetAddress();
            std::is_same_v<GetAllSymbolsReturnType<Binary>, std::vector<Sym*>&>;
        }
    {
        return GetBinary<Binary>()->GetAllSymbols();
    }

    template <typename Binary, typename Sym>
        requires AnyBinaryFormat<Binary>
    std::vector<Sym>* GetUndefinedSymbols() const
        requires requires(Binary bin, Sym sym) {
            sym->GetName();
            sym->GetAddress();
            sym->IsUndefined();
            std::is_same_v<GetAllSymbolsReturnType<Binary>, std::vector<Sym>*>;
        }
    {
        Binary bin = GetBinary<Binary>();

        std::vector<Sym>* syms = new std::vector<Sym>();
        std::vector<Sym>& allsyms = bin->GetAllSymbols();

        for (int i = 0; i < allsyms.size(); i++) {
            Sym sym = allsyms.at(i);

            if (sym->IsUndefined())
                syms->push_back(sym);
        }

        return syms;
    }

    template <typename Binary, typename Sym>
        requires AnyBinaryFormat<Binary>
    std::vector<Sym>* GetExternalSymbols() const
        requires requires(Sym sym) {
            sym->GetName();
            sym->GetAddress();
            sym->IsExternal();
            std::is_same_v<GetAllSymbolsReturnType<Binary>, std::vector<Sym>*>;
        }
    {
        Binary bin = GetBinary<Binary>();

        std::vector<Sym>* syms = new std::vector<Sym>();
        std::vector<Sym>& allsyms = bin->GetAllSymbols();

        for (int i = 0; i < allsyms.size(); i++) {
            Sym sym = allsyms.at(i);

            if (sym->IsExternal())
                syms->push_back(sym);
        }

        return syms;
    }

    struct FuzzBinary* GetMainBinary() const {
        return mainBinary;
    }

    struct FuzzBinary* GetModuleBinary() const {
        return moduleBinary;
    }

    template <typename T>
    T GetBinary() const
        requires AnyBinaryFormat<T> && PointerToClassType<T>
    {
        static_assert(AnyBinaryFormat<T>, "Unsupported type for Module::GetBinary()");

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
    T GetBase() const {
        return reinterpret_cast<T>(base);
    }

    Size GetSize() const {
        return size;
    }

    Offset GetSlide() const {
        return slide;
    }

    void Load();

    template <typename Seg>
    void MapSegment(Seg segment)
        requires requires(Seg seg) { seg->GetAddress(); };

    template <typename Seg>
    void ModifySegment(Seg segment)
        requires requires(Seg seg) { seg->GetAddress(); };

private:
    fuzzer::Loader* loader;

    const char* name;
    const char* path;

    struct FuzzBinary* mainBinary;
    struct FuzzBinary* moduleBinary;

    xnu::mach::VmAddress base;

    Size size;

    Offset slide;
};

class Loader {
public:
    explicit Loader(fuzzer::Harness* harness, struct FuzzBinary* binary);

    ~Loader();

    fuzzer::Harness* GetHarness() const {
        return harness;
    }

    struct FuzzBinary* GetFuzzBinary() const {
        return binary;
    }

    arch::Architecture* GetArchitecture() const {
        return arch;
    }

    fuzzer::Module* GetModule(char* name) {
        for (int i = 0; i < modules.size(); i++) {
            fuzzer::Module* module = modules.at(i);

            if (strcmp(module->GetName(), name) == 0) {
                return module;
            }
        }

        return nullptr;
    }

    template <typename Binary>
        requires AnyBinaryFormat<Binary>
    void LoadModule(Module* module);

    void LoadModuleFromKext(const char* kextPath);

    void LoadKextMachO(const char* kextPath, xnu::mach::VmAddress* loadAddress, Size* loadSize,
                       xnu::mach::VmAddress* oldLoadAddress);

    template <typename Sym, typename Binary>
        requires AnyBinaryFormat<Binary>
    void LinkSymbols(Module* module)
        requires requires(Sym sym) {
            sym->GetName();
            sym->GetAddress();
            std::is_same_v<GetSymbolReturnType<Binary>, Sym>;
        };

    template <typename Sym, typename Binary>
        requires AnyBinaryFormat<Binary>
    void LinkSymbol(Module* module, Sym sym)
        requires requires(Sym sym) {
            sym->GetName();
            sym->GetAddress();
            std::is_same_v<GetSymbolReturnType<Binary>, Sym>;
        };

    template <typename Sym, typename Binary>
        requires AnyBinaryFormat<Binary>
    void StubFunction(Module* module, Sym sym, xnu::mach::VmAddress stub)
        requires requires(Sym sym) {
            sym->GetName();
            sym->GetAddress();
            std::is_same_v<GetSymbolReturnType<Binary>, Sym>;
        };

    template <typename Sym, typename Binary>
        requires AnyBinaryFormat<Binary>
    void ShimFunction(Module* module, Sym sym, xnu::mach::VmAddress stub)
        requires requires(Sym sym) {
            sym->GetName();
            sym->GetAddress();
            std::is_same_v<GetSymbolReturnType<Binary>, Sym>;
        };

    void* AllocateModuleMemory(Size sz, int prot);

private:
    fuzzer::Harness* harness;

    arch::Architecture* arch;

    struct FuzzBinary* binary;

    std::vector<Module*> modules;
};
}; // namespace fuzzer
