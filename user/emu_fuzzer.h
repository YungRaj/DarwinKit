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

extern "C" {
#include <stdio.h>
#include <string.h>
};

#include <vector>

#include <types.h>

#include "kernel.h"

#include "binary_format.h"

#include "kernel_macho.h"
#include "kext_macho.h"
#include "macho.h"

// #include "Emulator.hpp"

template <typename T>
concept ClassType = std::is_class_v<T>;

template <typename T>
concept VoidPointerType = std::is_same_v<std::remove_pointer_t<T>, void>;

template <typename T>
concept PointerToClassType =
    (std::is_pointer_v<T> && std::is_class_v<std::remove_pointer_t<T>>) || VoidPointerType<T>;

template <typename T>
concept FundamentalType = std::is_fundamental_v<T>;

template <typename T>
concept ScalarType = std::is_scalar_v<T>;

template <typename T>
concept PodType = std::is_pod_v<T>;

template <typename T>
concept IntegralType = std::is_integral_v<T>;

template <typename T>
concept PointerType = std::is_pointer_v<T>;

template <typename T>
concept IntegralOrPointerType = IntegralType<T> || PointerType<T>;

template <typename T>
concept CastableType = FundamentalType<T> || PodType<T> || IntegralType<T> || PointerType<T>;

namespace darwin {
namespace vm {
class Hypervisor;
};
};

namespace emulation {
class Unicorn;
class Panda;

template <typename Emu>
class Emulator;
}; // namespace emulation

namespace fuzzer {
class Loader;
class Module;

enum LanguageType { LANG_TYPE_C, LANG_TYPE_CXX, LANG_TYPE_OBJC, LANG_TYPE_SWIFT, LANG_TYPE_RUST };

template <LanguageType LangType>
concept ManglableLang = LangType == LANG_TYPE_CXX || LangType == LANG_TYPE_SWIFT;

template <typename T, typename Sym>
concept HasCompatibleSymbol = std::is_same_v<Sym, decltype(std::declval<T>()->GetSymbol(nullptr))>;

template <typename T, typename Seg>
concept HasCompatibleSegment =
    std::is_same_v<Seg, decltype(std::declval<T>()->GetSegment(nullptr))>;

template <typename T, typename Sect>
concept HasCompatibleSection =
    std::is_same_v<Sect, decltype(std::declval<T>()->GetSection(nullptr))>;

template <typename T, typename Sym, typename Seg>
concept MappableBinary =
    std::is_base_of_v<binary::BinaryFormat, std::remove_pointer_t<T>> &&
    HasCompatibleSymbol<T, Sym> && (HasCompatibleSegment<T, Seg> || HasCompatibleSection<T, Seg>);

template <typename T, typename Sym, typename Sect>
struct LinkerMap {
    static_assert(MappableBinary<T, Sym, Sect>);

public:
    explicit LinkerMap(T binary, char* map) : binary(binary), mapFilePath(map) { Read(); ParseMapFile(); }

    T GetBinary() const {
        return binary;
    }

    char* GetMapFilePath() const {
        return mapFilePath;
    }

    char* GetMapFile() const {
        return mapFile;
    }

    std::vector<Sym>& GetSymbols() {
        return symbols;
    }
    std::vector<Sect>& GetSections() {
        return sections;
    }

    Size GetSymbolCount() {
        return symbols.size();
    }

    Size GetSectionCount() {
        return sections.size();
    }

    void Read();

    void ParseMapFile();

private:
    T binary;

    std::vector<Sym> symbols;
    std::vector<Sect> sections;

    char* mapFilePath;
    char* mapFile;
};

struct RawBinary : public binary::BinaryFormat {

    struct SectionRaw {
    public:
        explicit SectionRaw(char* name, xnu::mach::VmAddress address, Size size, int prot, int idx)
            : name(name), address(address), size(size), prot(prot), idx(idx) {}

        char* GetName() const {
            return name;
        }

        template <typename T>
        T operator[](UInt64 index) const {
            return reinterpret_cast<T>((UInt8*)address + index);
        }

        xnu::mach::VmAddress GetAddress() const {
            return address;
        }

        template <typename T>
        T GetAddressAs() const {
            return reinterpret_cast<T>(address);
        }

        Size GetSize() const {
            return size;
        }

        int GetProt() const {
            return prot;
        }

        int GetIndex() const {
            return idx;
        }

    private:
        char* name;

        xnu::mach::VmAddress address;

        Size size;

        int prot;
        int idx;
    };

    struct SymbolRaw {
    public:
        explicit SymbolRaw(char* name, xnu::mach::VmAddress address, int type)
            : name(name), address(address), type(type) {}

        char* GetName() const {
            return name;
        }

        template <LanguageType LangType>
            requires ManglableLang<LangType>
        char* GetDemangledName() {
            if constexpr (LangType == LANG_TYPE_SWIFT) {
                char* _swift_demangle = swift_demangle(GetName());

                if (_swift_demangle)
                    return _swift_demangle;
            }

            if constexpr (LangType == LANG_TYPE_CXX) {
                char* _cxx_demangle = cxx_demangle(GetName());

                if (_cxx_demangle)
                    return _cxx_demangle;
            }

            char* empty = new char[1];

            *empty = '\0';

            return empty;
        }

        xnu::mach::VmAddress GetAddress() const {
            return address;
        }

        int GetType() const {
            return type;
        }

        bool IsNamed() {
            return !name || strcmp(name, "") == 0;
        }

        bool IsUndefined() const {
            return false;
        }

        bool IsExternal() const {
            return false;
        }

    private:
        char* name;

        xnu::mach::VmAddress address;

        int type;
    };

public:
    explicit RawBinary(char* path, char* mapFile) : path(path), mapFile(mapFile) {}

    template <typename T>
    T operator[](UInt64 index) const {
        return reinterpret_cast<T>((UInt8*)base + index);
    }

    xnu::mach::VmAddress GetBase() const {
        return base;
    }

    template <typename T>
    T GetBaseAs() const {
        return reinterpret_cast<T>(base);
    }

    char* GetMapFile() const {
        return mapFile;
    }

    std::vector<SymbolRaw*>& GetAllSymbols() {
        return linkerMap->GetSymbols();
    }

    SymbolRaw* GetSymbol(const char* name) {
        std::vector<SymbolRaw*>& symbols = linkerMap->GetSymbols();

        for (int i = 0; i < symbols.size(); i++) {
            SymbolRaw* sym = symbols.at(i);

            if (strcmp(name, sym->GetName()) == 0)
                return sym;
        }

        return nullptr;
    }

    SectionRaw* GetSection(const char* name) {
        std::vector<SectionRaw*>& sections = linkerMap->GetSections();

        for (int i = 0; i < sections.size(); i++) {
            SectionRaw* sect = sections.at(i);

            if (strcmp(name, sect->GetName()) == 0)
                return sect;
        }

        return nullptr;
    }

    void PopulateSymbols();
    void PopulateSections();

private:
    xnu::mach::VmAddress base;

    char* path;

    char* mapFile;

    LinkerMap<RawBinary*, SymbolRaw*, SectionRaw*>* linkerMap;
};

template <typename T>
concept BinaryFmt = std::is_same_v<T, binary::BinaryFormat*>;

template <typename T>
concept MachOFormat =
    std::is_base_of_v<MachO, std::remove_pointer_t<T>> || std::is_same_v<T, MachO*>;

/*
template <typename T>
concept ELFFormat = std::is_same_v<T, ELF*>;

template <typename T>
concept PEFormat = std::is_same_v<T, PE*>;

template <typename T>
concept TEFormat = std::is_same_v<T, TE*>;
*/

template <typename T>
concept RawBinaryFormat = std::is_same_v<T, RawBinary*>;

template <typename T>
concept AnyBinaryFormat = BinaryFmt<T> || MachOFormat<T>  /* || ELFFormat<T> || PEFormat<T> ||
                          TEFormat<T> */ || RawBinaryFormat<T> || VoidPointerType<T>;

static_assert(MachOFormat<xnu::KernelMachO*>,
              "KernelMachO does not satisfy MachOFormat constraint");
static_assert(MachOFormat<xnu::KextMachO*>, "KextMachO does not satisfy MachOFormat constraint");

static_assert(RawBinaryFormat<RawBinary*>);

using SymbolRaw = RawBinary::SymbolRaw;
using SectionRaw = RawBinary::SectionRaw;

template <typename T>
using GetSymbolReturnType = decltype(std::declval<T>()->GetSymbol(nullptr));

template <typename T>
using GetSegmentReturnType = decltype(std::declval<T>()->GetSegment(nullptr));

template <typename T>
using GetSectionReturnType = decltype(std::declval<T>()->GetSection(nullptr));

static_assert(std::is_same_v<GetSymbolReturnType<MachO*>, Symbol*>);
static_assert(std::is_same_v<GetSymbolReturnType<RawBinary*>, SymbolRaw*>);

struct FuzzBinary {
    const char* path;

    void* base;
    void* originalBase;

    Size size;

    template <PointerToClassType T>
        requires AnyBinaryFormat<T>
    union Bin {
        /* We know the binary is a any of the below BinaryFormats */
        T bin;

        /* Support BinaryFormat */
        binary::BinaryFormat* binFmt;

        /* Support MachO */
        MachO* macho;

        /* Support Linux Binary fuzzing on ELFs */
        // ELF* elf;

        /* Support EFI fuzzing on PE32/TE */
        // PE* portableExecutable;

        // TE* terseExecutable;

        /* Support Raw Binary */
        RawBinary* raw;

        /* Support void* to use type punning */
        void* binPtr;

        /* This union constrains the Binary Format types */
        /* The following binary formats are supported but may not be implemented */

        Bin() : binPtr(nullptr) {}

        Bin(T ptr) : bin(ptr) {}

        template <typename U>
            requires AnyBinaryFormat<U>
        Bin(const Bin<U>& other) {
            static_assert(std::is_convertible_v<U, T>,
                          "Incompatible BinaryFormat types for type punning");

            binPtr = static_cast<T>(static_cast<U>(other.binPtr));
        }
    };

    template <PointerToClassType T>
        requires AnyBinaryFormat<T>
    static constexpr Bin<T> MakeBinary(T ptr) {
        return Bin<T>(ptr);
    }

    using AnyBinary = Bin<void*>;

    AnyBinary binary;

    template <PointerToClassType B>
        requires AnyBinaryFormat<B>
    B GetBinary() {
        return reinterpret_cast<B>(binary.binFmt);
    }

    template <typename T>
        requires CastableType<T>
    T operator[](UInt64 index) const {
        return reinterpret_cast<T>((UInt8*)base + index);
    }

    const char* GetPath() const {
        return path;
    }

    template <typename T>
        requires IntegralOrPointerType<T>
    T GetBase() const {
        return reinterpret_cast<T>(base);
    }

    template <typename T>
        requires IntegralOrPointerType<T>
    T GetOriginalBase() const {
        return reinterpret_cast<T>(base);
    }

    template <typename Sym, typename Binary>
    Sym GetSymbol(char* symbolname)
        requires requires(Sym sym, Binary bin) {
            sym->GetName();
            sym->GetAddress();
            std::is_same_v<GetSymbolReturnType<Binary>, Sym>;
        }
    {
        static_assert(AnyBinaryFormat<Binary>, "Unsupported type for FuzzBinary:GetSymbol()");

        if constexpr (std::is_base_of_v<MachO, std::remove_pointer_t<Binary>>) {
            return dynamic_cast<Sym>(binary.macho->GetSymbol(symbolname));
        }

        if constexpr (std::is_same_v<Binary, MachO*>) {
            return binary.macho->GetSymbol(symbolname);
        }

        if constexpr (std::is_same_v<Binary, RawBinary*>) {
            return binary.raw->GetSymbol(symbolname);
        }

        return nullptr;
    }

    template <typename Seg, typename Binary>
    Seg GetSegment(char* segname)
        requires requires(Seg seg, Binary bin) {
            seg->GetName();
            seg->GetAddress();
            std::is_same_v<GetSegmentReturnType<Binary>, Seg> ||
                std::is_same_v<GetSectionReturnType<Binary>, Seg>;
        }
    {
        static_assert(AnyBinaryFormat<Binary>, "Unsupported type for FuzzBinary:GetSegment()");

        if constexpr (std::is_base_of_v<MachO, std::remove_pointer_t<Binary>>) {
            return dynamic_cast<Seg>(binary.macho->GetSegment(segname));
        }

        if constexpr (std::is_same_v<Binary, MachO*>) {
            return binary.macho->GetSegment(segname);
        }

        if constexpr (std::is_same_v<Binary, RawBinary*>) {
            return binary.raw->GetSection(segname);
        }

        return nullptr;
    }
};

static_assert(std::is_same_v<GetSegmentReturnType<MachO*>, Segment*>);
static_assert(std::is_same_v<GetSectionReturnType<RawBinary*>, SectionRaw*>);

static_assert(AnyBinaryFormat<decltype(FuzzBinary::binary.macho)> &&
                  // AnyBinaryFormat<decltype(FuzzBinary::binary.elf)> &&
                  // AnyBinaryFormat<decltype(FuzzBinary::binary.portableExecutable)> &&
                  // AnyBinaryFormat<decltype(FuzzBinary::binary.terseExecutable)> &&
                  AnyBinaryFormat<decltype(FuzzBinary::binary.raw)>,
              "All types in the union must satisfy the BinaryFormat concept");

template <typename T>
concept FuzzableType = ClassType<T> || FundamentalType<T> || PodType<T> || IntegralOrPointerType<T>;

class Harness {
public:
    explicit Harness(xnu::Kernel* kernel);

    explicit Harness(const char* binary);
    explicit Harness(const char* binary, const char* mapFile);

    ~Harness() = default;

    struct FuzzBinary* GetFuzzBinary() const {
        return fuzzBinary;
    }

    template <typename Sym>
    std::vector<Sym>* GetSymbols()
        requires requires(Sym sym) {
            sym->GetName();
            sym->GetAddress();
        };

    template <typename T>
        requires AnyBinaryFormat<T> && PointerToClassType<T>
    T GetBinary() {
        static_assert(AnyBinaryFormat<T>, "Unsupported type for Harness::GetBinary()");

        if constexpr (std::is_base_of_v<MachO, std::remove_pointer_t<T>>) {
            return dynamic_cast<T>(fuzzBinary->binary.macho);
        }

        if constexpr (std::is_same_v<T, MachO*>) {
            return fuzzBinary->binary.macho;
        }

        if constexpr (std::is_same_v<T, RawBinary*>) {
            return fuzzBinary->binary.raw;
        }

        return nullptr;
    }

    fuzzer::Loader* GetLoader() const {
        return loader;
    }

    char* GetMapFile() const {
        return mapFile;
    }

    template <int CpuType>
    char* GetMachOFromFatHeader(char* file_data);

    template <typename Binary, typename Seg>
        requires AnyBinaryFormat<Binary>
    bool MapSegments(char* file_data, char* mapFile);

    template <typename Binary, typename Seg>
        requires AnyBinaryFormat<Binary>
    bool UnmapSegments();

    template <typename Binary>
        requires AnyBinaryFormat<Binary>
    void GetMappingInfo(char* file_data, Size* size, xnu::mach::VmAddress* load_addr);

    void UpdateSegmentLoadCommandsForNewLoadAddress(char* file_data,
                                                    xnu::mach::VmAddress newLoadAddress,
                                                    xnu::mach::VmAddress oldLoadAddress);
    void UpdateSymbolTableForMappedMachO(char* file_data, xnu::mach::VmAddress newLoadAddress,
                                         xnu::mach::VmAddress oldLoadAddress);

    template <typename Binary = RawBinary>
        requires(AnyBinaryFormat<Binary> && !MachOFormat<Binary>)
    void LoadBinary(const char* path, const char* mapFile);

    void LoadMachO(const char* path);

    void StartKernel();

    void CallFunctionInKernel(const char* funcname);
    void CallFunctionInKernelUsingHypervisor(const char* funcname);

    void GetEntryPointFromKC(xnu::mach::VmAddress kc, xnu::mach::VmAddress* entryPoint);

    void GetKernelFromKC(xnu::mach::VmAddress kc, xnu::mach::VmAddress* loadAddress,
                         Offset* loadOffset);

    void LoadKernel(const char* path, Offset slide);
    void LoadKernelExtension(const char* path);

    bool LoadKernelCache(const char* kernelPath, xnu::mach::VmAddress* kernelCache,
                         Size* kernelCacheSize, Offset* loadOffset,
                         xnu::mach::VmAddress* loadAddress);

    void AddDebugSymbolsFromKernel(const char* debugSymbols);

    template <typename Binary = RawBinary>
        requires AnyBinaryFormat<Binary>
    void PopulateSymbolsFromMapFile(const char* mapFile);

    template <typename T>
    void Mutate(T data)
        requires FuzzableType<T>;

    template <typename Func, typename... Args, typename Binary, typename Sym>
        requires requires(Binary bin, Sym sym) {
            std::is_invocable_v<Func, Args...>;

            sym->GetName();
            sym->GetAddress();
            std::is_same_v<GetSymbolReturnType<Binary>, Sym>;
        }
    std::invoke_result_t<Func, Args...> Execute(const char* name, Func func, Args... args);

private:
    darwin::vm::Hypervisor* hypervisor;

    emulation::Emulator<emulation::Unicorn> *unicorn;
    emulation::Emulator<emulation::Panda> *panda;

    xnu::Kernel* kernel;

    xnu::KDKInfo* kdkInfo;

    struct FuzzBinary* fuzzBinary;

    fuzzer::Loader* loader;

    char* mapFile;
};
} // namespace Fuzzer
