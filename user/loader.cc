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

#include "arch.h"
#include "kernel_macho.h"
#include "kext_macho.h"
#include "loader.h"
#include "log.h"

#include <sys/mman.h>

using namespace Fuzzer;

void Module::load() {}

/*
template<typename Sym>
Sym Module::getSymbol(const char *symname) requires requires(Sym sym) {
    sym.getName();
    sym.getAddress();
}
{

}
*/

template <typename Seg>
void mapSegment(Seg segment)
    requires requires(Seg seg) { seg->getAddress(); }
{}

Loader::Loader(Fuzzer::Harness* harness, struct FuzzBinary* binary)
    : arch(arch::initArchitecture()), harness(harness), binary(binary) {}

template <typename Binary>
    requires AnyBinaryFormat<Binary>
void Loader::loadModule(Module* module) {
    if constexpr (MachOFormat<Binary>) {
        std::vector<Symbol*>& symbols = module->getSymbols<Binary, GetSymbolReturnType<Binary>>();
        std::vector<Symbol*>* externalSymbols =
            module->getExternalSymbols<Binary, GetSymbolReturnType<Binary>>();
        std::vector<Symbol*>* undefinedSymbols =
            module->getUndefinedSymbols<Binary, GetSymbolReturnType<Binary>>();

        for (int i = 0; i < externalSymbols->size(); i++) {
            Symbol* symbol = externalSymbols->at(i);
        }

        for (int i = 0; i < undefinedSymbols->size(); i++) {
            Symbol* symbol = undefinedSymbols->at(i);
        }
    }
}

void Loader::loadModuleFromKext(const char* kextPath) {
    Fuzzer::Module* module;

    struct FuzzBinary* fuzzBinary = new FuzzBinary;

    xnu::Mach::VmAddress loadAddress = 0;
    xnu::Mach::VmAddress oldLoadAddress = 0;

    char* file_data = nullptr;

    Size file_size = 0;

    loadKextMachO(kextPath, &loadAddress, &file_size, &oldLoadAddress);

    fuzzBinary->path = kextPath;
    fuzzBinary->base = reinterpret_cast<void*>(loadAddress);
    fuzzBinary->originalBase = reinterpret_cast<void*>(oldLoadAddress);
    fuzzBinary->size = file_size;
    fuzzBinary->binary = FuzzBinary::MakeBinary<xnu::KextMachO*>(new xnu::KextMachO(loadAddress));

    module = new Module(this, kextPath, fuzzBinary);

    modules.push_back(module);

    loadModule<xnu::KextMachO*>(module);
}

void Loader::loadKextMachO(const char* kextPath, xnu::Mach::VmAddress* loadAddress, Size* loadSize,
                           xnu::Mach::VmAddress* oldLoadAddress) {
    bool success;

    char* file_data;

    int fd = open(kextPath, O_RDONLY);

    if (fd == -1) {
        printf("Error opening kext Mach-O %s", kextPath);

        *loadAddress = 0;
        *loadSize = 0;
        *oldLoadAddress = 0;

        return;
    }

    Offset file_size = lseek(fd, 0, SEEK_END);

    lseek(fd, 0, SEEK_SET);

    file_data = (char*)malloc(file_size);

    Size bytes_read;

    bytes_read = read(fd, file_data, file_size);

    if (bytes_read != file_size) {
        printf("Read file failed!\n");

        close(fd);

        *loadAddress = 0;
        *loadSize = 0;
        *oldLoadAddress = 0;

        return;
    }

    if (reinterpret_cast<struct mach_header_64*>(file_data)->magic == FAT_CIGAM) {
#ifdef __arm64__
//    file_data = harness->getMachOFromFatHeader<CPU_TYPE_ARM64>(file_data);
#elif __x86_64__
//     file_data = this-->harness->getMachOFromFatHeader<CPU_TYPE_X86_64>(file_data);
#endif
    }

    *oldLoadAddress = UINT64_MAX;

    // harness->getMappingInfo<MachO>(file_data, loadSize, oldLoadAddress);

    if (*oldLoadAddress == UINT64_MAX) {
        printf("oldLoadAddress == UINT64_MAX");

        close(fd);

        *loadAddress = 0;
        *loadSize = 0;
        *oldLoadAddress = 0;

        return;
    }

    void* baseAddress = allocateModuleMemory(*loadSize, PROT_READ | PROT_WRITE);

    if (baseAddress == MAP_FAILED) {
        printf("mmap() failed!\n");

        close(fd);

        *loadAddress = 0;
        *loadSize = 0;
        *oldLoadAddress = 0;

        return;
    }

    harness->updateSymbolTableForMappedMachO(file_data, (xnu::Mach::VmAddress)baseAddress,
                                                   *oldLoadAddress);

    harness->updateSegmentLoadCommandsForNewLoadAddress(
        file_data, (xnu::Mach::VmAddress)baseAddress, *oldLoadAddress);

    // success = harness->mapSegments<MachO, Segment>(file_data, nullptr);

    if (!success) {
        printf("Map Segments failed!\n");

        goto fail;
    }

    *loadAddress = (xnu::Mach::VmAddress)baseAddress;

    // writeToFile((char*) baseAddress, *loadSize);

    free(file_data);

    close(fd);

    return;

fail:
    close(fd);

    *loadAddress = 0;
    *loadSize = 0;
    *oldLoadAddress = 0;

    printf("Load Kext MachO failed!\n");
}

template <typename Sym, typename Binary>
    requires AnyBinaryFormat<Binary>
void Loader::linkSymbols(Module* module)
    requires requires(Sym sym) {
        sym->getName();
        sym->getAddress();
        std::is_same_v<GetSymbolReturnType<Binary>, Sym>;
    }
{}

template <typename Sym, typename Binary>
    requires AnyBinaryFormat<Binary>
void Loader::linkSymbol(Module* module, Sym sym)
    requires requires(Sym sym) {
        sym->getName();
        sym->getAddress();
        std::is_same_v<GetSymbolReturnType<Binary>, Sym>;
    }
{}

template <typename Sym, typename Binary>
    requires AnyBinaryFormat<Binary>
void Loader::stubFunction(Module* module, Sym sym, xnu::Mach::VmAddress stub)
    requires requires(Sym sym) {
        sym->getName();
        sym->getAddress();
        std::is_same_v<GetSymbolReturnType<Binary>, Sym>;
    }
{}

template <typename Sym, typename Binary>
    requires AnyBinaryFormat<Binary>
void Loader::shimFunction(Module* module, Sym sym, xnu::Mach::VmAddress stub)
    requires requires(Sym sym) {
        sym->getName();
        sym->getAddress();
        std::is_same_v<GetSymbolReturnType<Binary>, Sym>;
    }
{}

void* Loader::allocateModuleMemory(Size sz, int prot) {
    void* baseAddress = mmap(nullptr, sz, prot, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

    return baseAddress;
}