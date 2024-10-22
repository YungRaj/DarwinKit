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

#include "kext_macho.h"

#include "kernel.h"

namespace xnu {

KextMachO::KextMachO(Kernel* kernel, char* name, xnu::Mach::VmAddress base)
    : kernel(kernel), name(name), base_offset(0), kernel_cache(
#ifdef __arm64__
                                                      Kernel::findKernelCache()
#else
                                                      0
#endif
                                                          ),
      kernel_collection(
#ifdef __x86_64__
          Kernel::findKernelCollection()
#else
          0
#endif
      ) {
    size = 0;

    initWithBase(base, 0);

    kmod_info = reinterpret_cast<xnu::KmodInfo*>(getSymbolAddressByName("_kmod_info"));
}

KextMachO::KextMachO(Kernel* kernel, char* name, xnu::KmodInfo* kmod_info)
    : kernel(kernel), name(&kmod_info->name[0]), kmod_info(kmod_info), base_offset(0),
      kernel_cache(
#ifdef __arm64__
          Kernel::findKernelCache()
#else
          0
#endif
              ),
      kernel_collection(
#ifdef __x86_64__
          Kernel::findKernelCollection()
#else
          0
#endif
      ) {

    initWithBase(kmod_info->address, 0);
}

void KextMachO::parseLinkedit() {}

void KextMachO::parseSymbolTable(xnu::Macho::Nlist64* symtab, UInt32 nsyms, char* strtab,
                                 Size strsize) {

    for (int i = 0; i < nsyms; i++) {
        Symbol* symbol;

        xnu::Macho::Nlist64* nl = &symtab[i];

        char* name;

        xnu::Mach::VmAddress address;

        name = &strtab[nl->n_strx];

        address = nl->n_value;

        symbol =
            new Symbol(this, nl->n_type & N_TYPE, name, address, addressToOffset(address),
                       segmentForAddress(address), sectionForAddress(address));

        symbolTable->addSymbol(symbol);

        char buffer[128];

        snprintf(buffer, 128, "0x%llx", address);

        // DARWIN_RK_LOG("MacRK::Symbol %s %s\n", name, buffer);
    }

    // DARWIN_RK_LOG("MacRK::MachO::%u syms!\n", nsyms);
}

bool KextMachO::parseLoadCommands() {
    struct mach_header_64* mh = getMachHeader();

    char buffer[128];

    snprintf(buffer, 128, "0x%llx", (UInt64)(*this)[sizeof(struct mach_header_64)]);

    DARWIN_RK_LOG("MacRK::KextMachO::parseLoadCommands() mh + struct mach_header_64 = %s\n", buffer);

#ifdef __arm64__
    size = MachO::getSize();
#endif

    UInt8* q = reinterpret_cast<UInt8*>(mh) + sizeof(struct mach_header_64);

    UInt32 current_offset = sizeof(struct mach_header_64);

    DARWIN_RK_LOG("MacRK::KextMachO::mach_header->ncmds = %u\n", mh->ncmds);

    for (UInt32 i = 0; i < mh->ncmds; i++) {
        struct load_command* load_command =
            reinterpret_cast<struct load_command*>((*this)[current_offset]);

        UInt32 cmdtype = load_command->cmd;
        UInt32 cmdsize = load_command->cmdsize;

        if (cmdsize > mh->sizeofcmds - ((uintptr_t)load_command - (uintptr_t)(mh + 1)))
            return false;

        switch (cmdtype) {
        case LC_SEGMENT_64: {
            ;
            struct segment_command_64* segment_command =
                reinterpret_cast<struct segment_command_64*>(load_command);

            UInt32 nsects = segment_command->nsects;
            UInt32 sect_offset = current_offset + sizeof(struct segment_command_64);

            if (segment_command->vmaddr == getBase()) {
                base_offset = segment_command->fileoff;
            }

            char buffer1[128];
            char buffer2[128];

            snprintf(buffer1, 128, "0x%08llx", segment_command->vmaddr);
            snprintf(buffer2, 128, "0x%08llx", segment_command->vmaddr + segment_command->vmsize);

            // DARWIN_RK_LOG("MacRK::LC_SEGMENT_64 at 0x%llx - %s %s to %s \n",
            // segment_command->fileoff,
            //           segment_command->segname, buffer1, buffer2);

            if (!strcmp(segment_command->segname, "__LINKEDIT")) {
                linkedit = reinterpret_cast<UInt8*>(segment_command->vmaddr);
                linkedit_off = segment_command->fileoff;
                linkedit_size = segment_command->filesize;
            }

            int j = 0;

            if (nsects * sizeof(struct section_64) + sizeof(struct segment_command_64) > cmdsize)
                return false;

            Segment* segment = new Segment(segment_command);

            for (j = 0; j < nsects; j++) {
                struct section_64* section =
                    reinterpret_cast<struct section_64*>((*this)[sect_offset]);

                char buffer1[128];
                char buffer2[128];

                snprintf(buffer1, 128, "0x%08llx", section->addr);
                snprintf(buffer2, 128, "0x%08llx", section->addr + section->size);

                // DARWIN_RK_LOG("MacRK::\tSection %d: %s to %s - %s\n", j, buffer1, buffer2,
                //           section->sectname);

                sect_offset += sizeof(struct section_64);
            }

            segments.push_back(segment);

            break;
        }

        case LC_SYMTAB: {
            ;
            struct symtab_command* symtab_command =
                reinterpret_cast<struct symtab_command*>(load_command);

            xnu::Macho::Nlist64* symtab;
            UInt32 nsyms;

            char* strtab;
            UInt32 strsize;

            // DARWIN_RK_LOG("MacRK::LC_SYMTAB\n");
            // DARWIN_RK_LOG("MacRK::\tSymbol Table is at offset 0x%x (%u) with %u entries \n",
            //           symtab_command->symoff, symtab_command->symoff, symtab_command->nsyms);
            // DARWIN_RK_LOG("MacRK::\tString Table is at offset 0x%x (%u) with size of %u bytes\n",
            //          symtab_command->stroff, symtab_command->stroff, symtab_command->strsize);

            if (kernel_cache) {
                symtab = reinterpret_cast<xnu::Macho::Nlist64*>(kernel_cache +
                                                                symtab_command->symoff);
                nsyms = symtab_command->nsyms;

                strtab = reinterpret_cast<char*>(kernel_cache + symtab_command->stroff);
                strsize = symtab_command->strsize;

                char buffer1[128];
                char buffer2[128];

                snprintf(buffer1, 128, "0x%llx", (UInt64)symtab);
                snprintf(buffer2, 128, "0x%llx", (UInt64)strtab);

                // DARWIN_RK_LOG("MacRK::\tSymbol Table address = %s\n", buffer1);
                // DARWIN_RK_LOG("MacRK::\tString Table address = %s\n", buffer2);

            } else if (kernel_collection) {
                symtab = reinterpret_cast<xnu::Macho::Nlist64*>(
                    getBase() + (symtab_command->symoff - base_offset));
                nsyms = symtab_command->nsyms;

                strtab = reinterpret_cast<char*>(getBase() +
                                                 (symtab_command->stroff - base_offset));
                strsize = symtab_command->strsize;
            } else {
                symtab = nullptr;
                nsyms = 0;

                strtab = nullptr;
                strsize = 0;
            }

            if (nsyms > 0)
                parseSymbolTable(symtab, nsyms, strtab, strsize);

            break;
        }
        case LC_DYSYMTAB: {
            ;
            struct dysymtab_command* dysymtab_command =
                reinterpret_cast<struct dysymtab_command*>(load_command);

            /* DARWIN_RK_LOG("MacRK::LC_DYSYMTAB\n");
            DARWIN_RK_LOG("MacRK::\t%u local symbols at index %u\n", dysymtab_command->ilocalsym,
                       dysymtab_command->nlocalsym);
            DARWIN_RK_LOG("MacRK::\t%u external symbols at index %u\n", dysymtab_command->nextdefsym,
                       dysymtab_command->iextdefsym);
            DARWIN_RK_LOG("MacRK::\t%u undefined symbols at index %u\n", dysymtab_command->nundefsym,
                       dysymtab_command->iundefsym);
            DARWIN_RK_LOG("MacRK::\t%u Indirect symbols at offset 0x%x\n",
                       dysymtab_command->nindirectsyms, dysymtab_command->indirectsymoff); */

            break;
        }

        case LC_UUID: {
            ;
            struct uuid_command* uuid_command =
                reinterpret_cast<struct uuid_command*>(load_command);

            if (uuid_command->cmdsize != sizeof(struct uuid_command))
                return false;

            // DARWIN_RK_LOG("MacRK::LC_UUID\n");
            // DARWIN_RK_LOG("MacRK::\tuuid = ");

            for (int j = 0; j < sizeof(uuid_command->uuid); j++)
                // DARWIN_RK_LOG("%x", uuid_command->uuid[j]);

                // DARWIN_RK_LOG("\n");

                break;
        }

        case LC_DATA_IN_CODE: {
            ;
            struct linkedit_data_command* linkedit =
                reinterpret_cast<struct linkedit_data_command*>(load_command);

            UInt32 dataoff = linkedit->dataoff;
            UInt32 datasize = linkedit->datasize;

            // DARWIN_RK_LOG("MacRK::LC_DATA_IN_CODE\n");
            // DARWIN_RK_LOG("MacRK::\tOffset = 0x%x Size = 0x%x\n", dataoff, datasize);

            break;
        }
        }

        current_offset += cmdsize;
    }

    return true;
}

void KextMachO::parseHeader() {
    struct mach_header_64* mh = reinterpret_cast<struct mach_header_64*>(getMachHeader());

    UInt32 magic = mh->magic;

    if (magic == FAT_CIGAM) {

    } else if (magic == MH_MAGIC_64) {
#ifdef __x86_64__
        size = kmod_info->size;
#endif

        parseLoadCommands();
    }
}

void KextMachO::parseMachO() {
    parseHeader();
}

} // namespace xnu