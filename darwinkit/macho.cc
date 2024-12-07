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

#include "log.h"
#include "macho.h"

void MachO::InitWithBase(xnu::mach::VmAddress machoBase, Offset slide) {
    base = machoBase;
    aslr_slide = slide;
    buffer = reinterpret_cast<char*>(base);
    header = reinterpret_cast<xnu::macho::Header64*>(buffer);
    symbolTable = new SymbolTable();

    ParseMachO();
}

Size MachO::GetSize() {
    Size file_size = 0;

    xnu::macho::Header64* mh = GetMachHeader();

    UInt8* q = reinterpret_cast<UInt8*>(mh) + sizeof(xnu::macho::Header64);

    for (UInt32 i = 0; i < mh->ncmds; i++) {
        struct load_command* load_command = reinterpret_cast<struct load_command*>(q);

        UInt32 cmd = load_command->cmd;
        UInt32 cmdsize = load_command->cmdsize;

        if (cmd == LC_SEGMENT_64) {
            struct segment_command_64* segment_command =
                reinterpret_cast<struct segment_command_64*>(load_command);

            UInt64 vmaddr = segment_command->vmaddr;
            UInt64 vmsize = segment_command->vmsize;

            UInt64 fileoff = segment_command->fileoff;
            UInt64 filesize = segment_command->filesize;

            if (vmsize > 0) {
                file_size = max(file_size, fileoff + filesize);
            }
        }

        q += cmdsize;
    }

    return file_size;
}

Symbol* MachO::GetSymbolByName(char* symbolname) {
    return symbolTable->GetSymbolByName(symbolname);
}

Symbol* MachO::GetSymbolByAddress(xnu::mach::VmAddress address) {
    return symbolTable->GetSymbolByAddress(address);
}

xnu::mach::VmAddress MachO::GetSymbolAddressByName(char* symbolname) {
    Symbol* symbol = GetSymbolByName(symbolname);

    if (!symbol)
        return 0;

    return symbol->GetAddress();
}

Offset MachO::AddressToOffset(xnu::mach::VmAddress address) {
    xnu::macho::Header64* mh = GetMachHeader();

    UInt64 current_offset = sizeof(xnu::macho::Header64);

    for (UInt32 i = 0; i < mh->ncmds; i++) {
        struct load_command* load_command =
            reinterpret_cast<struct load_command*>((*this)[current_offset]);

        UInt32 cmdtype = load_command->cmd;
        UInt32 cmdsize = load_command->cmdsize;

        if (cmdtype == LC_SEGMENT_64) {
            struct segment_command_64* segment_command =
                reinterpret_cast<struct segment_command_64*>(load_command);

            UInt64 vmaddr = segment_command->vmaddr;
            UInt64 vmsize = segment_command->vmsize;

            UInt64 fileoff = segment_command->fileoff;
            UInt64 filesize = segment_command->filesize;

            UInt64 sect_offset = current_offset + sizeof(struct segment_command_64);

            for (int j = 0; j < segment_command->nsects; j++) {
                struct section_64* section =
                    reinterpret_cast<struct section_64*>((*this)[sect_offset]);

                UInt64 sectaddr = section->addr;
                UInt64 sectsize = section->size;

                UInt64 offset = section->offset;

                if (address >= sectaddr && address <= sectaddr + sectsize) {
                    return offset == 0 ? 0 : offset + (address - sectaddr);
                }

                sect_offset += sizeof(struct section_64);
            }
        }

        current_offset += cmdsize;
    }

    return 0;
}

xnu::mach::VmAddress MachO::OffsetToAddress(Offset offset) {
    xnu::macho::Header64* mh = GetMachHeader();

    UInt64 current_offset = sizeof(xnu::macho::Header64);

    for (UInt32 i = 0; i < mh->ncmds; i++) {
        struct load_command* load_command =
            reinterpret_cast<struct load_command*>((*this)[current_offset]);

        UInt32 cmdtype = load_command->cmd;
        UInt32 cmdsize = load_command->cmdsize;

        if (cmdtype == LC_SEGMENT_64) {
            struct segment_command_64* segment_command =
                reinterpret_cast<struct segment_command_64*>(load_command);

            UInt64 vmaddr = segment_command->vmaddr;
            UInt64 vmsize = segment_command->vmsize;

            UInt64 fileoff = segment_command->fileoff;
            UInt64 filesize = segment_command->filesize;

            if (offset >= fileoff && offset <= fileoff + filesize) {
                return vmaddr + (offset - fileoff);
            }
        }

        current_offset += cmdsize;
    }

    return 0;
}

void* MachO::AddressToPointer(xnu::mach::VmAddress address) {
    return reinterpret_cast<void*>(
        reinterpret_cast<xnu::mach::VmAddress>(buffer + AddressToOffset(address)));
}

xnu::mach::VmAddress MachO::GetBufferAddress(xnu::mach::VmAddress address) {
    xnu::mach::VmAddress header = reinterpret_cast<xnu::mach::VmAddress>(GetMachHeader());

    Segment* segment = SegmentForAddress(address);

    Section* section = SectionForAddress(address);

    if (segment && !section) {
        return header + segment->GetFileOffset() + (address - segment->GetAddress());
    }

    if (!segment && !section) {
        address -= GetAslrSlide();

        segment = SegmentForAddress(address);
        section = SectionForAddress(address);
    }

    return segment && section ? header + section->GetOffset() + (address - section->GetAddress())
                              : 0;
}

Segment* MachO::GetSegment(char* segmentname) {
    for (UInt32 i = 0; i < GetSegments().size(); i++) {
        Segment* segment = GetSegments().at(i);

        if (strcmp(segment->GetSegmentName(), segmentname) == 0 ||
            strncmp(segment->GetSegmentName(), segmentname, strlen(segmentname)) == 0) {
            return segment;
        }
    }

    return nullptr;
}

Section* MachO::GetSection(char* segmentname, char* sectionname) {
    for (UInt32 i = 0; i < GetSegments().size(); i++) {
        Segment* segment = GetSegments().at(i);

        if (strcmp(segment->GetSegmentName(), segmentname) == 0 ||
            strncmp(segment->GetSegmentName(), segmentname, strlen(segmentname)) == 0) {
            for (UInt32 j = 0; j < segment->GetSections().size(); j++) {
                Section* section = segment->GetSections().at(j);

                if (strcmp(section->GetSectionName(), sectionname) == 0 ||
                    strncmp(section->GetSectionName(), sectionname, strlen(sectionname)) == 0) {
                    return section;
                }
            }
        }
    }

    return nullptr;
}

Segment* MachO::SegmentForAddress(xnu::mach::VmAddress address) {
    for (UInt32 i = 0; i < GetSegments().size(); i++) {
        Segment* segment = GetSegments().at(i);

        if (address >= segment->GetAddress() &&
            address <= segment->GetAddress() + segment->GetSize()) {
            return segment;
        }
    }

    return nullptr;
}

Section* MachO::SectionForAddress(xnu::mach::VmAddress address) {
    Segment* segment = SegmentForAddress(address);

    if (!segment)
        return nullptr;

    for (UInt32 i = 0; i < segment->GetSections().size(); i++) {
        Section* section = segment->GetSections().at(i);

        if (address >= section->GetAddress() &&
            address <= section->GetAddress() + section->GetSize()) {
            return section;
        }
    }

    return nullptr;
}

Segment* MachO::SegmentForOffset(Offset offset) {
    xnu::mach::VmAddress address = OffsetToAddress(offset);

    if (!address)
        return nullptr;

    return SegmentForAddress(address);
}

Section* MachO::SectionForOffset(Offset offset) {
    xnu::mach::VmAddress address = OffsetToAddress(offset);

    if (!address)
        return nullptr;

    return SectionForAddress(address);
}

bool MachO::AddressInSegment(xnu::mach::VmAddress address, char* segmentname) {
    Segment* segment = SegmentForAddress(address);

    if (segment && strcmp(segment->GetSegmentName(), segmentname) == 0) {
        xnu::mach::VmAddress segmentAddress = segment->GetAddress();

        Size segmentSize = segment->GetSize();

        return address >= segmentAddress && address < segmentAddress + segmentSize;
    }

    return false;
}

bool MachO::AddressInSection(xnu::mach::VmAddress address, char* segmentname, char* sectname) {
    Section* section;

    if (AddressInSegment(address, segmentname)) {
        section = SectionForAddress(address);

        if (section && strcmp(section->GetSectionName(), sectname) == 0) {
            xnu::mach::VmAddress sectionAddress = section->GetAddress();

            Size sectionSize = section->GetSize();

            return address >= sectionAddress && address < sectionAddress + sectionSize;
        }

        return false;
    }

    return false;
}

void MachO::ParseSymbolTable(xnu::macho::Nlist64* symtab, UInt32 nsyms, char* strtab,
                             Size strsize) {
    for (int i = 0; i < nsyms; i++) {
        Symbol* symbol;

        xnu::macho::Nlist64* nl = &symtab[i];

        char* name;

        xnu::mach::VmAddress address;

        name = &strtab[nl->n_strx];

        address = nl->n_value;

        symbol =
            new Symbol(this, nl->n_type & N_TYPE, name, address, AddressToOffset(address),
                       SegmentForAddress(address), SectionForAddress(address));

        symbolTable->AddSymbol(symbol);

        DARWIN_KIT_LOG("MacRK::Symbol %s 0x%llx\n", name, address);
    }

    DARWIN_KIT_LOG("MacRK::MachO::%u syms!\n", nsyms);
}

void MachO::ParseLinkedit() {}

bool MachO::ParseLoadCommands() {
    return true;
}

void MachO::ParseFatHeader() {
    struct fat_header* fat_header = reinterpret_cast<struct fat_header*>(GetMachHeader());

    struct fat_arch* arch = reinterpret_cast<struct fat_arch*>(
        reinterpret_cast<UInt8*>(fat_header) + sizeof(struct fat_header));

    UInt32 nfat_arch = OSSwapBigToHostInt32(fat_header->nfat_arch);

    for (UInt32 i = 0; i < nfat_arch; i++) {
        UInt32 cputype;
        UInt32 cpusubtype;

        UInt32 offset;

        cputype = OSSwapBigToHostInt32(arch->cputype);
        cpusubtype = OSSwapBigToHostInt32(arch->cpusubtype);

        offset = OSSwapBigToHostInt32(arch->offset);

#ifdef __x86_64__
#define NATIVE_CPU_TYPE CPU_TYPE_X86_64
#endif

#ifdef __arm64__
#define NATIVE_CPU_TYPE CPU_TYPE_ARM64
#endif

        if (cputype == NATIVE_CPU_TYPE) {
            xnu::macho::Header64* mh = reinterpret_cast<xnu::macho::Header64*>(
                reinterpret_cast<UInt8*>(fat_header) + offset);

            header = mh;
            buffer = reinterpret_cast<char*>(mh);

            ParseHeader();
        }
    }
}

void MachO::ParseHeader() {
    xnu::macho::Header64* mh = GetMachHeader();

    UInt32 magic = mh->magic;

    if (magic == FAT_CIGAM) {

    } else if (magic == MH_MAGIC_64) {
        GetAslrSlide();

        size = GetSize();

        ParseLoadCommands();
    }
}

void MachO::ParseMachO() {
    ParseHeader();
}