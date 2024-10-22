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

void MachO::initWithBase(xnu::Mach::VmAddress machoBase, Offset slide) {
    base = machoBase;
    aslr_slide = slide;
    buffer = reinterpret_cast<char*>(base);
    header = reinterpret_cast<xnu::Macho::Header64*>(buffer);
    symbolTable = new SymbolTable();

    parseMachO();
}

Size MachO::getSize() {
    Size file_size = 0;

    xnu::Macho::Header64* mh = getMachHeader();

    UInt8* q = reinterpret_cast<UInt8*>(mh) + sizeof(xnu::Macho::Header64);

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

Symbol* MachO::getSymbolByName(char* symbolname) {
    return symbolTable->getSymbolByName(symbolname);
}

Symbol* MachO::getSymbolByAddress(xnu::Mach::VmAddress address) {
    return symbolTable->getSymbolByAddress(address);
}

xnu::Mach::VmAddress MachO::getSymbolAddressByName(char* symbolname) {
    Symbol* symbol = getSymbolByName(symbolname);

    if (!symbol)
        return 0;

    return symbol->getAddress();
}

Offset MachO::addressToOffset(xnu::Mach::VmAddress address) {
    xnu::Macho::Header64* mh = getMachHeader();

    UInt64 current_offset = sizeof(xnu::Macho::Header64);

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

xnu::Mach::VmAddress MachO::offsetToAddress(Offset offset) {
    xnu::Macho::Header64* mh = getMachHeader();

    UInt64 current_offset = sizeof(xnu::Macho::Header64);

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

void* MachO::addressToPointer(xnu::Mach::VmAddress address) {
    return reinterpret_cast<void*>(
        reinterpret_cast<xnu::Mach::VmAddress>(buffer + addressToOffset(address)));
}

xnu::Mach::VmAddress MachO::getBufferAddress(xnu::Mach::VmAddress address) {
    xnu::Mach::VmAddress header = reinterpret_cast<xnu::Mach::VmAddress>(getMachHeader());

    Segment* segment = segmentForAddress(address);

    Section* section = sectionForAddress(address);

    if (segment && !section) {
        return header + segment->getFileOffset() + (address - segment->getAddress());
    }

    if (!segment && !section) {
        address -= getAslrSlide();

        segment = segmentForAddress(address);
        section = sectionForAddress(address);
    }

    return segment && section ? header + section->getOffset() + (address - section->getAddress())
                              : 0;
}

Segment* MachO::getSegment(char* segmentname) {
    for (UInt32 i = 0; i < getSegments().size(); i++) {
        Segment* segment = getSegments().at(i);

        if (strcmp(segment->getSegmentName(), segmentname) == 0 ||
            strncmp(segment->getSegmentName(), segmentname, strlen(segmentname)) == 0) {
            return segment;
        }
    }

    return nullptr;
}

Section* MachO::getSection(char* segmentname, char* sectionname) {
    for (UInt32 i = 0; i < getSegments().size(); i++) {
        Segment* segment = getSegments().at(i);

        if (strcmp(segment->getSegmentName(), segmentname) == 0 ||
            strncmp(segment->getSegmentName(), segmentname, strlen(segmentname)) == 0) {
            for (UInt32 j = 0; j < segment->getSections().size(); j++) {
                Section* section = segment->getSections().at(j);

                if (strcmp(section->getSectionName(), sectionname) == 0 ||
                    strncmp(section->getSectionName(), sectionname, strlen(sectionname)) == 0) {
                    return section;
                }
            }
        }
    }

    return nullptr;
}

Segment* MachO::segmentForAddress(xnu::Mach::VmAddress address) {
    for (UInt32 i = 0; i < getSegments().size(); i++) {
        Segment* segment = getSegments().at(i);

        if (address >= segment->getAddress() &&
            address <= segment->getAddress() + segment->getSize()) {
            return segment;
        }
    }

    return nullptr;
}

Section* MachO::sectionForAddress(xnu::Mach::VmAddress address) {
    Segment* segment = segmentForAddress(address);

    if (!segment)
        return nullptr;

    for (UInt32 i = 0; i < segment->getSections().size(); i++) {
        Section* section = segment->getSections().at(i);

        if (address >= section->getAddress() &&
            address <= section->getAddress() + section->getSize()) {
            return section;
        }
    }

    return nullptr;
}

Segment* MachO::segmentForOffset(Offset offset) {
    xnu::Mach::VmAddress address = offsetToAddress(offset);

    if (!address)
        return nullptr;

    return segmentForAddress(address);
}

Section* MachO::sectionForOffset(Offset offset) {
    xnu::Mach::VmAddress address = offsetToAddress(offset);

    if (!address)
        return nullptr;

    return sectionForAddress(address);
}

bool MachO::addressInSegment(xnu::Mach::VmAddress address, char* segmentname) {
    Segment* segment = segmentForAddress(address);

    if (segment && strcmp(segment->getSegmentName(), segmentname) == 0) {
        xnu::Mach::VmAddress segmentAddress = segment->getAddress();

        Size segmentSize = segment->getSize();

        return address >= segmentAddress && address < segmentAddress + segmentSize;
    }

    return false;
}

bool MachO::addressInSection(xnu::Mach::VmAddress address, char* segmentname, char* sectname) {
    Section* section;

    if (addressInSegment(address, segmentname)) {
        section = sectionForAddress(address);

        if (section && strcmp(section->getSectionName(), sectname) == 0) {
            xnu::Mach::VmAddress sectionAddress = section->getAddress();

            Size sectionSize = section->getSize();

            return address >= sectionAddress && address < sectionAddress + sectionSize;
        }

        return false;
    }

    return false;
}

void MachO::parseSymbolTable(xnu::Macho::Nlist64* symtab, UInt32 nsyms, char* strtab,
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

        DARWIN_RK_LOG("MacRK::Symbol %s 0x%llx\n", name, address);
    }

    DARWIN_RK_LOG("MacRK::MachO::%u syms!\n", nsyms);
}

void MachO::parseLinkedit() {}

bool MachO::parseLoadCommands() {
    return true;
}

void MachO::parseFatHeader() {
    struct fat_header* fat_header = reinterpret_cast<struct fat_header*>(getMachHeader());

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
            xnu::Macho::Header64* mh = reinterpret_cast<xnu::Macho::Header64*>(
                reinterpret_cast<UInt8*>(fat_header) + offset);

            header = mh;
            buffer = reinterpret_cast<char*>(mh);

            parseHeader();
        }
    }
}

void MachO::parseHeader() {
    xnu::Macho::Header64* mh = getMachHeader();

    UInt32 magic = mh->magic;

    if (magic == FAT_CIGAM) {

    } else if (magic == MH_MAGIC_64) {
        getAslrSlide();

        size = getSize();

        parseLoadCommands();
    }
}

void MachO::parseMachO() {
    parseHeader();
}