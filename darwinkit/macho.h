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

extern "C" {
#include <mach-o.h>
}

#include <types.h>

#include "binary_format.h"

#include "section.h"
#include "segment.h"
#include "symbol.h"
#include "symbol_table.h"
#include "vector.h"

#include "log.h"

#ifdef __USER__

#define max(x, y) (x > y ? x : y)
#define min(x, y) (x > y ? y : x)

#endif

class MachO : public binary::BinaryFormat {
public:
    explicit MachO(char *buffer, xnu::macho::Header64 *header,
                   xnu::mach::VmAddress address, Offset slide)
                       : buffer(buffer),
                         header(header),
                         base(address),
                         aslr_slide(slide),
                         symbolTable(new SymbolTable()) {}

    explicit MachO() = default;

    ~MachO() = default;

    virtual void InitWithBase(xnu::mach::VmAddress machoBase, Offset slide);

    xnu::macho::Header64* GetMachHeader() {
        return header;
    }

    virtual xnu::mach::VmAddress GetBase() {
        return base;
    }

    xnu::mach::VmAddress GetEntryPoint() {
        return entry_point;
    }

    Offset GetAslrSlide() {
        return aslr_slide;
    }

    virtual Size GetSize();

    UInt8* GetOffset(Offset offset) {
        return reinterpret_cast<UInt8*>(buffer + offset);
    }
    UInt8* GetEnd() {
        return reinterpret_cast<UInt8*>(buffer + GetSize());
    }

    std::vector<Segment*>& GetSegments() {
        return segments;
    }

    std::vector<Section*>& GetSections(Segment* segment);

    std::vector<Symbol*>& GetAllSymbols() {
        return symbolTable->GetAllSymbols();
    }

    SymbolTable* GetSymbolTable() {
        return symbolTable;
    }

    Symbol* GetSymbol(char* symbolname) {
        return GetSymbolByName(symbolname);
    }

    Symbol* GetSymbolByName(char* symbolname);
    Symbol* GetSymbolByAddress(xnu::mach::VmAddress address);

    xnu::mach::VmAddress GetSymbolAddressByName(char* symbolname);

    Offset AddressToOffset(xnu::mach::VmAddress address);

    xnu::mach::VmAddress OffsetToAddress(Offset offset);

    void* AddressToPointer(xnu::mach::VmAddress address);

    xnu::mach::VmAddress GetBufferAddress(xnu::mach::VmAddress address);

    Segment* GetSegment(char* segmentname);
    Section* GetSection(char* segmentname, char* sectionname);

    Segment* SegmentForAddress(xnu::mach::VmAddress address);
    Section* SectionForAddress(xnu::mach::VmAddress address);

    Segment* SegmentForOffset(Offset offset);
    Section* SectionForOffset(Offset offset);

    bool AddressInSegment(xnu::mach::VmAddress address, char* segmentname);
    bool AddressInSection(xnu::mach::VmAddress address, char* segmentname, char* sectname);

    UInt8* operator[](UInt64 index) {
        return GetOffset(index);
    }

    virtual void ParseSymbolTable(xnu::macho::Nlist64* symtab, UInt32 nsyms, char* strtab,
                                  Size strsize);

    virtual void ParseLinkedit();

    virtual bool ParseLoadCommands();

    virtual void ParseHeader();

    virtual void ParseFatHeader();

    virtual void ParseMachO();

protected:
    char* buffer;
    bool fat;

    xnu::macho::Header64* header;
    std::vector<Segment*> segments;
    SymbolTable* symbolTable;

    Offset aslr_slide;
    xnu::mach::VmAddress entry_point;
    xnu::mach::VmAddress base;
    Size size;
};
