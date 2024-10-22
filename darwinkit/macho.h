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
    explicit MachO(char *buffer, xnu::Macho::Header64 *header,
                   xnu::Mach::VmAddress address, Offset slide)
                       : buffer(buffer),
                         header(header),
                         base(address),
                         aslr_slide(slide),
                         symbolTable(new SymbolTable()) {}

    explicit MachO() = default;

    ~MachO() = default;

    virtual void initWithBase(xnu::Mach::VmAddress machoBase, Offset slide);

    xnu::Macho::Header64* getMachHeader() {
        return header;
    }

    virtual xnu::Mach::VmAddress getBase() {
        return base;
    }

    xnu::Mach::VmAddress getEntryPoint() {
        return entry_point;
    }

    Offset getAslrSlide() {
        return aslr_slide;
    }

    virtual Size getSize();

    UInt8* getOffset(Offset offset) {
        return reinterpret_cast<UInt8*>(buffer + offset);
    }
    UInt8* getEnd() {
        return reinterpret_cast<UInt8*>(buffer + getSize());
    }

    std::vector<Segment*>& getSegments() {
        return segments;
    }

    std::vector<Section*>& getSections(Segment* segment);

    std::vector<Symbol*>& getAllSymbols() {
        return symbolTable->getAllSymbols();
    }

    SymbolTable* getSymbolTable() {
        return symbolTable;
    }

    Symbol* getSymbol(char* symbolname) {
        return getSymbolByName(symbolname);
    }

    Symbol* getSymbolByName(char* symbolname);
    Symbol* getSymbolByAddress(xnu::Mach::VmAddress address);

    xnu::Mach::VmAddress getSymbolAddressByName(char* symbolname);

    Offset addressToOffset(xnu::Mach::VmAddress address);

    xnu::Mach::VmAddress offsetToAddress(Offset offset);

    void* addressToPointer(xnu::Mach::VmAddress address);

    xnu::Mach::VmAddress getBufferAddress(xnu::Mach::VmAddress address);

    Segment* getSegment(char* segmentname);
    Section* getSection(char* segmentname, char* sectionname);

    Segment* segmentForAddress(xnu::Mach::VmAddress address);
    Section* sectionForAddress(xnu::Mach::VmAddress address);

    Segment* segmentForOffset(Offset offset);
    Section* sectionForOffset(Offset offset);

    bool addressInSegment(xnu::Mach::VmAddress address, char* segmentname);
    bool addressInSection(xnu::Mach::VmAddress address, char* segmentname, char* sectname);

    UInt8* operator[](UInt64 index) {
        return getOffset(index);
    }

    virtual void parseSymbolTable(xnu::Macho::Nlist64* symtab, UInt32 nsyms, char* strtab,
                                  Size strsize);

    virtual void parseLinkedit();

    virtual bool parseLoadCommands();

    virtual void parseHeader();

    virtual void parseFatHeader();

    virtual void parseMachO();

protected:
    char* buffer;

    bool fat;

    xnu::Macho::Header64* header;

    std::vector<Segment*> segments;

    SymbolTable* symbolTable;

    Offset aslr_slide;

    xnu::Mach::VmAddress entry_point;

    xnu::Mach::VmAddress base;

    Size size;
};
