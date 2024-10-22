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

#include <Types.h>

#include "section.h"
#include "segment.h"

class MachO;

class Segment;
class Section;

extern "C" {
extern char* cxx_demangle(char* mangled);
extern char* swift_demangle(char* mangled);
}

class Symbol {
public:
    explicit Symbol() {}

    explicit Symbol(MachO* macho, UInt32 type, char* name, xnu::Mach::VmAddress address, Offset offset,
           Segment* segment, Section* section)
        : macho(macho), type(type), name(name), demangled_name(nullptr), // getDemangledName();
          address(address), offset(offset), segment(segment), section(section) {}

    bool isUndefined() {
        return type == N_UNDF;
    }
    bool isExternal() {
        return type & N_EXT;
    }

    bool is_cxx() {
        return cxx_demangle(getName()) != nullptr;
    }
    bool is_swift() {
        return /* swift */ cxx_demangle(getName()) != nullptr;
    }

    MachO* getMachO() {
        return macho;
    }

    Segment* getSegment() {
        return segment;
    }

    Section* getSection() {
        return section;
    }

    char* getName() {
        return name;
    }

    char* getDemangledName() {
        char* _swift_demangle = swift_demangle(getName());
        char* _cxx_demangle = cxx_demangle(getName());

        if (_swift_demangle)
            return _swift_demangle;
        if (_cxx_demangle)
            return _cxx_demangle;

        char* empty = new char[1];

        *empty = '\0';

        return empty;
    }

    xnu::Mach::VmAddress getAddress() {
        return address;
    }

    Offset getOffset() {
        return offset;
    }

    UInt32 getType() {
        return type;
    }

private:
    MachO* macho;

    Segment* segment;
    Section* section;

    char* name;
    char* demangled_name;

    UInt32 type;

    xnu::Mach::VmAddress address;

    Offset offset;
};
