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

#include <types.h>

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

    explicit Symbol(MachO* macho, UInt32 type, char* name, xnu::mach::VmAddress address, Offset offset,
           Segment* segment, Section* section)
        : macho(macho), type(type), name(name), demangled_name(nullptr), // getDemangledName();
          address(address), offset(offset), segment(segment), section(section) {}

    ~Symbol() = default;

    bool IsUndefined() {
        return type == N_UNDF;
    }
    bool IsExternal() {
        return type & N_EXT;
    }

    bool IsCxx() {
        return cxx_demangle(GetName()) != nullptr;
    }
    bool IsSwift() {
        return /* swift */ cxx_demangle(GetName()) != nullptr;
    }

    MachO* GetMachO() {
        return macho;
    }

    Segment* GetSegment() {
        return segment;
    }

    Section* GetSection() {
        return section;
    }

    char* GetName() {
        return name;
    }

    char* GetDemangledName() {
        char* _swift_demangle = swift_demangle(GetName());
        char* _cxx_demangle = cxx_demangle(GetName());

        if (_swift_demangle)
            return _swift_demangle;
        if (_cxx_demangle)
            return _cxx_demangle;

        char* empty = new char[1];

        *empty = '\0';

        return empty;
    }

    xnu::mach::VmAddress GetAddress() {
        return address;
    }

    Offset GetOffset() {
        return offset;
    }

    UInt32 GetType() {
        return type;
    }

private:
    MachO* macho;

    Segment* segment;
    Section* section;

    char* name;
    char* demangled_name;

    UInt32 type;

    xnu::mach::VmAddress address;

    Offset offset;
};
