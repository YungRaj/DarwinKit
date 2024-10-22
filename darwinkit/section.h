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

extern "C" {
#include <mach-o.h>

#include <mach/mach_types.h>
#include <sys/types.h>

#include <string.h>
}

#include "log.h"

class Section {
public:
    explicit Section(xnu::Macho::Section64* section)
        : section(section), address(section->addr), offset(section->offset), size(section->size) {
        name = new char[strlen(section->sectname) + 1];

        strlcpy(name, section->sectname, strlen(section->sectname) + 1);
    }

    ~Section() {
        delete name;
    }

    xnu::Macho::Section64* getSection() {
        return section;
    }

    char* getSectionName() {
        return name;
    }

    xnu::Mach::VmAddress getAddress() {
        return address;
    }

    Offset getOffset() {
        return offset;
    }
    Offset getOffsetEnd() {
        return offset + size;
    }

    Size getSize() {
        return size;
    }

    struct section_64* getSectionHeader() {
        return section;
    }

private:
    xnu::Macho::Section64* section;

    char* name;

    xnu::Mach::VmAddress address;

    Offset offset;

    Size size;
};