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
}

#include "section.h"

#include "log.h"

class Segment {
public:
    explicit Segment(xnu::Macho::Segment64* segment_command)
        : segment(segment_command), initprot(segment_command->initprot),
          maxprot(segment_command->maxprot), address(segment_command->vmaddr),
          size(segment_command->vmsize), fileoffset(segment_command->fileoff),
          filesize(segment_command->filesize) {
        name = new char[strlen(segment_command->segname) + 1];

        strlcpy(name, segment_command->segname, strlen(segment_command->segname) + 1);

        populateSections();
    }

    ~Segment() {
        delete name;

        for (int i = 0; i < sections.size(); i++) {
            Section* section = sections.at(i);

            delete section;
        }
    }

    xnu::Macho::Segment64* getSegmentCommand() {
        return segment;
    }

    xnu::Mach::VmProtection getProt() {
        return maxprot;
    }

    char* getSegmentName() {
        return name;
    }

    xnu::Mach::VmAddress getAddress() {
        return address;
    }

    Size getSize() {
        return size;
    }

    Offset getFileOffset() {
        return fileoffset;
    }

    Size getFileSize() {
        return filesize;
    }

    std::vector<Section*>& getSections() {
        return sections;
    }

    Section* getSection(char* sectname) {
        for (int i = 0; i < sections.size(); i++) {
            Section* section = sections.at(i);

            if (strcmp(section->getSectionName(), sectname) == 0 ||
                strncmp(section->getSectionName(), sectname, strlen(sectname)) == 0) {
                return section;
            }
        }

        return nullptr;
    }

    void addSection(Section* section) {
        sections.push_back(section);
    }

    void populateSections() {
        xnu::Macho::Segment64 *segment = segment;

        UInt32 nsects = segment->nsects;
        UInt32 offset = sizeof(struct segment_command_64);

        for (int32_t i = 0; i < nsects; i++) {
            xnu::Macho::Section64* sect =
                reinterpret_cast<xnu::Macho::Section64*>((UInt8*)segment + offset);

            Section* section = new Section(sect);

            addSection(section);

            offset += sizeof(struct section_64);
        }
    }

private:
    xnu::Macho::Segment64* segment;

    std::vector<Section*> sections;

    char* name;

    xnu::Mach::VmAddress address;

    Size size;

    Offset fileoffset;

    Size filesize;

    xnu::Mach::VmProtection maxprot;
    xnu::Mach::VmProtection initprot;
};