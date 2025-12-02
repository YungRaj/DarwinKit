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

#include "log.h"
#include "section.h"

class Segment {
public:
    explicit Segment(xnu::macho::Segment64* segment_command)
        : segment(segment_command), initprot(segment_command->initprot),
          maxprot(segment_command->maxprot), address(segment_command->vmaddr),
          size(segment_command->vmsize), fileoffset(segment_command->fileoff),
          filesize(segment_command->filesize) {
        name = new char[strlen(segment_command->segname) + 1];
        strlcpy(name, segment_command->segname, strlen(segment_command->segname) + 1);
        PopulateSections();
    }

    ~Segment() {
        delete name;
        for (int i = 0; i < sections.size(); i++) {
            Section* section = sections.at(i);
            delete section;
        }
    }

    xnu::macho::Segment64* GetSegmentCommand() {
        return segment;
    }

    xnu::mach::VmProtection GetProt() {
        return maxprot;
    }

    char* GetSegmentName() {
        return name;
    }

    xnu::mach::VmAddress GetAddress() {
        return address;
    }

    Size GetSize() {
        return size;
    }

    Offset GetFileOffset() {
        return fileoffset;
    }

    Size GetFileSize() {
        return filesize;
    }

    std::vector<Section*>& GetSections() {
        return sections;
    }

    Section* GetSection(char* sectname) {
        for (int i = 0; i < sections.size(); i++) {
            Section* section = sections.at(i);
            if (strcmp(section->GetSectionName(), sectname) == 0 ||
                strncmp(section->GetSectionName(), sectname, strlen(sectname)) == 0) {
                return section;
            }
        }
        return nullptr;
    }

    void AddSection(Section* section) {
        sections.push_back(section);
    }

    void PopulateSections() {
        Int32 nsects = segment->nsects;
        UInt32 offset = sizeof(struct segment_command_64);
        for (Int32 i = 0; i < nsects; i++) {
            xnu::macho::Section64* sect =
                reinterpret_cast<xnu::macho::Section64*>((UInt8*)segment + offset);
            Section* section = new Section(sect);
            AddSection(section);
            offset += sizeof(struct section_64);
        }
    }

private:
    xnu::macho::Segment64* segment;
    std::vector<Section*> sections;
    char* name;

    xnu::mach::VmAddress address;
    Size size;
    Offset fileoffset;
    Size filesize;

    xnu::mach::VmProtection maxprot;
    xnu::mach::VmProtection initprot;
};