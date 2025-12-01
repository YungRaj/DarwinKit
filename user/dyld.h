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
#include <mach/mach_types.h>
#include <sys/types.h>
#include <dyld_cache_format.h>
}

#include <vector>
#include <types.h>

class MachO;
class Segment;
class Section;

namespace xnu {
class Task;
class Kernel;
}; // namespace xnu

#define MH_DYLIB_IN_CACHE 0x80000000

namespace darwin {
namespace dyld {
class Library;

namespace shared_cache {
using Header = struct dyld_cache_header;
using MappingInfo = struct dyld_cache_mapping_info;
using AllImageInfos = struct dyld_all_image_infos;
using ImageInfo = struct dyld_image_info;
}; // namespace shared_cache

class Dyld {
public:
    explicit Dyld(xnu::Kernel* kernel, xnu::Task* task)
                : kernel(kernel), task(task) {
        IterateAllImages();
    }

    ~Dyld() = default;

    char* GetMainImagePath() {
        return main_image_path;
    }

    xnu::Task* GetTask() {
        return task;
    }

    xnu::mach::VmAddress GetMainImageLoadBase() {
        return main_image_load_base;
    }
    xnu::mach::VmAddress GetAllImageInfoAddr() {
        return all_image_info_addr;
    }

    xnu::mach::VmAddress GetDyld() {
        return dyld;
    }
    xnu::mach::VmAddress GetDyldSharedCache() {
        return dyld_shared_cache;
    }

    dyld::shared_cache::ImageInfo* GetMainImageInfo() {
        return main_image_info;
    }

    Offset GetSlide() {
        return slide;
    }

    char* Contains(char* str, const char* substr);

    int EndsWith(const char* str, const char* suffix);

    void GetImageInfos();

    void IterateAllImages();

    dyld::shared_cache::Header* CacheGetHeader();

    dyld::shared_cache::MappingInfo* CacheGetMappings(dyld::shared_cache::Header* cache_header);
    dyld::shared_cache::MappingInfo* CacheGetMapping(dyld::shared_cache::Header* cache_header,
                                                     xnu::mach::VmProtection prot);

    void CacheOffsetToAddress(UInt64 dyld_cache_offset, xnu::mach::VmAddress* address,
                              Offset* slide);

    void CacheGetSymtabStrtab(struct symtab_command* symtab_command, xnu::mach::VmAddress* symtab,
                              xnu::mach::VmAddress* strtab, Offset* off);

    xnu::mach::VmAddress GetImageLoadedAt(char* image_name, char** image_path);
    xnu::mach::VmAddress GetImageSlide(xnu::mach::VmAddress address);

    Size GetAdjustedLinkeditSize(xnu::mach::VmAddress address);
    Size GetAdjustedStrtabSize(struct symtab_command* symtab_command, xnu::mach::VmAddress linkedit,
                               Offset linkedit_fileoff);

    void RebuildSymtabStrtab(struct symtab_command* symtab_command, xnu::mach::VmAddress symtab_,
                             xnu::mach::VmAddress strtab_, xnu::mach::VmAddress linkedit,
                             Offset linkedit_fileoff);

    void FixupObjectiveC(MachO* macho);
    void FixupDyldRebaseBindOpcodes(MachO* macho, Segment* linkedit);

    Size GetImageSize(xnu::mach::VmAddress address);

    MachO* CacheDumpImage(char* image);
    MachO* CacheDumpImageToFile(char* image, char* path);

private:
    char* main_image_path;
    xnu::Kernel* kernel;
    xnu::Task* task;
    std::vector<Library*> libraries;

    xnu::mach::VmAddress main_image_load_base;
    xnu::mach::VmAddress dyld;
    xnu::mach::VmAddress dyld_shared_cache;

    Offset slide;
    xnu::mach::VmAddress all_image_info_addr;
    Size all_image_info_size;

    dyld::shared_cache::AllImageInfos* all_image_infos;
    dyld::shared_cache::ImageInfo* main_image_info;
};

} // namespace dyld
} // namespace darwin
