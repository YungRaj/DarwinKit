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

#include "dyld.h"
#include "kernel.h"
#include "library.h"
#include "macho.h"
#include "offsets.h"
#include "task.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mach/mach.h>

namespace darwin {
namespace dyld {

char* Dyld::Contains(char* str, const char* substr) {
    return strstr(str, substr);
}

int Dyld::EndsWith(const char* str, const char* suffix) {
    if (!str || !suffix)
        return 0;

    Size lenstr = strlen(str);
    Size lensuffix = strlen(suffix);

    if (lensuffix > lenstr)
        return 0;
    return strncmp(str + lenstr - lensuffix, suffix, lensuffix) == 0;
}

void Dyld::IterateAllImages() {
    bool found_main_image = false;
    struct mach_header_64 hdr;
    struct dyld_all_image_infos all_images;
    GetImageInfos();
    assert(all_image_info_addr && all_image_info_size);
    task->Read(all_image_info_addr, &all_images, sizeof(struct dyld_all_image_infos));
    all_image_infos =
        reinterpret_cast<struct dyld_all_image_infos*>(malloc(sizeof(struct dyld_all_image_infos)));
    memcpy(all_image_infos, &all_images, sizeof(struct dyld_all_image_infos));
    char* task_name = task->GetName();
    for (UInt32 i = 0; i < all_image_infos->infoArrayCount; i++) {
        struct dyld_image_info* image_info =
            (struct dyld_image_info*)malloc(sizeof(struct dyld_image_info));
        xnu::mach::VmAddress image_info_addr;
        xnu::mach::VmAddress image_load_addr;
        xnu::mach::VmAddress image_file_path;
        char* image_file;

        image_info_addr = (xnu::mach::VmAddress)(all_images.infoArray + i);
        task->Read(image_info_addr, image_info, sizeof(*image_info));
        image_load_addr = (xnu::mach::VmAddress)image_info->imageLoadAddress;
        image_file_path = (xnu::mach::VmAddress)image_info->imageFilePath;
        image_file = task->ReadString(image_file_path);
        Library* library = new Library(GetTask(), this, image_info);
        if (!found_main_image &&
            (EndsWith(image_file, task_name) || (i == 0 && Contains(image_file, task_name)))) {
            task->Read(image_load_addr, &hdr, sizeof(hdr));
            if (hdr.magic == MH_MAGIC_64) {
                main_image_path = image_file;
                main_image_info = (struct dyld_image_info*)malloc(sizeof(struct dyld_image_info));
                memcpy(main_image_info, image_info, sizeof(struct dyld_image_info));
                dyld_shared_cache = all_image_infos->sharedCacheBaseAddress;
                printf("%s main image loaded at 0x%llx\n", image_file, image_load_addr);
                main_image_load_base = image_load_addr;
                found_main_image = true;
            }
        } else {
            free(image_file);
        }
        libraries.push_back(library);
    }
    assert(found_main_image);
    dyld = GetImageLoadedAt("libdyld.dylib", nullptr);
    dyld_shared_cache = all_image_infos->sharedCacheBaseAddress;
    // printf("dyld_shared_cache = 0x%llx\n", dyld_shared_cache);
    assert(dyld);
    assert(dyld_shared_cache);
}

void Dyld::GetImageInfos() {
    all_image_info_addr = kernel->Read64(task->GetTask() + Offsets::task_all_image_info_addr);
    all_image_info_size = kernel->Read64(task->GetTask() + Offsets::task_all_image_info_size);
    if (!all_image_info_addr || !all_image_info_size) {
        kern_return_t kr;
        struct task_dyld_info dyld_info;
        mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
        if ((kr = task_info(task->GetTaskPort(), TASK_DYLD_INFO, (task_info_t)&dyld_info,
                            &count)) == KERN_SUCCESS) {
            all_image_info_addr = dyld_info.all_image_info_addr;
            all_image_info_size = dyld_info.all_image_info_size;
        } else {
            DARWIN_KIT_LOG("DarwinKit::could not find all_image_info for task! %d\n", kr);
        }
    }
}

xnu::mach::VmAddress Dyld::GetImageLoadedAt(char* image_name, char** image_path) {
    struct mach_header_64 hdr;
    xnu::mach::VmAddress where = 0;
    dyld::shared_cache::AllImageInfos all_images;
    GetImageInfos();
    assert(all_image_info_addr && all_image_info_size);
    task->Read(all_image_info_addr, &all_images, sizeof(all_images));
    if (!all_image_infos) {
        all_image_infos = reinterpret_cast<struct dyld_all_image_infos*>(
            malloc(sizeof(struct dyld_all_image_infos)));
    }
    memcpy(all_image_infos, &all_images, sizeof(struct dyld_all_image_infos));
    for (UInt32 i = 0; i < all_image_infos->infoArrayCount; i++) {
        dyld::shared_cache::ImageInfo image_info;
        xnu::mach::VmAddress image_info_addr;
        xnu::mach::VmAddress image_load_addr;
        xnu::mach::VmAddress image_file_path;
        char* image_file;
        image_info_addr = (xnu::mach::VmAddress)(all_image_infos->infoArray + i);
        task->Read(image_info_addr, &image_info, sizeof(image_info));
        image_load_addr = (xnu::mach::VmAddress)image_info.imageLoadAddress;
        image_file_path = (xnu::mach::VmAddress)image_info.imageFilePath;
        image_file = task->ReadString(image_file_path);
        if (EndsWith(image_file, image_name) || strcmp(image_file, image_name) == 0) {
            task->Read(image_load_addr, &hdr, sizeof(hdr));
            if (hdr.magic == MH_MAGIC_64) {
                printf("Found %s at %s loaded at 0x%llx\n", image_name, image_file,
                       image_load_addr);
                if (image_path) {
                    *image_path = image_file;
                }
                where = image_load_addr;
                if (strcmp(image_file, image_name) == 0) {
                    return where;
                }
            }
        }
        free(image_file);
    }
    if (image_path) {
        *image_path = nullptr;
    }
    return where;
}

dyld::shared_cache::Header* Dyld::CacheGetHeader() {
    struct dyld_cache_header* cache_header;
    xnu::mach::VmAddress shared_cache_rx_base;
    shared_cache_rx_base = dyld_shared_cache;
    cache_header =
        reinterpret_cast<struct dyld_cache_header*>(malloc(sizeof(struct dyld_cache_header)));
    task->Read(shared_cache_rx_base, cache_header, sizeof(struct dyld_cache_header));
    return cache_header;
}

dyld::shared_cache::MappingInfo* Dyld::CacheGetMappings(struct dyld_cache_header* cache_header) {
    dyld::shared_cache::MappingInfo* mappings;
    mappings = reinterpret_cast<struct dyld_cache_mapping_info*>(
        malloc(sizeof(struct dyld_cache_mapping_info) * cache_header->mappingCount));
    task->Read(dyld_shared_cache + cache_header->mappingOffset, mappings,
               sizeof(struct dyld_cache_mapping_info) * cache_header->mappingCount);
    return mappings;
}

dyld::shared_cache::MappingInfo* Dyld::CacheGetMapping(struct dyld_cache_header* cache_header,
                                                       xnu::mach::VmProtection prot) {
    for (UInt32 i = 0; i < cache_header->mappingCount; ++i) {
        struct dyld_cache_mapping_info* mapping =
            (struct dyld_cache_mapping_info*)malloc(sizeof(struct dyld_cache_mapping_info));
        task->Read(dyld_shared_cache + cache_header->mappingOffset +
                       sizeof(struct dyld_cache_mapping_info) * i,
                   mapping, sizeof(struct dyld_cache_mapping_info));
        if (mapping->initProt == prot) {
            return mapping;
        }
        free(mapping);
    }
    return nullptr;
}

void Dyld::CacheOffsetToAddress(UInt64 dyld_cache_offset, xnu::mach::VmAddress* address,
                                Offset* aslr) {
    dyld::shared_cache::Header* cache_header;
    dyld::shared_cache::MappingInfo* mappings;
    xnu::mach::VmAddress shared_cache_rx_base;
    shared_cache_rx_base = dyld_shared_cache;
    cache_header = CacheGetHeader();
    mappings = CacheGetMappings(cache_header);
    Size rx_size = 0;
    Size rw_size = 0;
    Size ro_size = 0;
    xnu::mach::VmAddress rx_addr = 0;
    xnu::mach::VmAddress rw_addr = 0;
    xnu::mach::VmAddress ro_addr = 0;
    xnu::mach::VmAddress dyld_cache_address = 0;
    for (UInt32 i = 0; i < cache_header->mappingCount; i++) {
        dyld::shared_cache::MappingInfo* mapping = &mappings[i];
        Offset low_bound = mapping->fileOffset;
        Offset high_bound = mapping->fileOffset + mapping->size;
        if (dyld_cache_offset >= low_bound && dyld_cache_offset < high_bound) {
            xnu::mach::VmAddress mappingAddr = dyld_cache_offset - low_bound;
            dyld_cache_address = mappingAddr + mapping->address;
        }
        if (mapping->maxProt == (VM_PROT_READ | VM_PROT_EXECUTE)) {
            rx_size += mapping->size;
            rx_addr = mapping->address;
        }
        if (mapping->maxProt == (VM_PROT_READ | VM_PROT_WRITE)) {
            rw_size += mapping->size;
            rw_addr = mapping->address;
        }
        if (mapping->maxProt == VM_PROT_READ) {
            ro_size += mapping->size;
            ro_addr = mapping->address;
        }
    }
    Offset aslr_slide = (Offset)(dyld_shared_cache - rx_addr);
    char* shared_cache_ro = (char*)((xnu::mach::VmAddress)ro_addr + aslr_slide);
    Offset offset_from_ro = (Offset)(dyld_cache_offset - rx_size - rw_size);
    if (address) {
        *address = ((xnu::mach::VmAddress)dyld_cache_address + aslr_slide);
    }
    if (aslr_slide) {
        *aslr = aslr_slide;
    }
    free(cache_header);
    free(mappings);
}

void Dyld::CacheGetSymtabStrtab(struct symtab_command* symtab_command, xnu::mach::VmAddress* symtab,
                                xnu::mach::VmAddress* strtab, Offset* off) {
    CacheOffsetToAddress(symtab_command->symoff, symtab, off);
    CacheOffsetToAddress(symtab_command->stroff, strtab, off);
    slide = *off;
}

xnu::mach::VmAddress Dyld::GetImageSlide(xnu::mach::VmAddress address) {
    bool ok;
    bool dylibInSharedCache;
    struct mach_header_64* hdr;
    xnu::mach::VmAddress symtab;
    xnu::mach::VmAddress strtab;
    Offset slide;
    UInt8* cmds;
    UInt32 ncmds;
    Size sizeofcmds;
    UInt64 cmd_offset;

    hdr = reinterpret_cast<struct mach_header_64*>(malloc(sizeof(struct mach_header_64)));
    ok = task->Read(address, hdr, sizeof(struct mach_header_64));
    dylibInSharedCache = hdr->flags & MH_DYLIB_IN_CACHE;
    ncmds = hdr->ncmds;
    sizeofcmds = hdr->sizeofcmds;

    cmds = reinterpret_cast<UInt8*>(malloc(sizeofcmds));
    ok = task->Read(address + sizeof(struct mach_header_64), cmds, sizeofcmds);
    cmd_offset = 0;
    slide = 0;
    for (int i = 0; i < ncmds; i++) {
        struct load_command* load_cmd = reinterpret_cast<struct load_command*>(cmds + cmd_offset);
        UInt32 cmdtype = load_cmd->cmd;
        UInt32 cmdsize = load_cmd->cmdsize;
        switch (cmdtype) {
        case LC_SYMTAB: {
            ;
            struct symtab_command* symtab_command = (struct symtab_command*)load_cmd;
            if (dylibInSharedCache) {
                CacheGetSymtabStrtab(symtab_command, &symtab, &strtab, &slide);
            }
            break;
        }
        }
        cmd_offset += cmdsize;
    }
    free(hdr);
    free(cmds);
    return slide;
}

Size Dyld::GetAdjustedStrtabSize(struct symtab_command* symtab_command,
                                 xnu::mach::VmAddress linkedit, Offset linkedit_fileoff) {
    xnu::mach::VmAddress symtab;
    xnu::mach::VmAddress strtab;
    Size symsize;
    Size new_strsize;
    Offset symoff;
    Offset stroff;
    struct nlist_64* syms;

    symoff = symtab_command->symoff;
    stroff = symtab_command->stroff;
    symsize = symtab_command->nsyms * sizeof(struct nlist_64);
    syms = reinterpret_cast<struct nlist_64*>(malloc(symsize));
    symtab = linkedit + (symtab_command->symoff - linkedit_fileoff);
    strtab = linkedit + (symtab_command->stroff - linkedit_fileoff);
    task->Read(symtab, syms, symsize);
    new_strsize = 0;
    for (int i = 0; i < symtab_command->nsyms; i++) {
        struct nlist_64* nl = &syms[i];
        char* sym = task->ReadString(strtab + nl->n_strx);
        new_strsize += strlen(sym) + 1;
        free(sym);
    }
    free(syms);
    return new_strsize;
}

Size Dyld::GetAdjustedLinkeditSize(xnu::mach::VmAddress address) {
    struct mach_header_64* hdr;
    Size linkedit_new_sz;
    xnu::mach::VmAddress symtab;
    xnu::mach::VmAddress strtab;
    xnu::mach::VmAddress linkedit_vmaddr;
    xnu::mach::VmAddress text_vmaddr;
    xnu::mach::VmAddress linkedit_begin_off;
    xnu::mach::VmAddress linkedit_old_off;
    xnu::mach::VmAddress linkedit_new_off;
    Offset aslr_slide;
    xnu::mach::VmAddress align;
    xnu::mach::VmAddress current_offset;

    UInt64 cmd_offset;
    UInt8* cmds;
    UInt8* q;
    UInt32 ncmds;
    Size sizeofcmds;
    Size filesz = 0;

    aslr_slide = GetImageSlide(address);
    linkedit_new_sz = 0;
    hdr = reinterpret_cast<struct mach_header_64*>(malloc(sizeof(struct mach_header_64)));
    bool ok = task->Read(address, hdr, sizeof(struct mach_header_64));
    assert(ok);

    ncmds = hdr->ncmds;
    sizeofcmds = hdr->sizeofcmds;
    cmds = reinterpret_cast<UInt8*>(malloc(sizeofcmds));
    ok = task->Read(address + sizeof(struct mach_header_64), cmds, sizeofcmds);
    align = sizeof(struct mach_header_64) + hdr->sizeofcmds;
    current_offset = (align % 0x1000 > 0 ? align / 0x1000 + 1 : align / 0x1000) * 0x1000;
    q = cmds;
    for (int i = 0; i < ncmds; i++) {
        struct load_command* load_cmd = reinterpret_cast<struct load_command*>(q);
        UInt32 cmdtype = load_cmd->cmd;
        UInt32 cmdsize = load_cmd->cmdsize;
        if (load_cmd->cmd == LC_SEGMENT_64) {
            struct segment_command_64* segment_command =
                reinterpret_cast<struct segment_command_64*>(load_cmd);
            if (strcmp(segment_command->segname, "__LINKEDIT") != 0) {
                current_offset += segment_command->filesize;
            } else {
                linkedit_begin_off = current_offset;

                linkedit_new_off = current_offset;
                linkedit_old_off = segment_command->fileoff;

                linkedit_vmaddr = segment_command->vmaddr;
            }
            printf("LC_SEGMENT_64 at 0x%llx - %s 0x%08llx to 0x%08llx \n", segment_command->fileoff,
                   segment_command->segname, segment_command->vmaddr,
                   segment_command->vmaddr + segment_command->vmsize);
            UInt64 sect_offset = 0;
            for (int j = 0; j < segment_command->nsects; j++) {
                struct section_64* section =
                    (struct section_64*)((UInt64)load_cmd + sizeof(struct segment_command_64) +
                                         sect_offset);
                printf("\tSection %d: 0x%08llx to 0x%08llx - %s\n", j, section->addr,
                       section->addr + section->size, section->sectname);
                sect_offset += sizeof(struct section_64);
            }
        } else if (load_cmd->cmd == LC_SYMTAB) {
            struct symtab_command* symtab_command = reinterpret_cast<struct symtab_command*>(q);
            task->Read(address + sizeof(struct mach_header_64), cmds, sizeofcmds);
            UInt32 new_strsize = GetAdjustedStrtabSize(symtab_command, linkedit_vmaddr + aslr_slide,
                                                       linkedit_old_off);
            UInt64 symsize = symtab_command->nsyms * sizeof(struct nlist_64);
            UInt64 strsize = symtab_command->strsize;
            UInt64 old_symoff = symtab_command->symoff;
            UInt64 old_stroff = symtab_command->stroff;
            UInt64 new_symoff = (old_symoff - linkedit_old_off);
            UInt64 new_stroff = (old_stroff - linkedit_old_off);
            symtab_command->symoff = (UInt32)new_symoff;
            symtab_command->stroff = (UInt32)new_stroff;
            linkedit_new_sz += (symsize + new_strsize);
            new_symoff = (old_symoff - linkedit_old_off) + linkedit_new_off;
            new_stroff = (old_stroff - linkedit_old_off) + linkedit_new_off;
            symtab_command->symoff = (UInt32)new_symoff;
            symtab_command->stroff = (UInt32)new_stroff;
        } else if (load_cmd->cmd == LC_DYSYMTAB) {
            struct dysymtab_command* dysymtab_command = (struct dysymtab_command*)q;
            UInt32 tocoff = dysymtab_command->tocoff;
            UInt32 tocsize = dysymtab_command->ntoc * sizeof(struct dylib_table_of_contents);
            UInt32 modtaboff = dysymtab_command->modtaboff;
            UInt32 modtabsize = dysymtab_command->nmodtab * sizeof(struct dylib_module_64);
            UInt32 extrefsymoff = dysymtab_command->extrefsymoff;
            UInt32 extrefsize = dysymtab_command->nextrefsyms * sizeof(struct dylib_reference);
            UInt32 indirectsymoff = dysymtab_command->indirectsymoff;
            UInt32 indirectsize = dysymtab_command->nindirectsyms * sizeof(UInt32);
            UInt32 extreloff = dysymtab_command->extreloff;
            UInt32 extrelsize = dysymtab_command->nextrel * sizeof(struct relocation_info);
            UInt32 locreloff = dysymtab_command->locreloff;
            UInt32 locrelsize = dysymtab_command->nlocrel * sizeof(struct relocation_info);
            dysymtab_command->tocoff = (tocoff - linkedit_old_off) + linkedit_new_off;
            dysymtab_command->modtaboff = (modtaboff - linkedit_old_off) + linkedit_new_off;
            dysymtab_command->extrefsymoff = (extrefsymoff - linkedit_old_off) + linkedit_new_off;
            dysymtab_command->indirectsymoff =
                (indirectsymoff - linkedit_old_off) + linkedit_new_off;
            dysymtab_command->extreloff = (extreloff - linkedit_old_off) + linkedit_new_off;
            dysymtab_command->locreloff = (locreloff - linkedit_old_off) + linkedit_new_off;
            linkedit_new_sz +=
                (tocsize + modtabsize + extrefsize + indirectsize + extrelsize + locrelsize);
        } else if (load_cmd->cmd == LC_DYLD_INFO_ONLY) {
            struct dyld_info_command* dyld_info_command = (struct dyld_info_command*)q;
            UInt32 rebase_off = dyld_info_command->rebase_off;
            UInt32 rebase_size = dyld_info_command->rebase_size;
            UInt32 bind_off = dyld_info_command->bind_off;
            UInt32 bind_size = dyld_info_command->bind_size;
            UInt32 weak_bind_off = dyld_info_command->weak_bind_off;
            UInt32 weak_bind_size = dyld_info_command->weak_bind_size;
            UInt32 lazy_bind_off = dyld_info_command->lazy_bind_off;
            UInt32 lazy_bind_size = dyld_info_command->lazy_bind_size;
            UInt32 export_off = dyld_info_command->export_off;
            UInt32 export_size = dyld_info_command->export_size;
            dyld_info_command->rebase_off = (rebase_off - linkedit_old_off) + linkedit_new_off;
            dyld_info_command->bind_off = (bind_off - linkedit_old_off) + linkedit_new_off;
            dyld_info_command->weak_bind_off =
                (weak_bind_off - linkedit_old_off) + linkedit_new_off;
            dyld_info_command->lazy_bind_off =
                (lazy_bind_off - linkedit_old_off) + linkedit_new_off;
            dyld_info_command->export_off = (export_off - linkedit_old_off) + linkedit_new_off;
            linkedit_new_sz +=
                (rebase_size + bind_size + weak_bind_size + lazy_bind_size + export_size);
        } else if (load_cmd->cmd == LC_FUNCTION_STARTS) {
            struct linkedit_data_command* linkedit_data_command = (struct linkedit_data_command*)q;
            linkedit_data_command->dataoff =
                (linkedit_data_command->dataoff - linkedit_old_off) + linkedit_new_off;
            linkedit_new_sz += linkedit_data_command->datasize;
        } else if (load_cmd->cmd == LC_CODE_SIGNATURE) {
            struct linkedit_data_command* linkedit_data_command = (struct linkedit_data_command*)q;
            linkedit_data_command->dataoff =
                (linkedit_data_command->dataoff - linkedit_old_off) + linkedit_new_off;
            linkedit_new_sz += linkedit_data_command->datasize;
        } else if (load_cmd->cmd == LC_DATA_IN_CODE) {
            struct linkedit_data_command* linkedit_data_command = (struct linkedit_data_command*)q;
            linkedit_data_command->dataoff =
                (linkedit_data_command->dataoff - linkedit_old_off) + linkedit_new_off;
            linkedit_new_sz += linkedit_data_command->datasize;
        }
        q = q + load_cmd->cmdsize;
    }
    linkedit_new_sz =
        (linkedit_new_sz % 0x1000 > 0 ? linkedit_new_sz / 0x1000 + 1 : linkedit_new_sz / 0x1000) *
        0x1000;
    return linkedit_new_sz;

exit:
    if (hdr) {
        free(hdr);
    }
    if (cmds) {
        free(cmds);
    }
    return 0;
}

void Dyld::RebuildSymtabStrtab(struct symtab_command* symtab_command, xnu::mach::VmAddress symtab_,
                               xnu::mach::VmAddress strtab_, xnu::mach::VmAddress linkedit,
                               Offset linkedit_fileoff) {
    struct nlist_64* symtab;
    char* strtab;
    xnu::mach::VmAddress symoff;
    xnu::mach::VmAddress stroff;
    Size symsize;
    Size strsize;
    int idx = 0;
    symoff = symtab_command->symoff;
    stroff = symtab_command->stroff;
    symsize = symtab_command->nsyms * sizeof(struct nlist_64);
    strsize = symtab_command->strsize;
    symtab = reinterpret_cast<struct nlist_64*>(symtab_);
    strtab = reinterpret_cast<char*>(strtab_);
    for (int i = 0; i < symtab_command->nsyms; i++) {
        struct nlist_64* nl = &symtab[i];
        char* sym = task->ReadString(linkedit + (stroff - linkedit_fileoff) + nl->n_strx);
        memcpy(strtab + idx, sym, strlen(sym));
        strtab[idx + strlen(sym)] = '\0';
        nl->n_strx = idx;
        idx += strlen(sym) + 1;
        free(sym);
    }
}

void Dyld::FixupObjectiveC(MachO* macho) {}

void Dyld::FixupDyldRebaseBindOpcodes(MachO* macho, Segment* linkedit) {}

Size Dyld::GetImageSize(xnu::mach::VmAddress address) {
    bool ok;
    bool dylibInSharedCache;

    struct mach_header_64* hdr;
    xnu::mach::VmAddress align;
    UInt64 ncmds;
    Size sizeofcmds;
    UInt8* cmds;
    UInt8* q;
    Size filesz = 0;

    hdr = nullptr;
    cmds = nullptr;
    hdr = reinterpret_cast<struct mach_header_64*>(malloc(sizeof(struct mach_header_64)));
    ok = task->Read(address, hdr, sizeof(struct mach_header_64));
    assert(ok);
    dylibInSharedCache = hdr->flags & MH_DYLIB_IN_CACHE;
    ncmds = hdr->ncmds;
    sizeofcmds = hdr->sizeofcmds;
    cmds = reinterpret_cast<UInt8*>(malloc(sizeofcmds));
    ok = task->Read(address + sizeof(struct mach_header_64), cmds, sizeofcmds);
    assert(ok);
    align = sizeof(struct mach_header_64) + hdr->sizeofcmds;
    filesz = (align % 0x1000 > 0 ? align / 0x1000 + 1 : align / 0x1000) * 0x1000;
    q = cmds;
    for (int i = 0; i < ncmds; i++) {
        struct load_command* load_cmd = reinterpret_cast<struct load_command*>(q);
        UInt32 cmdtype = load_cmd->cmd;
        UInt32 cmdsize = load_cmd->cmdsize;
        if (load_cmd->cmd == LC_SEGMENT_64) {
            struct segment_command_64* segment = reinterpret_cast<struct segment_command_64*>(q);
            UInt64 fileoff = segment->fileoff;
            UInt64 filesize = segment->filesize;
            if (task->GetPid() == getpid()) {
                filesz = max(filesz, fileoff + filesize);
            } else {
                if (dylibInSharedCache && strcmp(segment->segname, "__LINKEDIT") == 0) {
                    filesize = GetAdjustedLinkeditSize(address);
                }
                filesz += filesize;
            }
        }
        q = q + load_cmd->cmdsize;
    }
    free(hdr);
    free(cmds);
    if (task->GetPid() == getpid()) {
        return filesz;
    }
    align = sizeof(struct mach_header_64) + sizeofcmds;
    return filesz + (align % 0x1000 > 0 ? align / 0x1000 + 1 : align / 0x1000) * 0x1000;
exit:
    if (hdr) {
        free(hdr);
    }
    if (cmds) {
        free(cmds);
    }
    return 0;
}

MachO* Dyld::CacheDumpImage(char* image) {
    MachOUserspace* macho;
    MachOUserspace* objc;
    bool objC = false;
    struct mach_header_64* hdr;
    bool dylibInSharedCache;
    UInt8* cmds;
    xnu::mach::VmAddress symtab;
    xnu::mach::VmAddress strtab;
    xnu::mach::VmAddress linkedit_vmaddr;
    xnu::mach::VmAddress linkedit_off;
    xnu::mach::VmAddress linkedit_old_off;
    xnu::mach::VmAddress linkedit_new_off;

    Size linkedit_new_sz;
    char* image_dump;
    Size image_size;
    xnu::mach::VmAddress address = GetImageLoadedAt(image, nullptr);
    Size size = GetImageSize(address);
    Offset aslr_slide = GetImageSlide(address);
    FILE* fp;
    objc = nullptr;
    if (size) {
        UInt8* q;
        UInt64 align;
        UInt64 current_offset = 0;
        image_size = GetImageSize(address);
        image_dump = reinterpret_cast<char*>(malloc(image_size));
        memset(image_dump, 0x0, size);
        // printf("Dumping image at 0x%llx with size 0x%zx\n", (UInt64) image, size);
        task->Read(address, image_dump, sizeof(struct mach_header_64));
        hdr = reinterpret_cast<struct mach_header_64*>(image_dump);
        dylibInSharedCache = hdr->flags & MH_DYLIB_IN_CACHE;
        // printf("dylib in cache? %s %d\n", dylibInSharedCache ? "YES" : "NO", hdr->filetype);
        if (!dylibInSharedCache) {
            aslr_slide = 0;
        }
        task->Read(address + sizeof(struct mach_header_64),
                   image_dump + sizeof(struct mach_header_64), hdr->sizeofcmds);
        align = sizeof(struct mach_header_64) + hdr->sizeofcmds;
        current_offset = (align % 0x1000 > 0 ? align / 0x1000 + 1 : align / 0x1000) * 0x1000;
        cmds = reinterpret_cast<UInt8*>(hdr) + sizeof(struct mach_header_64);
        q = cmds;
        for (int i = 0; i < hdr->ncmds; i++) {
            struct load_command* load_cmd = reinterpret_cast<struct load_command*>(q);
            UInt32 cmdtype = load_cmd->cmd;
            UInt32 cmdsize = load_cmd->cmdsize;
            if (load_cmd->cmd == LC_SEGMENT_64) {
                struct segment_command_64* segment =
                    reinterpret_cast<struct segment_command_64*>(q);
                UInt64 vmaddr = segment->vmaddr;
                UInt64 vmsize = segment->vmsize;
                UInt64 fileoffset = segment->fileoff;
                UInt64 filesize = segment->filesize;
                if (dylibInSharedCache && strcmp(segment->segname, "__LINKEDIT") == 0) {
                    linkedit_new_off = current_offset;
                    linkedit_old_off = segment->fileoff;
                    linkedit_new_sz = GetAdjustedLinkeditSize(address);
                    filesize = linkedit_new_sz;
                    linkedit_off = 0;
                    linkedit_vmaddr = vmaddr;
                    segment->fileoff = current_offset;
                    segment->filesize = linkedit_new_sz;
                    segment->vmsize = linkedit_new_sz;
                } else {
                    segment->fileoff = current_offset;
                    segment->filesize = filesize;
                    printf("Dumping %s at 0x%llx with size 0x%llx at 0x%llx\n", segment->segname,
                           vmaddr + aslr_slide, filesize, (UInt64)(image_dump + current_offset));
                    if (dylibInSharedCache &&
                        !task->Read(vmaddr + aslr_slide, image_dump + current_offset, filesize)) {
                        printf("Failed to dump segment %s\n", segment->segname);
                        goto exit;
                    }
                    if (!dylibInSharedCache && !task->Read(address + vmaddr + aslr_slide,
                                                           image_dump + current_offset, filesize)) {
                        printf("Failed to dump segment %s\n", segment->segname);
                        goto exit;
                    }
                    for (int j = 0; j < segment->nsects; j++) {
                        struct section_64* section = reinterpret_cast<struct section_64*>(
                            q + sizeof(struct segment_command_64) + sizeof(struct section_64) * j);
                        if (!strstr(image, "libobjc.A.dylib") &&
                            strstr(section->sectname, "__objc")) {
                            objC = true;
                        }
                        if (section->offset) {
                            section->offset = current_offset + (section->offset - fileoffset);
                        }
                    }
                    current_offset += filesize;
                }

            } else if (load_cmd->cmd == LC_SYMTAB) {
                struct symtab_command* symtab_command = reinterpret_cast<struct symtab_command*>(q);
                if (dylibInSharedCache) {
                    UInt64 symsize = symtab_command->nsyms * sizeof(struct nlist_64);
                    UInt64 strsize = symtab_command->strsize;
                    UInt64 old_symoff = symtab_command->symoff;
                    UInt64 old_stroff = symtab_command->stroff;
                    UInt64 symoff = old_symoff - linkedit_new_off;
                    UInt64 stroff = old_stroff - linkedit_new_off;
                    UInt32 new_strsize = GetAdjustedStrtabSize(
                        symtab_command, linkedit_vmaddr + aslr_slide, linkedit_old_off);
                    UInt64 symtab = (UInt64)(image_dump + linkedit_new_off + linkedit_off);
                    UInt64 strtab =
                        (UInt64)(image_dump + linkedit_new_off + linkedit_off + symsize);
                    task->Read(linkedit_vmaddr + aslr_slide +
                                   (symtab_command->symoff - linkedit_old_off),
                               image_dump + linkedit_new_off + linkedit_off, symsize);
                    RebuildSymtabStrtab(symtab_command, symtab, strtab,
                                        linkedit_vmaddr + aslr_slide, linkedit_old_off);
                    symtab_command->symoff = linkedit_new_off + linkedit_off;
                    symtab_command->stroff = linkedit_new_off + linkedit_off + symsize;
                    symtab_command->strsize = new_strsize;
                    linkedit_off += (symsize + new_strsize);
                } else {
                    UInt64 symsize = symtab_command->nsyms * sizeof(struct nlist_64);
                    UInt64 strsize = symtab_command->strsize;
                    UInt64 symoff = symtab_command->symoff;
                    UInt64 stroff = symtab_command->stroff;
                    task->Read(address + aslr_slide + symoff, image_dump + current_offset, symsize);
                    symtab_command->symoff = current_offset;
                    current_offset += symsize;
                    task->Read(address + aslr_slide + stroff, image_dump + current_offset, strsize);
                    symtab_command->stroff = current_offset;
                    current_offset += strsize;
                }
            } else if (load_cmd->cmd == LC_DYSYMTAB) {
                struct dysymtab_command* dysymtab_command =
                    reinterpret_cast<struct dysymtab_command*>(q);
                if (dylibInSharedCache) {
                    UInt32 tocoff = dysymtab_command->tocoff - linkedit_old_off;
                    UInt32 tocsize =
                        dysymtab_command->ntoc * sizeof(struct dylib_table_of_contents);
                    UInt32 modtaboff = dysymtab_command->modtaboff - linkedit_old_off;
                    UInt32 modtabsize = dysymtab_command->nmodtab * sizeof(struct dylib_module_64);
                    UInt32 extrefsymoff = dysymtab_command->extrefsymoff - linkedit_old_off;
                    UInt32 extrefsize =
                        dysymtab_command->nextrefsyms * sizeof(struct dylib_reference);
                    UInt32 indirectsymoff = dysymtab_command->indirectsymoff - linkedit_old_off;
                    UInt32 indirectsize = dysymtab_command->nindirectsyms * sizeof(UInt32);
                    UInt32 extreloff = dysymtab_command->extreloff - linkedit_old_off;
                    UInt32 extrelsize = dysymtab_command->nextrel * sizeof(struct relocation_info);
                    UInt32 locreloff = dysymtab_command->locreloff - linkedit_old_off;
                    UInt32 locrelsize = dysymtab_command->nlocrel * sizeof(struct relocation_info);
                    task->Read(linkedit_vmaddr + aslr_slide + tocoff,
                               image_dump + linkedit_new_off + linkedit_off, tocsize);

                    dysymtab_command->tocoff = linkedit_new_off + linkedit_off;
                    linkedit_off += tocsize;
                    task->Read(linkedit_vmaddr + aslr_slide + modtaboff,
                               image_dump + linkedit_new_off + linkedit_off, modtabsize);
                    dysymtab_command->modtaboff = linkedit_new_off + linkedit_off;
                    linkedit_off += modtabsize;
                    task->Read(linkedit_vmaddr + aslr_slide + extrefsymoff,
                               image_dump + linkedit_new_off + linkedit_off, extrefsize);
                    dysymtab_command->extrefsymoff = linkedit_new_off + linkedit_off;
                    linkedit_off += extrefsize;
                    task->Read(linkedit_vmaddr + aslr_slide + indirectsymoff,
                               image_dump + linkedit_new_off + linkedit_off, indirectsize);
                    dysymtab_command->indirectsymoff = linkedit_new_off + linkedit_off;
                    linkedit_off += indirectsize;
                    task->Read(linkedit_vmaddr + aslr_slide + extreloff,
                               image_dump + linkedit_new_off + linkedit_off, extrelsize);
                    dysymtab_command->extreloff = linkedit_new_off + linkedit_off;
                    linkedit_off += extrelsize;
                    task->Read(linkedit_vmaddr + aslr_slide + locreloff,
                               image_dump + linkedit_new_off + linkedit_off, locrelsize);
                    dysymtab_command->locreloff = linkedit_new_off + linkedit_off;
                    linkedit_off += locrelsize;
                } else {
                    UInt32 tocoff = dysymtab_command->tocoff;
                    UInt32 tocsize =
                        dysymtab_command->ntoc * sizeof(struct dylib_table_of_contents);
                    UInt32 modtaboff = dysymtab_command->modtaboff;
                    UInt32 modtabsize = dysymtab_command->nmodtab * sizeof(struct dylib_module_64);
                    UInt32 extrefsymoff = dysymtab_command->extrefsymoff;
                    UInt32 extrefsize =
                        dysymtab_command->nextrefsyms * sizeof(struct dylib_reference);
                    UInt32 indirectsymoff = dysymtab_command->indirectsymoff;
                    UInt32 indirectsize = dysymtab_command->nindirectsyms * sizeof(UInt32);
                    UInt32 extreloff = dysymtab_command->extreloff;
                    UInt32 extrelsize = dysymtab_command->nextrel * sizeof(struct relocation_info);
                    UInt32 locreloff = dysymtab_command->locreloff;
                    UInt32 locrelsize = dysymtab_command->nlocrel * sizeof(struct relocation_info);
                    task->Read(address + aslr_slide + tocoff, image_dump + current_offset, tocsize);
                    dysymtab_command->tocoff = current_offset;
                    current_offset += tocsize;
                    task->Read(address + aslr_slide + modtaboff, image_dump + current_offset,
                               modtabsize);
                    dysymtab_command->modtaboff = current_offset;
                    current_offset += modtabsize;
                    task->Read(address + aslr_slide + extrefsymoff, image_dump + current_offset,
                               extrefsize);
                    dysymtab_command->extrefsymoff = current_offset;
                    current_offset += extrefsize;
                    task->Read(address + aslr_slide + indirectsymoff, image_dump + current_offset,
                               indirectsize);
                    dysymtab_command->indirectsymoff = current_offset;
                    current_offset += indirectsize;
                    task->Read(address + aslr_slide + extreloff, image_dump + current_offset,
                               extrelsize);
                    dysymtab_command->extreloff = current_offset;
                    current_offset += extrelsize;
                    task->Read(address + aslr_slide + locreloff, image_dump + current_offset,
                               locrelsize);
                    dysymtab_command->locreloff = current_offset;
                    current_offset += locrelsize;
                }

            } else if (load_cmd->cmd == LC_DYLD_INFO_ONLY) {
                struct dyld_info_command* dyld_info_command =
                    reinterpret_cast<struct dyld_info_command*>(q);
                if (dylibInSharedCache) {
                    UInt32 rebase_off = dyld_info_command->rebase_off - linkedit_old_off;
                    UInt32 rebase_size = dyld_info_command->rebase_size;
                    UInt32 bind_off = dyld_info_command->bind_off - linkedit_old_off;
                    UInt32 bind_size = dyld_info_command->bind_size;
                    UInt32 weak_bind_off = dyld_info_command->weak_bind_off - linkedit_old_off;
                    UInt32 weak_bind_size = dyld_info_command->weak_bind_size;
                    UInt32 lazy_bind_off = dyld_info_command->lazy_bind_off - linkedit_old_off;
                    UInt32 lazy_bind_size = dyld_info_command->lazy_bind_size;
                    UInt32 export_off = dyld_info_command->export_off - linkedit_old_off;
                    UInt32 export_size = dyld_info_command->export_size;
                    task->Read(linkedit_vmaddr + aslr_slide + rebase_off,
                               image_dump + linkedit_new_off + linkedit_off, rebase_size);
                    dyld_info_command->rebase_off = linkedit_new_off + linkedit_off;
                    linkedit_off += rebase_size;
                    task->Read(linkedit_vmaddr + aslr_slide + bind_off,
                               image_dump + linkedit_new_off + linkedit_off, bind_size);
                    dyld_info_command->bind_off = linkedit_new_off + linkedit_off;
                    linkedit_off += bind_size;
                    task->Read(linkedit_vmaddr + aslr_slide + weak_bind_off,
                               image_dump + linkedit_new_off + linkedit_off, weak_bind_size);
                    dyld_info_command->weak_bind_off = linkedit_new_off + linkedit_off;
                    linkedit_off += weak_bind_size;
                    task->Read(linkedit_vmaddr + aslr_slide + lazy_bind_off,
                               image_dump + linkedit_new_off + linkedit_off, lazy_bind_size);
                    dyld_info_command->lazy_bind_off = linkedit_new_off + linkedit_off;
                    linkedit_off += lazy_bind_size;
                    task->Read(linkedit_vmaddr + aslr_slide + export_off,
                               image_dump + linkedit_new_off + linkedit_off, export_size);
                    dyld_info_command->export_off = linkedit_new_off + linkedit_off;
                    linkedit_off += export_size;
                } else {
                    UInt32 rebase_off = dyld_info_command->rebase_off;
                    UInt32 rebase_size = dyld_info_command->rebase_size;
                    UInt32 bind_off = dyld_info_command->bind_off;
                    UInt32 bind_size = dyld_info_command->bind_size;
                    UInt32 weak_bind_off = dyld_info_command->weak_bind_off;
                    UInt32 weak_bind_size = dyld_info_command->weak_bind_size;
                    UInt32 lazy_bind_off = dyld_info_command->lazy_bind_off - linkedit_old_off;
                    UInt32 lazy_bind_size = dyld_info_command->lazy_bind_size;
                    UInt32 export_off = dyld_info_command->export_off - linkedit_old_off;
                    UInt32 export_size = dyld_info_command->export_size;
                    task->Read(address + aslr_slide + rebase_off, image_dump + current_offset,
                               rebase_size);
                    dyld_info_command->rebase_off = current_offset;
                    current_offset += rebase_size;
                    task->Read(address + aslr_slide + bind_off, image_dump + current_offset,
                               bind_size);
                    dyld_info_command->bind_off = current_offset;
                    current_offset += bind_size;
                    task->Read(address + aslr_slide + weak_bind_off, image_dump + current_offset,
                               weak_bind_size);
                    dyld_info_command->weak_bind_off = current_offset;
                    current_offset += weak_bind_size;
                    task->Read(address + aslr_slide + lazy_bind_off, image_dump + current_offset,
                               lazy_bind_size);
                    dyld_info_command->lazy_bind_off = current_offset;
                    current_offset += lazy_bind_size;
                    task->Read(address + aslr_slide + export_off, image_dump + current_offset,
                               export_size);
                    dyld_info_command->export_off = current_offset;
                    current_offset += export_size;
                }

            } else if (load_cmd->cmd == LC_FUNCTION_STARTS) {
                struct linkedit_data_command* linkedit_data_command =
                    reinterpret_cast<struct linkedit_data_command*>(q);
                if (dylibInSharedCache) {
                    UInt32 dataoff = linkedit_data_command->dataoff - linkedit_old_off;
                    UInt32 datasize = linkedit_data_command->datasize;
                    task->Read(linkedit_vmaddr + aslr_slide + dataoff,
                               image_dump + linkedit_new_off + linkedit_off, datasize);

                    linkedit_data_command->dataoff = linkedit_new_off + linkedit_off;
                    linkedit_off += datasize;
                } else {
                    UInt32 dataoff = linkedit_data_command->dataoff;
                    UInt32 datasize = linkedit_data_command->datasize;
                    task->Read(address + aslr_slide + dataoff, image_dump + current_offset,
                               datasize);
                    linkedit_data_command->dataoff = current_offset;
                    current_offset += datasize;
                }

            } else if (load_cmd->cmd == LC_CODE_SIGNATURE) {
                struct linkedit_data_command* linkedit_data_command =
                    reinterpret_cast<struct linkedit_data_command*>(q);
                if (dylibInSharedCache) {
                    UInt32 dataoff = linkedit_data_command->dataoff - linkedit_old_off;
                    UInt32 datasize = linkedit_data_command->datasize;
                    task->Read(linkedit_vmaddr + aslr_slide + dataoff,
                               image_dump + linkedit_new_off + linkedit_off, datasize);
                    linkedit_data_command->dataoff = linkedit_new_off + linkedit_off;
                    linkedit_off += datasize;
                } else {
                    UInt32 dataoff = linkedit_data_command->dataoff;
                    UInt32 datasize = linkedit_data_command->datasize;
                    task->Read(address + aslr_slide + dataoff, image_dump + current_offset,
                               datasize);
                    linkedit_data_command->dataoff = current_offset;
                    current_offset += datasize;
                }
            } else if (load_cmd->cmd == LC_DATA_IN_CODE) {
                struct linkedit_data_command* linkedit_data_command =
                    reinterpret_cast<struct linkedit_data_command*>(q);
                if (dylibInSharedCache) {
                    UInt32 dataoff = linkedit_data_command->dataoff - linkedit_old_off;
                    UInt32 datasize = linkedit_data_command->datasize;
                    task->Read(linkedit_vmaddr + aslr_slide + dataoff,
                               image_dump + linkedit_new_off + linkedit_off, datasize);
                    linkedit_data_command->dataoff = linkedit_new_off + linkedit_off;
                    linkedit_off += datasize;
                } else {
                    UInt32 dataoff = linkedit_data_command->dataoff;
                    UInt32 datasize = linkedit_data_command->datasize;
                    task->Read(address + aslr_slide + dataoff, image_dump + current_offset,
                               datasize);
                    linkedit_data_command->dataoff = current_offset;
                    current_offset += datasize;
                }
            }
            q = q + load_cmd->cmdsize;
        }
    }
    if (objC) {
        objc = dynamic_cast<MachOUserspace*>(CacheDumpImage("libobjc.A.dylib"));

        objc->SetObjectiveCLibrary(objc);
        objc->SetIsObjectiveCLibrary(true);
    }
    /*
    fp = fopen("file.bin", "w");
    fwrite(image_dump, image_size, 1, fp);
    fclose(fp);
    */
    macho = new MachOUserspace();
    if (objc) {
        macho->WithBuffer(objc, address, image_dump, aslr_slide);
    } else {
        if (strstr(image, "libobjc.A.dylib")) {
            macho->WithBuffer(macho, address, image_dump, aslr_slide);
        } else {
            macho->WithBuffer(address, image_dump, aslr_slide, true);
        }
    }
    return reinterpret_cast<MachO*>(macho);

exit:
    if (image) {
        free(image);
    }
    return nullptr;
}

MachO* Dyld::CacheDumpImageToFile(char* image, char* path) {
    FILE* out;
    MachO* macho = CacheDumpImage(image);
    if (!macho) {
        return nullptr;
    }
    out = fopen(path, "w");
    if (!out) {
        return nullptr;
    }
    fclose(out);
    return macho;
}

} // namespace dyld
} // namespace darwin