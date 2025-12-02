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

#include <stdio.h>
#include <stdlib.h>

#include "macho_userspace.h"

#include "dyld.h"
#include "objc.h"
#include "task.h"

namespace darwin {

MachOUserspace::MachOUserspace(const char* path) : objc(nullptr), file_path(strdup(path)) {
    WithFilePath(path);
}

void MachOUserspace::WithTask(xnu::Task* task) {
    task = task;
    dyld = task->GetDyld();
    dyld_base = dyld->GetDyld();
    dyld_shared_cache = dyld->GetDyldSharedCache();
    file_path = dyld->GetMainImagePath();
    symbolTable = new SymbolTable();
}

void MachOUserspace::WithFilePath(const char* path) {
    int fd = open(path, O_RDONLY);
    Size size = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);
    buffer = reinterpret_cast<char*>(malloc(size));
    Size bytes_read;
    bytes_read = read(fd, buffer, size);
    header = reinterpret_cast<struct mach_header_64*>(buffer);
    base = reinterpret_cast<xnu::mach::VmAddress>(buffer);
    symbolTable = new SymbolTable();
    ParseMachO();
    close(fd);
}

void MachOUserspace::WithBuffer(char* buf) {
    buffer = buf;
    header = reinterpret_cast<struct mach_header_64*>(buffer);
    symbolTable = new SymbolTable();
    ParseMachO();
}

void MachOUserspace::WithBuffer(char* buf, off_t slide) {
    buffer = buf;
    header = reinterpret_cast<struct mach_header_64*>(buffer);
    symbolTable = new SymbolTable();
    aslr_slide = slide;
    ParseMachO();
}

void MachOUserspace::WithBuffer(xnu::mach::VmAddress base_, char* buf, off_t slide) {
    buffer = buf;
    base = base_;
    header = (struct mach_header_64*)buffer;
    SetIsDyldCache(false);
    symbolTable = new SymbolTable();
    aslr_slide = slide;
    ParseMachO();
}

void MachOUserspace::WithBuffer(xnu::mach::VmAddress base_, char* buf, off_t slide,
                                bool is_dyld_cache) {
    buffer = buf;
    base = base_;
    header = (struct mach_header_64*)buffer;
    SetIsDyldCache(is_dyld_cache);
    symbolTable = new SymbolTable();
    aslr_slide = slide;
    ParseMachO();
}

void MachOUserspace::WithBuffer(MachOUserspace* libobjc, xnu::mach::VmAddress base_, char* buf,
                                off_t slide) {
    buffer = buf;
    base = base_;
    header = (struct mach_header_64*)buffer;
    SetIsDyldCache(true);
    libobjc = libobjc;
    symbolTable = new SymbolTable();
    aslr_slide = slide;
    ParseMachO();
}

void MachOUserspace::WithBuffer(char* buffer, UInt64 size) {}

MachO* MachOUserspace::LibraryLoadedAt(xnu::mach::Port task_port, char* library) {
    return nullptr;
}

UInt64 MachOUserspace::UntagPacPointer(xnu::mach::VmAddress base, enum dyld_fixup_t fixupKind,
                                       UInt64 ptr, bool* bind, bool* auth, UInt16* pac,
                                       Size* skip) {
    pacptr_t pp;
    pp.ptr = ptr;
    if (fixupKind == DYLD_CHAINED_PTR_64_KERNEL_CACHE) {
        if (bind) {
            *bind = false;
        }
        if (auth) {
            *auth = !!(pp.cache.auth && pp.cache.tag);
        }
        if (pac) {
            *pac = pp.cache.div;
        }
        if (skip) {
            *skip = pp.cache.next * sizeof(UInt32);
        }
        return base + pp.cache.target;
    }

    if (fixupKind == DYLD_CHAINED_PTR_ARM64E || fixupKind == DYLD_CHAINED_PTR_ARM64E_KERNEL) {
        if (pp.pac.bind) {
            if (bind) {
                *bind = true;
            }
        } else if (bind) {
            if (bind) {
                *bind = false;
            }
        }

        if (auth) {
            *auth = false;
        }
        if (pac) {
            *pac = 0;
        }
        if (skip) {
            *skip = pp.pac.next * sizeof(UInt32);
        }
        if (pp.pac.auth) {
            if (auth) {
                *auth = !!pp.pac.tag;
            }
            if (pac) {
                *pac = pp.pac.div;
            }
        }
        if (pp.pac.bind) {
            return pp.pac.off & 0xffff;
        }
        if (pp.pac.auth) {
            return base + pp.pac.off;
        }
        return (UInt64)pp.raw.lo;
    }
    if (bind) {
        *bind = false;
    }
    if (auth) {
        *auth = false;
    }
    if (pac) {
        *pac = 0;
    }
    if (skip) {
        *skip = 0;
    }
    return pp.ptr;
}

bool MachOUserspace::PointerIsInPacFixupChain(xnu::mach::VmAddress ptr) {
    struct mach_header_64* header;
    UInt8* q;
    UInt64 ncmds;
    UInt64 cmd_offset;
    bool bind;

    header = GetMachHeader();
    ncmds = header->ncmds;
    cmd_offset = sizeof(struct mach_header_64);
    q = (UInt8*)header + cmd_offset;
    for (int n = 0; n < ncmds; n++) {
        struct load_command* load_cmd = (struct load_command*)q;
        UInt32 cmdtype = load_cmd->cmd;
        UInt32 cmdsize = load_cmd->cmdsize;
        if (cmdtype == LC_SEGMENT_64) {
            struct segment_command_64* segcmd = (struct segment_command_64*)load_cmd;
            if (strcmp("__TEXT", segcmd->segname) == 0) {
                UInt64 sect_offset = cmd_offset + sizeof(struct segment_command_64);
                for (int j = 0; j < segcmd->nsects; j++) {
                    struct section_64* section = (struct section_64*)(q + sect_offset);
                    if (strcmp("__thread_starts", section->sectname) == 0) {
                        UInt32* start = (UInt32*)((UIntPtr)((UInt8*)header + section->offset));
                        UInt32* end = (UInt32*)((UIntPtr)start + section->size);
                        if (end > start) {
                            ++start;
                            for (; start < end; ++start) {
                                if (*start == 0xffffffff) {
                                    break;
                                }
                                UInt64* mem = (UInt64*)((UInt8*)header + *start);
                                Size skip = 0;
                                do {
                                    UInt64 ptr_tag = *mem;
                                    UInt64 ptr_tag_ptr = ((UInt64)mem - (UInt64)header) + GetBase();
                                    ptr_tag =
                                        UntagPacPointer(GetBase(), DYLD_CHAINED_PTR_ARM64E, ptr_tag,
                                                        &bind, nullptr, nullptr, &skip);
                                    if (ptr_tag_ptr == ptr) {
                                        return true;
                                    }
                                    mem = (UInt64*)((UInt64)mem + skip);
                                } while (skip > 0);
                                return false;
                            }
                        }
                        sect_offset += sizeof(struct section_64);
                    }
                }
            }
        }
        if (cmdtype == LC_DYLD_CHAINED_FIXUPS) {
            struct linkedit_data_command* data = (struct linkedit_data_command*)q;
            struct dyld_chained_fixups_header* fixup =
                (struct dyld_chained_fixups_header*)(UInt8*)header + data->dataoff;
            struct dyld_chained_starts_in_image* segs =
                (struct dyld_chained_starts_in_image*)((UIntPtr)fixup + fixup->starts_offset);
            for (UInt32 i = 0; i < segs->seg_count; ++i) {
                if (segs->seg_info_offset[i] == 0) {
                    continue;
                }
                struct dyld_chained_starts_in_segment* starts =
                    (struct dyld_chained_starts_in_segment*)((UIntPtr)segs +
                                                             segs->seg_info_offset[i]);
                UInt64 off = (UIntPtr)ptr - (UIntPtr)buffer;
                if (starts->pointer_format == DYLD_CHAINED_PTR_ARM64E_KERNEL) {
                    off = OffsetToAddress(off) - base;
                }
                if (off < starts->segment_offset ||
                    (off - starts->segment_offset) / starts->page_size >= starts->page_count) {
                    continue;
                }
                UInt16 j = (off - starts->segment_offset) / starts->page_size;
                UInt16 idx = starts->page_start[j];
                if (idx == 0xffff) {
                    continue;
                }
                Size where =
                    (Size)starts->segment_offset + (Size)j * (Size)starts->page_size + (Size)idx;
                Size skip = 0;
                UInt64* mem =
                    starts->pointer_format == DYLD_CHAINED_PTR_ARM64E_KERNEL
                        ? reinterpret_cast<UInt64*>(AddressToPointer(base + where))
                        : reinterpret_cast<UInt64*>((reinterpret_cast<UIntPtr>(buffer) + where));
                do {
                    UInt64 ptr_tag = *mem;
                    UInt64 ptr_tag_ptr = ((UInt64)mem - (UInt64)buffer) + base;
                    ptr_tag = UntagPacPointer(base, DYLD_CHAINED_PTR_ARM64E, ptr_tag, &bind,
                                              nullptr, nullptr, &skip);
                    if (ptr_tag_ptr == ptr) {
                        return true;
                    }
                    mem = (UInt64*)((UIntPtr)mem + skip);
                } while (skip > 0);
            }
            return false;
        }
        cmd_offset += cmdsize;
    }
    return false;
}

xnu::mach::VmAddress MachOUserspace::GetBufferAddress(xnu::mach::VmAddress address) {
    xnu::mach::VmAddress header = reinterpret_cast<xnu::mach::VmAddress>(GetMachHeader());
    Segment* segment = SegmentForAddress(address);
    Section* section = SectionForAddress(address);
    if (segment && !section) {
        return header + segment->GetFileOffset() + (address - segment->GetAddress());
    }
    if (!segment && !section) {
        address -= GetAslrSlide();
        segment = SegmentForAddress(address);
        section = SectionForAddress(address);
    }
    return segment && section ? header + section->GetOffset() + (address - section->GetAddress())
                              : 0;
}

void MachOUserspace::ParseSymbolTable(struct nlist_64* symtab, UInt32 nsyms, char* strtab,
                                      Size strsize) {
    for (int i = 0; i < nsyms; i++) {
        Symbol* symbol;
        struct nlist_64* nl = &symtab[i];
        char* name;
        xnu::mach::VmAddress address;
        name = &strtab[nl->n_strx];
        address = nl->n_value;
        printf("%s\n", name);
        symbol = new Symbol(this, nl->n_type & N_TYPE, name, address, AddressToOffset(address),
                            SegmentForAddress(address), SectionForAddress(address));
        symbolTable->AddSymbol(symbol);
    }
}

UInt64 MachOUserspace::ReadUleb128(UInt8* start, UInt8* end, UInt32* idx) {
    UInt64 result = 0;
    UInt8* p = start;
    int bit = 0;
    do {
        if (p == end) {
            break;
        }
        UInt64 slice = *p & 0x7F;
        if (bit > 63) {
            break;
        } else {
            result |= (slice << bit);
            bit += 0x7;
        }
        *idx = *idx + 1;

    } while (*p++ & 0x80);
    *idx = *idx - 1;
    return result;
}

Int64 MachOUserspace::ReadSleb128(UInt8* start, UInt8* end, UInt32* idx) {
    Int64 result = 0;
    UInt8* p = start;
    int bit = 0;
    UInt8 byte = 0;
    do {
        if (p == end) {
            break;
        }
        byte = *p++;
        *idx = *idx + 1;
        result |= (((Int64)(byte & 0x7F)) << bit);
        bit += 0x7;
    } while (byte & 0x90);
    *idx = *idx - 1;
    if (((byte & 0x40) != 0) && (bit < 64)) {
        result |= (~0ULL) << bit;
    }
    return result;
}

void MachOUserspace::ParseLinkedit() {}

bool MachOUserspace::ParseLoadCommands() {
    struct mach_header_64* mh = GetMachHeader();
    Size file_size;
    size = GetSize();
    file_size = size;
    UInt8* q = (UInt8*)mh + sizeof(struct mach_header_64);
    UInt32 current_offset = sizeof(struct mach_header_64);
    for (UInt32 i = 0; i < mh->ncmds; i++) {
        struct load_command* load_cmd = (struct load_command*)(*this)[current_offset];
        UInt32 cmdtype = load_cmd->cmd;
        UInt32 cmdsize = load_cmd->cmdsize;
        if (cmdsize > mh->sizeofcmds - ((UIntPtr)load_cmd - (UIntPtr)(mh + 1))) {
            return false;
        }
        switch (cmdtype) {
        case LC_LOAD_DYLIB: {
            ;
            struct dylib_command* dylib_command = (struct dylib_command*)load_cmd;
            struct dylib dylib = dylib_command->dylib;
            off_t dylib_name_offset = current_offset + reinterpret_cast<off_t>(dylib.name);
            Size dylib_name_len = cmdsize - sizeof(dylib_command);
            char* name = (char*)(*this)[dylib_name_offset];
            // printf("LC_LOAD_DYLIB - %s\n",name);
            // printf("\tVers - %u Timestamp - %u\n", dylib.current_version,dylib.timestamp);
            break;
        }

        case LC_SEGMENT_64: {
            ;
            struct segment_command_64* segment_command = (struct segment_command_64*)load_cmd;
            UInt32 nsects = segment_command->nsects;
            UInt32 sect_offset = current_offset + sizeof(struct segment_command_64);
            if (segment_command->fileoff > size ||
                segment_command->filesize > size - segment_command->fileoff) {
                return false;
            }
            printf("LC_SEGMENT_64 at 0x%llx - %s 0x%08llx to 0x%08llx \n", segment_command->fileoff,
                   segment_command->segname, segment_command->vmaddr,
                   segment_command->vmaddr + segment_command->vmsize);
            int j = 0;
            if (nsects * sizeof(struct section_64) + sizeof(struct segment_command_64) > cmdsize) {
                return false;
            }
            Segment* segment = new Segment(segment_command);
            for (j = 0; j < nsects; j++) {
                struct section_64* section = (struct section_64*)(*this)[sect_offset];
                printf("\tSection %d: 0x%08llx to 0x%08llx - %s\n", j, section->addr,
                       section->addr + section->size, section->sectname);
                if (section->offset > size || section->size > size - section->offset) {
                    return false;
                }
                sect_offset += sizeof(struct section_64);
            }
            segments.push_back(segment);
            break;
        }
        case LC_SYMTAB: {
            ;
            struct symtab_command* symtab_command = (struct symtab_command*)load_cmd;
            if (symtab_command->stroff > size || symtab_command->symoff > size ||
                symtab_command->nsyms > (size - symtab_command->symoff) / sizeof(struct nlist_64)) {
                return false;
            }
            // printf("LC_SYMTAB\n");
            // printf("\tSymbol Table is at offset 0x%x (%u) with %u entries
            // \n",symtab_command->symoff,symtab_command->symoff,symtab_command->nsyms);
            // printf("\tString Table is at offset 0x%x (%u) with size of %u
            // bytes\n",symtab_command->stroff,symtab_command->stroff,symtab_command->strsize);
            struct nlist_64* symtab = (struct nlist_64*)(*this)[symtab_command->symoff];
            UInt32 nsyms = symtab_command->nsyms;
            char* strtab = (char*)(*this)[symtab_command->stroff];
            UInt32 strsize = symtab_command->strsize;
            if (nsyms > 0) {
                ParseSymbolTable(symtab, nsyms, strtab, strsize);
            }
            break;
        }
        case LC_DYSYMTAB: {
            ;
            struct dysymtab_command* dysymtab_command = (struct dysymtab_command*)load_cmd;
            if (dysymtab_command->extreloff > size ||
                dysymtab_command->nextrel >
                    (size - dysymtab_command->extreloff) / sizeof(struct relocation_info)) {
                return false;
            }
            // printf("LC_DYSYMTAB\n");
            // printf("\t%u local symbols at index
            // %u\n",dysymtab_command->ilocalsym,dysymtab_command->nlocalsym); printf("\t%u external
            // symbols at index %u\n",dysymtab_command->nextdefsym,dysymtab_command->iextdefsym);
            // printf("\t%u undefined symbols at index
            // %u\n",dysymtab_command->nundefsym,dysymtab_command->iundefsym); printf("\t%u Indirect
            // symbols at offset
            // 0x%x\n",dysymtab_command->nindirectsyms,dysymtab_command->indirectsymoff);
            break;
        }
        case LC_UUID: {
            ;
            struct uuid_command* uuid_command = (struct uuid_command*)load_cmd;
            if (uuid_command->cmdsize != sizeof(struct uuid_command)) {
                return false;
            }
            // printf("LC_UUID\n");
            // printf("\tuuid = ");

            // for(int j = 0; j < sizeof(uuid_command->uuid); j++)
            // printf("%x", uuid_command->uuid[j]);

            // printf("\n");
            break;
        }
        case LC_FUNCTION_STARTS: {
            ;
            struct linkedit_data_command* linkedit = (struct linkedit_data_command*)load_cmd;
            UInt32 dataoff = linkedit->dataoff;
            UInt32 datasize = linkedit->datasize;
            // printf("LC_FUNCTION_STARTS\n");
            // printf("\tOffset = 0x%x Size = 0x%x\n", dataoff, datasize);
            break;
        }
        case LC_MAIN: {
            ;
            struct entry_point_command* ep = (struct entry_point_command*)load_cmd;
            // printf("LC_MAIN\n");
            // printf("\tEntry Point = 0x%llx\n", macho->base + entry_point->entryoff);
            entry_point = base + ep->entryoff;
            break;
        }
        case LC_UNIXTHREAD: {
            ;
            struct unixthread_command* thread_command = (struct unixthread_command*)load_cmd;
            // if(thread_command->flavor != ARM_THREAD_STATE64) {
            //	return false;
            // }
            break;
        }
        case LC_DYLD_INFO: {
            ;
            struct dyld_info_command* dyld_info_command = (struct dyld_info_command*)load_cmd;
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
            /* printf("LC_DYLD_INFO\n");

            if(rebase_off) {
                printf("\tRebase info: %u bytes at offset 0x%x\n", rebase_size, rebase_off);
            } else {
                printf("\tNo rebase info\n");
            }

            if(bind_off) {
                printf("\tBind info: %u bytes at offset 0x%x\n", bind_size, bind_off);
            } else {
                printf("\tNo bind info\n");
            }

            if(weak_bind_off) {
                printf("\tWeak info: %u bytes at offset 0x%x\n", weak_bind_size, weak_bind_off);
            } else {
                printf("\tNo weak info\n");
            }

            if(lazy_bind_off) {
                printf("\tLazy info: %u bytes at offset 0x%x\n", lazy_bind_size, lazy_bind_off);
            } else {
                printf("\tNo lazy info\n");
            }

            if(export_off) {
                printf("\tExport info: %u bytes at offset 0x%x\n", export_size, export_off);
            } else {
                printf("\tNo export info\n");
            }
            */
            break;
        }

        case LC_DYLD_INFO_ONLY: {
            ;
            struct dyld_info_command* dyld_info_command = (struct dyld_info_command*)load_cmd;
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
            /*
            printf("LC_DYLD_INFO_ONLY\n");

            if(rebase_off) {
                printf("\tRebase info: %u bytes at offset 0x%x\n", rebase_size, rebase_off);

                macho_parse_dyld_rebase_info(macho, rebase_off, rebase_size);
            }
            else {
                printf("\tNo rebase info\n");
            }
            if(bind_off) {
                printf("\tBind info: %u bytes at offset 0x%x\n", bind_size, bind_off);

                macho_parse_dyld_bind_info(macho, bind_off, bind_size);
            } else {
                printf("\tNo bind info\n");
            }
            if(weak_bind_off) {
                printf("\tWeak info: %u bytes at offset 0x%x\n", weak_bind_size, weak_bind_off);
                macho_parse_dyld_bind_info(macho, weak_bind_off, weak_bind_size);
            }
            else {
                printf("\tNo weak info\n");
            }
            if(lazy_bind_off) {
                printf("\tLazy info: %u bytes at offset 0x%x\n", lazy_bind_size, lazy_bind_off);
                macho_parse_dyld_bind_info(macho, lazy_bind_off, lazy_bind_size);
            }
            else {
                printf("\tNo lazy info\n");
            }
            if(export_off) {
                printf("\tExport info: %u bytes at offset 0x%x\n", export_size, export_off);
            } else {
                printf("\tNo export info\n");
            }
            */
            break;
        }
        case LC_CODE_SIGNATURE: {
            struct linkedit_data_command* linkedit = (struct linkedit_data_command*)load_cmd;
            UInt32 dataoff = linkedit->dataoff;
            UInt32 datasize = linkedit->datasize;
            // printf("LC_CODE_SIGNATURE\n");
            ParseCodeSignature(linkedit);
            break;
        }
        case LC_DATA_IN_CODE: {
            ;
            struct linkedit_data_command* linkedit = (struct linkedit_data_command*)load_cmd;
            UInt32 dataoff = linkedit->dataoff;
            UInt32 datasize = linkedit->datasize;
            // printf("LC_DATA_IN_CODE\n");
            // printf("\tOffset = 0x%x Size = 0x%x\n", dataoff, datasize);
            break;
        }
        }
        current_offset += cmdsize;
    }
    if (GetSection("__DATA_CONST", "__objc_classlist")) {
        ParseObjC();
    }
    return true;
}

void MachOUserspace::ParseFatHeader() {
    struct fat_header* fat_header = (struct fat_header*)GetMachHeader();
    struct fat_arch* arch = (struct fat_arch*)((UInt8*)fat_header + sizeof(struct fat_header));
    UInt32 nfat_arch = OSSwapBigToHostInt32(fat_header->nfat_arch);
    for (UInt32 i = 0; i < fat_header->nfat_arch; i++) {
        UInt32 cputype;
        UInt32 cpusubtype;
        UInt64 offset;
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
            struct mach_header_64* mh = (struct mach_header_64*)((UInt8*)fat_header + offset);
            buffer = reinterpret_cast<char*>(mh);
            header = mh;
            ParseHeader();
        }
        arch++;
    }
}

void MachOUserspace::ParseHeader() {
    struct mach_header_64* mh = (struct mach_header_64*)GetMachHeader();
    UInt32 magic = mh->magic;
    if (magic == FAT_CIGAM) {
        // ParseFatHeader();
        // Ignores fatHeader if we are parsing in memory MachO's that aren't dumps
    } else if (magic == MH_MAGIC_64) {
        ParseLoadCommands();
    }
}

void MachOUserspace::ParseMachO() {
    ParseHeader();
}

} // namespace darwin
