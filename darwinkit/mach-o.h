#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <architecture/byte_order.h>

#include <sys/_types/_uuid_t.h>

#ifdef __USER__

typedef uint32_t mach_port_t;

#endif

#define LC_REQ_DYLD 0x80000000

#define FAT_CIGAM 0xbebafeca
#define MH_MAGIC_64 0xfeedfacf

#define MH_EXECUTE 0x00000002
#define MH_KEXT_BUNDLE 0x0000000b
#define MH_FILESET 0x0000000c

#define LC_SYMTAB 0x00000002
#define LC_UNIXTHREAD 0x00000005
#define LC_LOAD_DYLIB 0x0000000c
#define LC_DYSYMTAB 0x0000000b
#define LC_SEGMENT_64 0x00000019
#define LC_UUID 0x0000001b
#define LC_CODE_SIGNATURE 0x0000001d
#define LC_ENCRYPTION_INFO 0x00000021
#define LC_DYLD_INFO 0x00000022
#define LC_DYLD_INFO_ONLY (0x00000022 | LC_REQ_DYLD)
#define LC_FUNCTION_STARTS 0x00000026
#define LC_MAIN (0x28 | LC_REQ_DYLD)
#define LC_DATA_IN_CODE 0x00000029
#define LC_DYLD_CHAINED_FIXUPS (0x00000034 | LC_REQ_DYLD)
#define LC_FILESET_ENTRY (0x00000035 | LC_REQ_DYLD)

#define N_STAB 0xe0
#define N_PEXT 0x10
#define N_TYPE 0x0e
#define N_EXT 0x01

#define N_UNDF 0x0
#define N_ABS 0x2
#define N_SECT 0xe
#define N_PBUD 0xc
#define N_INDR 0xa

#define REBASE_TYPE_POINTER 1
#define REBASE_TYPE_TEXT_ABSOLUTE32 2
#define REBASE_TYPE_TEXT_PCREL32 3

#define REBASE_OPCODE_MASK 0xF0
#define REBASE_IMMEDIATE_MASK 0x0F
#define REBASE_OPCODE_DONE 0x00
#define REBASE_OPCODE_SET_TYPE_IMM 0x10
#define REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB 0x20
#define REBASE_OPCODE_ADD_ADDR_ULEB 0x30
#define REBASE_OPCODE_ADD_ADDR_IMM_SCALED 0x40
#define REBASE_OPCODE_DO_REBASE_IMM_TIMES 0x50
#define REBASE_OPCODE_DO_REBASE_ULEB_TIMES 0x60
#define REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB 0x70
#define REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB 0x80

#define BIND_TYPE_POINTER 1
#define BIND_TYPE_TEXT_ABSOLUTE32 2
#define BIND_TYPE_TEXT_PCREL32 3

#define BIND_SPECIAL_DYLIB_SELF 0
#define BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE -1
#define BIND_SPECIAL_DYLIB_FLAT_LOOKUP -2
#define BIND_SPECIAL_DYLIB_WEAK_LOOKUP -3

#define BIND_SYMBOL_FLAGS_WEAK_IMPORT 0x1
#define BIND_SYMBOL_FLAGS_NON_WEAK_DEFINITION 0x8

#define BIND_OPCODE_MASK 0xF0
#define BIND_IMMEDIATE_MASK 0x0F
#define BIND_OPCODE_DONE 0x00
#define BIND_OPCODE_SET_DYLIB_ORDINAL_IMM 0x10
#define BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB 0x20
#define BIND_OPCODE_SET_DYLIB_SPECIAL_IMM 0x30
#define BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM 0x40
#define BIND_OPCODE_SET_TYPE_IMM 0x50
#define BIND_OPCODE_SET_ADDEND_SLEB 0x60
#define BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB 0x70
#define BIND_OPCODE_ADD_ADDR_ULEB 0x80
#define BIND_OPCODE_DO_BIND 0x90
#define BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB 0xA0
#define BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED 0xB0
#define BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB 0xC0
#define BIND_OPCODE_THREADED 0xD0
#define BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB 0x00
#define BIND_SUBOPCODE_THREADED_APPLY 0x01

#define EXPORT_SYMBOL_FLAGS_KIND_MASK 0x03
#define EXPORT_SYMBOL_FLAGS_KIND_REGULAR 0x00
#define EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL 0x01
#define EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE 0x02
#define EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION 0x04
#define EXPORT_SYMBOL_FLAGS_REEXPORT 0x08
#define EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER 0x10

#define CSMAGIC_REQUIREMENT 0xfade0c00
#define CSMAGIC_REQUIREMENTS 0xfade0c01
#define CSMAGIC_CODEDIRECTORY 0xfade0c02
#define CSMAGIC_EMBEDDED_SIGNATURE 0xfade0cc0
#define CSMAGIC_EMBEDDED_SIGNATURE_OLD 0xfade0b02
#define CSMAGIC_EMBEDDED_ENTITLEMENTS 0xfade7171
#define CSMAGIC_DETACHED_SIGNATURE 0xfade0cc1
#define CSMAGIC_BLOBWRAPPER 0xfade0b01

#define CSSLOT_CODEDIRECTORY 0x00000
#define CSSLOT_INFOSLOT 0x00001
#define CSSLOT_REQUIREMENTS 0x00002
#define CSSLOT_RESOURCEDIR 0x00003
#define CSSLOT_APPLICATION 0x00004
#define CSSLOT_ENTITLEMENTS 0x00005

#define CSSLOT_SIGNATURESLOT 0x10000

#define HASH_TYPE_SHA1 0x01
#define HASH_TYPE_SHA256 0x02

struct fat_header {
    uint32_t magic;
    uint32_t nfat_arch;
};

struct fat_arch {
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t offset;
    uint32_t size;
    uint32_t align;
};

struct mach_header_64 {
    uint32_t magic;
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
    uint32_t reserved;
};

struct load_command {
    uint32_t cmd;
    uint32_t cmdsize;
};

struct segment_command_64 {
    uint32_t cmd;
    uint32_t cmdsize;
    char segname[16];
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
    uint32_t maxprot;
    uint32_t initprot;
    uint32_t nsects;
    uint32_t flags;
};

struct section_64 {
    char sectname[16];
    char segname[16];
    uint64_t addr;
    uint64_t size;
    uint32_t offset;
    uint32_t align;
    uint32_t reloff;
    uint32_t nreloc;
    uint32_t flags;
    uint32_t reserved1;
    uint32_t reserved2;
    uint32_t reserved3;
};

struct fileset_entry_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint64_t vmaddr;
    uint64_t fileoff;
    uint32_t entry_id;
    uint32_t reserved;
};

struct symtab_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t symoff;
    uint32_t nsyms;
    uint32_t stroff;
    uint32_t strsize;
};

struct dysymtab_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t ilocalsym;
    uint32_t nlocalsym;
    uint32_t iextdefsym;
    uint32_t nextdefsym;
    uint32_t iundefsym;
    uint32_t nundefsym;
    uint32_t tocoff;
    uint32_t ntoc;
    uint32_t modtaboff;
    uint32_t nmodtab;
    uint32_t extrefsymoff;
    uint32_t nextrefsyms;
    uint32_t indirectsymoff;
    uint32_t nindirectsyms;
    uint32_t extreloff;
    uint32_t nextrel;
    uint32_t locreloff;
    uint32_t nlocrel;
};

struct relocation_info {
    int32_t r_address;
    uint32_t r_symbolnum : 24, r_pcrel : 1, r_length : 2, r_extern : 1, r_type : 4;
};

struct linkedit_data_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t dataoff;
    uint32_t datasize;
};

struct encryption_info_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t cryptoff;
    uint32_t cryptsize;
    uint32_t cryptid;
};

struct entry_point_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint64_t entryoff;
    uint64_t stacksize;
};

struct unixthread_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t flavor;
    uint32_t count;
};

struct uuid_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint8_t uuid[16];
};

#ifdef __USER__

struct dylib {
    char* name;
    uint32_t timestamp;
    uint32_t current_version;
    uint32_t compatibility_version;
};

struct dylib_command {
    uint32_t cmd;
    uint32_t cmdsize;

    struct dylib dylib;
};

struct dyld_info_command {
    uint32_t cmd;
    uint32_t cmdsize;

    uint32_t rebase_off;
    uint32_t rebase_size;

    uint32_t bind_off;
    uint32_t bind_size;

    uint32_t weak_bind_off;
    uint32_t weak_bind_size;

    uint32_t lazy_bind_off;
    uint32_t lazy_bind_size;

    uint32_t export_off;
    uint32_t export_size;
};

struct dylib_table_of_contents {
    uint32_t symbol_index;
    uint32_t module_index;
};

struct dylib_module_64 {
    uint32_t module_name;

    uint32_t iextdefsym;
    uint32_t nextdefsym;
    uint32_t irefsym;
    uint32_t nrefsym;
    uint32_t ilocalsym;
    uint32_t nlocalsym;

    uint32_t iextrel;
    uint32_t nextrel;

    uint32_t iinit_iterm;

    uint32_t ninit_nterm;

    uint32_t objc_module_info_size;
    uint64_t objc_module_info_addr;
};

struct dylib_reference {
    uint32_t isym : 24, flags : 8;
};

typedef union {
    uint64_t ptr;

    struct {
        int64_t lo : 51, hi : 13;
    } raw;

    struct {
        uint64_t off : 32, div : 16, tag : 1, dkey : 1, bkey : 1, next : 11, bind : 1, auth : 1;
    } pac;

    struct {
        uint64_t target : 30, cache : 2, div : 16, tag : 1, dkey : 1, bkey : 1, next : 12, auth : 1;
    } cache;

} pacptr_t;

enum dyld_fixup_t {
    DYLD_CHAINED_PTR_NONE = 0,            // pacptr.raw
    DYLD_CHAINED_PTR_ARM64E = 1,          // pacptr.pac
    DYLD_CHAINED_PTR_ARM64E_KERNEL = 7,   // pacptr.cache, virt offset from kernel base
    DYLD_CHAINED_PTR_64_KERNEL_CACHE = 8, // pacptr.cache, file offset
};

struct dyld_chained_fixups_header {
    uint32_t fixups_version;
    uint32_t starts_offset;
    uint32_t imports_offset;
    uint32_t symbols_offset;
    uint32_t imports_count;
    uint32_t imports_format;
    uint32_t symbols_format;
};

struct dyld_chained_starts_in_image {
    uint32_t seg_count;
    uint32_t seg_info_offset[];
};

struct dyld_chained_starts_in_segment {
    uint32_t size;
    uint16_t page_size;
    uint16_t pointer_format;
    uint64_t segment_offset;
    uint32_t max_valid_pointer;
    uint16_t page_count;
    uint16_t page_start[];
};

struct dyld_chained_import {
    uint32_t lib_ordinal : 8, weak_import : 1, name_offset : 23;
};

enum dyld_image_mode { dyld_image_adding = 0, dyld_image_removing = 1 };

#endif

struct dyld_image_info {
    const struct mach_header* imageLoadAddress;
    const char* imageFilePath;
    uintptr_t imageFileModDate;
};

#ifdef __USER__

struct dyld_uuid_info {
    const struct mach_header* imageLoadAddress;
    uuid_t imageUUID;
};

typedef void (*dyld_image_notifier)(enum dyld_image_mode mode, uint32_t infoCount,
                                    const struct dyld_image_info info[]);

enum {
    dyld_error_kind_none = 0,
    dyld_error_kind_dylib_missing = 1,
    dyld_error_kind_dylib_wrong_arch = 2,
    dyld_error_kind_dylib_version = 3,
    dyld_error_kind_symbol_missing = 4
};

#define DYLD_MAX_PROCESS_INFO_NOTIFY_COUNT 8

struct dyld_all_image_infos {
    uint32_t version;
    uint32_t infoArrayCount;
    const struct dyld_image_info* infoArray;
    dyld_image_notifier notification;
    bool processDetachedFromSharedRegion;

    bool libSystemInitialized;
    const struct mach_header* dyldImageLoadAddress;

    void* jitInfo;

    const char* dyldVersion;
    const char* errorMessage;
    uintptr_t terminationFlags;

    void* coreSymbolicationShmPage;

    uintptr_t systemOrderFlag;

    uintptr_t uuidArrayCount;
    const struct dyld_uuid_info* uuidArray;

    struct dyld_all_image_infos* dyldAllImageInfosAddress;

    uintptr_t initialImageCount;

    uintptr_t errorKind;
    const char* errorClientOfDylibPath;
    const char* errorTargetDylibPath;
    const char* errorSymbol;

    uintptr_t sharedCacheSlide;
    uint8_t sharedCacheUUID[16];

    uintptr_t sharedCacheBaseAddress;
    uint64_t infoArrayChangeTimestamp;
    const char* dyldPath;
    mach_port_t notifyPorts[DYLD_MAX_PROCESS_INFO_NOTIFY_COUNT];
#if __LP64__
    uintptr_t reserved[13 - (DYLD_MAX_PROCESS_INFO_NOTIFY_COUNT / 2)];
#else
    uintptr_t reserved[12 - DYLD_MAX_PROCESS_INFO_NOTIFY_COUNT];
#endif
};

extern struct dyld_all_image_infos dyld_all_image_infos;

#define DYLD_ALL_IMAGE_INFOS_OFFSET_OFFSET 0x1010

extern struct dyld_shared_cache_ranges dyld_shared_cache_ranges;

#endif

struct nlist_64 {
    uint32_t n_strx;
    uint8_t n_type;
    uint8_t n_sect;
    uint16_t n_desc;
    uint64_t n_value;
};

extern void swap_fat_header(struct fat_header* fat_header, enum NXByteOrder target_byte_order);

extern void swap_fat_arch(struct fat_arch* fat_archs, unsigned long nfat_arch,
                          enum NXByteOrder target_byte_order);

extern void swap_mach_header(struct mach_header* mh, enum NXByteOrder target_byte_order);

extern void swap_load_command(struct load_command* lc, enum NXByteOrder target_byte_order);

extern void swap_symtab_command(struct symtab_command* st, enum NXByteOrder target_byte_order);

extern void swap_dysymtab_command(struct dysymtab_command* dyst, enum NXByteOrder target_byte_sex);

typedef struct {
    uint32_t type;
    uint32_t offset;
} BlobIndex;

typedef struct Blob {
    uint32_t magic;
    uint32_t length;
} Blob;

typedef struct {
    Blob blob;
    uint32_t count;
    BlobIndex index[];
} SuperBlob;

typedef struct code_directory {
    struct Blob blob;
    uint32_t version;
    uint32_t flags;
    uint32_t hashOffset;
    uint32_t identOffset;
    uint32_t nSpecialSlots;
    uint32_t nCodeSlots;
    uint32_t codeLimit;
    uint8_t hashSize;
    uint8_t hashType;
    uint8_t spare1;
    uint8_t pageSize;
    uint32_t spare2;
    uint32_t scatterOffset;
}* code_directory_t;

enum { ENTITLEMENTS, APPLICATION_SPECIFIC, RESOURCE_DIR, REQUIREMENTS_BLOB, BOUND_INFO_PLIST };

typedef struct {
    char* name;

    uint8_t* data;

    uint8_t* hash;
    uint32_t hashSize;

    bool sha256;
} special_slot;

static special_slot special_slots[5] = {{"Entitlements.plist", nullptr, nullptr},
                                        {"Application Specific", nullptr, nullptr},
                                        {"Resource Directory", nullptr, nullptr},
                                        {"Requirements Blob", nullptr, nullptr},
                                        {"Bound Info.plist", nullptr, nullptr}};
