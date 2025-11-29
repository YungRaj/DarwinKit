/*
 * Copyright (c) YungRaj
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; Without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along With this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include <types.h>
#include <vector>

#include "macho.h"
#include "symbol_table.h"

#include "objc.h"
#include "swift.h"

#include "dyld.h"

extern "C" {
#include <mach-o.h>
}

class Segment;
class Section;

namespace dyld {
class Dyld;
class Library;
}; // namespace dyld

namespace objc {
class ObjCData;
};

namespace xnu {
class Task;
};

namespace darwin {
class CodeSignature {
public:
    explicit CodeSignature(MachOUserspace* macho, struct linkedit_data_command* cmd)
        : macho(macho), cmd(cmd) {
        ParseCodeSignature();
    }

    ~CodeSignature() = default;

    static CodeSignature* CodeSignatureWithLinkedit(MachOUserspace* macho,
                                                    struct linkedit_data_command* cmd);

    MachOUserspace* GetMachO() {
        return macho;
    }

    struct linkedit_data_command* GetLoadCommand() {
        return cmd;
    }

    SuperBlob* GetSuperBlob() {
        return superBlob;
    }

    code_directory_t GetCodeDirectory() {
        return codeDirectory;
    }

    char* GetEntitlements() {
        return entitlements;
    }

    bool VerifyCodeSlot(UInt8* blob, Size size, bool sha256, char* signature, Size sigsize);

    bool CompareHash(UInt8* hash1, UInt8* hash2, Size hashSize);

    UInt8* ComputeHash(bool sha256, UInt8* blob, Size size);

    bool ParseCodeSignature();

private:
    MachOUserspace* macho;
    SuperBlob* superBlob;

    code_directory_t codeDirectory;
    struct linkedit_data_command* cmd;
    char* entitlements;
};

class MachOUserspace : public MachO {
public:
    explicit MachOUserspace() : task(nullptr), file_path(nullptr) {}
    explicit MachOUserspace(const char* path);

    ~MachOUserspace() = default;

    virtual void WithTask(xnu::Task* task);
    virtual void WithFilePath(const char* path);

    virtual void WithBuffer(char* buffer);
    virtual void WithBuffer(char* buffer, Offset slide);
    virtual void WithBuffer(char* buffer, UInt64 size);

    virtual void WithBuffer(xnu::mach::VmAddress base, char* buffer, Offset slide);
    virtual void WithBuffer(xnu::mach::VmAddress base, char* buffer, Offset slide,
                            bool is_dyld_cache);

    virtual void WithBuffer(darwin::MachOUserspace* libobjc, xnu::mach::VmAddress base, char* buffer,
                            Offset slide);

    char* GetFilePath() {
        return dyld ? dyld->GetMainImagePath() : file_path;
    }

    bool IsDyldCache() {
        return is_dyldCache;
    }

    void  SetIsDyldCache(bool IsDyldCache) {
        is_dyldCache = IsDyldCache;
    }

    MachOUserspace* GetObjectiveCLibrary() {
        return libobjc;
    }

    objc::ObjCData* GetObjCMetadata() {
        return objc;
    }

    bool IsObjectiveCLibrary() {
        return is_libobjc;
    }

    void SetIsObjectiveCLibrary(bool objc) {
        is_libobjc = objc;
    }

    void SetObjectiveCLibrary(MachOUserspace* objc) {
        libobjc = objc;
    }

    static MachO* TaskAt(xnu::mach::Port task);
    static MachO* LibraryLoadedAt(xnu::mach::Port task, char* library);

    static UInt64 UntagPacPointer(xnu::mach::VmAddress base, enum dyld_fixup_t fixupKind,
                                  UInt64 ptr, bool* bind, bool* auth, UInt16* pac, Size* skip);

    bool PointerIsInPacFixupChain(xnu::mach::VmAddress ptr);

    xnu::mach::VmAddress GetBufferAddress(xnu::mach::VmAddress address);

    virtual void ParseMachO() override;

    virtual void ParseHeader() override;

    virtual void ParseFatHeader() override;

    virtual void ParseSymbolTable(struct nlist_64* symtab, UInt32 nsyms, char* strtab,
                                  Size strsize) override;

    virtual void ParseLinkedit() override;

    virtual bool ParseLoadCommands() override;

    inline void ParseCodeSignature(struct linkedit_data_command* cmd) {
        codeSignature = CodeSignature::CodeSignatureWithLinkedit(this, cmd);
    }

    inline void ParseObjC() {
        objc = objc::ParseObjectiveC(this);
    }

    inline void ParseSwift() {
        swift = swift::ParseSwift(this);
    }

    UInt8* operator[](UInt64 index) {
        return GetOffset(index);
    }

private:
    xnu::Task* task;
    darwin::MachOUserspace* libobjc;
    darwin::dyld::Dyld* dyld;
    darwin::CodeSignature* codeSignature;
    objc::ObjCData* objc;
    swift::SwiftABI* swift;

    xnu::mach::VmAddress dyld_base;
    xnu::mach::VmAddress dyld_shared_cache;

    char* file_path;
    bool is_dyldCache;
    bool is_libobjc;

    UInt64 ReadUleb128(UInt8* start, UInt8* end, UInt32* idx);
    Int64 ReadSleb128(UInt8* start, UInt8* end, UInt32* idx);
};
} // namespace darwin
