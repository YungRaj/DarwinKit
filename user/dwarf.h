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
#include <dwarf_v5.h>

#include "log.h"
#include "vector.h"
#include "binary_format.h"

namespace Binary {
class BinaryFormat;
};

namespace debug {
using namespace debug;

template <typename BinaryFormat>
struct BinaryFormatAttributes {
    using SegmentType = decltype(std::declval<BinaryFormat>()->getSegment(nullptr));
    using SectionType = decltype(std::declval<BinaryFormat>()->getSection(nullptr, nullptr));
    using SymbolType = decltype(std::declval<BinaryFormat>()->getSymbol(nullptr));
};

template <typename T>
concept HasIndexingOperator = requires(T t, UInt64 index) {
    { (*t)[index] } -> std::same_as<UInt8*>;
};

template <typename T, typename Sym>
concept HasCompatibleSymbol = std::is_same_v<Sym, decltype(std::declval<T>()->getSymbol(nullptr))>;

template <typename T, typename Seg>
concept HasCompatibleSegment =
    std::is_same_v<Seg, decltype(std::declval<T>()->getSegment(nullptr))>;

template <typename T, typename Sect>
concept HasCompatibleSect = std::is_same_v<Sect, decltype(std::declval<T>()->getSection(nullptr))>;

template <typename T, typename Sym = typename BinaryFormatAttributes<T>::SymbolType,
          typename Seg = typename BinaryFormatAttributes<T>::SegmentType,
          typename Sect = typename BinaryFormatAttributes<T>::SectionType>
concept DebuggableBinary =
    std::is_base_of_v<binary::BinaryFormat, std::remove_pointer_t<T>> && HasIndexingOperator<T>;

template <typename T>
    requires DebuggableBinary<T>
class Dwarf;

template <typename T>
    requires DebuggableBinary<T>
class CompilationUnit;

template <typename T>
    requires DebuggableBinary<T>
class DIE;

template <typename T>
    requires DebuggableBinary<T>
class LineTable;

template <typename T>
    requires DebuggableBinary<T>
class AbbreviationTable;

struct AttrSpec {
    enum DW_AT name;
    enum DW_FORM form;
};

struct AttrAbbrev {
    enum DW_TAG tag;
    enum DW_CHILDREN children;

    struct AttrSpec attr_spec;

    UInt64 code;
};

struct Attribute {
    struct AttrAbbrev abbreviation;

    UInt64 value;
};

template <typename T, typename Sym = typename BinaryFormatAttributes<T>::SymbolType,
          typename Seg = typename BinaryFormatAttributes<T>::SegmentType,
          typename Sect = typename BinaryFormatAttributes<T>::SectionType>
    requires DebuggableBinary<T, Sym, Seg>
Dwarf<T>* parseDebugSymbols(T binary);

template <typename T, typename Sym = typename BinaryFormatAttributes<T>::SymbolType,
          typename Seg = typename BinaryFormatAttributes<T>::SegmentType,
          typename Sect = typename BinaryFormatAttributes<T>::SectionType>
    requires DebuggableBinary<T, Sym, Seg>
Dwarf<T>* parseDebugSymbols(T binary, const char* dSYM);

template <typename T>
    requires DebuggableBinary<T>
class DIE {
public:
    explicit DIE(Dwarf<T>* dwarf, UInt64 code, char* name, enum DW_TAG tag,
                 enum DW_CHILDREN has_children);

    enum DW_TAG getTag() {
        return tag;
    }
    enum DW_CHILDREN getHasChildren() {
        return has_children;
    }

    UInt64 getCode() {
        return code;
    }

    Size getAttributesCount() {
        return abbreviationTable.size();
    }

    struct AttrAbbrev* getAttribute(enum DW_AT attr);
    struct AttrAbbrev* getAttribute(int index) {
        return abbreviationTable.at(index);
    }

    char* getName() {
        return name;
    }

    Offset getOffset() {
        return offset;
    }

    void setOffset(Offset offset) {
        offset = offset;
    }

    struct AttrAbbrev* getAbbreviation(int index) {
        return abbreviationTable.at(index);
    }
    struct AttrAbbrev* getAbbreviation(enum DW_AT attr);

    void addAbbreviation(struct AttrAbbrev* abbreviation) {
        abbreviationTable.push_back(abbreviation);
    }
    void removeAbbreviation(struct AttrAbbrev* abbreviation) {
        abbreviationTable.erase(
            std::remove(abbreviationTable.begin(), abbreviationTable.end(), abbreviation),
            abbreviationTable.end());
    }

private:
    Dwarf<T>* dwarf;

    UInt64 code;

    std::vector<struct AttrAbbrev*> abbreviationTable;

    enum DW_TAG tag;

    enum DW_CHILDREN has_children;

    char* name;

    DIE<T>* parent;

    UInt32 idx;
    UInt32 sibling_idx;
    UInt32 parent_idx;

    Offset offset;
};

template <typename T>
    requires DebuggableBinary<T>
class DwarfDIE {
public:
    explicit DwarfDIE(Dwarf<T>* dwarf, CompilationUnit<T>* unit, DIE<T>* die, DwarfDIE<T>* parent);

    Dwarf<T>* getDwarf() {
        return dwarf;
    }

    DIE<T>* getDebugInfoEntry() {
        return die;
    }

    enum DW_TAG getTag() {
        return die->getTag();
    }
    enum DW_CHILDREN hasChildren() {
        return die->getHasChildren();
    }

    DwarfDIE<T>* getParent() {
        return parent;
    }

    std::vector<DwarfDIE<T>*>& getChildren() {
        return children;
    }

    std::vector<struct Attribute*>& getAttributes() {
        return attributes;
    }

    void addChild(DwarfDIE<T>* child) {
        children.push_back(child);
    }
    void removeChild(DwarfDIE<T>* child) {
        children.erase(std::remove(children.begin(), children.end(), child), children.end());
    }

    void addAttribute(struct Attribute* attribute) {
        attributes.push_back(attribute);
    }
    void addAttributes(std::vector<struct Attribute*>& attrs) {
        for (int i = 0; i < attrs.size(); i++)
            attributes.push_back(attrs.at(i));
    }

    struct Attribute* getAttribute(enum DW_AT attr);
    struct Attribute* getAttribute(int index) {
        return attributes.at(index);
    }

    UInt64 getAttributeValue(enum DW_AT attr);

private:
    Dwarf<T>* dwarf;

    CompilationUnit<T>* compilationUnit;

    DIE<T>* die;

    DwarfDIE<T>* parent;

    std::vector<DwarfDIE*> children;
    std::vector<struct Attribute*> attributes;
};

#pragma pack(1)

struct CompileUnitHeader {
    UInt32 length;
    UInt16 format;
    UInt16 version;
    UInt16 abbr_offset;
    UInt8 addr_size;
};

#pragma options align = reset

template <typename T>
    requires DebuggableBinary<T>
class CompilationUnit {
public:
    explicit CompilationUnit(Dwarf<T>* dwarf, struct CompileUnitHeader* hdr, DIE<T>* die);

    std::vector<DwarfDIE<T>*>& getDebugInfoEntries() {
        return debugInfoEntries;
    }

    Dwarf<T>* getDwarf() {
        return dwarf;
    }

    LineTable<T>* getLineTable() {
        return lineTable;
    }

    char* getSourceFileName() {
        return source_file;
    }

    void addDebugInfoEntry(DwarfDIE<T>* dwarfDIE) {
        debugInfoEntries.push_back(dwarfDIE);
    }

private:
    Dwarf<T>* dwarf;

    DIE<T>* die;

    struct CompileUnitHeader* header;

    std::vector<DwarfDIE<T>*> debugInfoEntries;

    LineTable<T>* lineTable;

    char* source_file;
    char* source_language;

    UInt16 dwarf_version;

    UInt8 unit_type;
    UInt64 dwo_id;

    UInt64 unit_type_signature;
    UInt64 unit_type_offset;

    xnu::Mach::VmAddress address_base = 0;
    xnu::Mach::VmAddress str_offsets_base = 0;
    xnu::Mach::VmAddress range_lists_base = 0;
};

#pragma pack(1)

struct LTPrologue {
    UInt32 total_length;
    UInt8 format;
    UInt8 version;
    UInt32 prologue_length;
    UInt8 min_inst_length;
    UInt8 max_ops_per_inst;
    UInt8 default_is_stmt;
    Int8 line_base;
    UInt8 line_range;
    UInt8 opcode_base;
};

struct LTStandardOpcodeLengths {
    DW_LNS copy;
    DW_LNS advance_pc;
    DW_LNS advance_line;
    DW_LNS set_file;
    DW_LNS set_column;
    DW_LNS negate_stmt;
    DW_LNS set_basic_block;
    DW_LNS const_add_pc;
    DW_LNS fixed_advance_pc;
    DW_LNS set_prologue_end;
    DW_LNS set_epilogue_begin;
    DW_LNS set_isa;
};

struct LTSourceFileMetadata {
    UInt8 dir_index;
    UInt8 mod_time;
    UInt8 length;
};

#pragma options align = reset

struct LTSourceFile {
    char* source_file;

    struct LTSourceFileMetadata metadata;
};

struct LTStateMachine {
    xnu::Mach::VmAddress address;

    UInt8 isa;
    Int64 line;
    UInt64 column;
    UInt16 file;
    UInt32 discriminator;

    UInt8 statement : 1, basic_block : 1, end_sequence : 1, prologue_end : 1, epilogue_begin : 1;
};

struct LTSourceLine {
    struct LTSourceFile* source_file;

    struct LTStateMachine state;
};

struct Sequence {
    UInt64 LowPC;
    UInt64 HighPC;

    Segment* segment;
    Section* section;

    std::vector<LTSourceLine*> sourceLines;
};

static LTStateMachine gInitialState = {.address = 0,
                                       .isa = 0,
                                       .line = 1,
                                       .column = 1,
                                       .file = 1,
                                       .discriminator = 1,
                                       .statement = 1,
                                       .basic_block = 0,
                                       .end_sequence = 0,
                                       .prologue_end = 0,
                                       .epilogue_begin = 0};

template <typename T>
    requires DebuggableBinary<T>
class LineTable {
public:
    explicit LineTable(T binary, Dwarf<T>* dwarf) : binary(binary), dwarf(dwarf) {}

    std::vector<struct LTSourceFile*>& getSourceFileNames() {
        return files;
    }
    std::vector<char*>& getIncludeDirectories() {
        return include_directories;
    }

    CompilationUnit<T>* getCompilationUnit() {
        return compilationUnit;
    }

    LTSourceLine* getSourceLine(xnu::Mach::VmAddress pc);

    LTSourceFile* getSourceFile(int index) {
        return files.at(index);
    }

    void setCompilationUnit(CompilationUnit<T>* cu) {
        compilationUnit = cu;
    }

    void setPrologue(struct LTPrologue* p) {
        memcpy(&prologue, p, sizeof(struct LTPrologue));
    }

    void setStandardOpcodeLengths(struct LTStandardOpcodeLengths* opcodes) {
        memcpy(&standardOpcodeLengths, opcodes, sizeof(struct LTStandardOpcodeLengths));
    }

    void addSequence(Sequence* sequence) {
        sources.push_back(sequence);
    }
    void addSourceFile(struct LTSourceFile* file) {
        files.push_back(file);
    }
    void addIncludeDirectory(char* directory) {
        include_directories.push_back(directory);
    }

private:
    T binary;

    Dwarf<T>* dwarf;

    struct LTPrologue prologue;

    struct LTStandardOpcodeLengths standardOpcodeLengths;

    CompilationUnit<T>* compilationUnit;

    std::vector<Sequence*> sources;

    std::vector<char*> include_directories;
    std::vector<struct LTSourceFile*> files;
};

struct LocationTableEntry {
    DW_LLE kind;

    UInt32 offset;

    UInt64 value0;
    UInt64 value1;

    Segment* segment;

    std::vector<DW_OP> location_ops;
};

#pragma pack(1)

struct AddressRange {
    xnu::Mach::VmAddress start;
    xnu::Mach::VmAddress end;
};

struct AddressRangeHeader {
    UInt32 length;
    UInt16 version;
    UInt32 offset;
    UInt8 addr_size;
    UInt8 seg_size;
};

struct AddressRangeEntry {
    struct AddressRangeHeader header;

    std::vector<struct AddressRange*> ranges;
};

struct RangeEntry {
    UInt32 offset;

    UInt64 value0;
    UInt64 value1;
};

using RangeEntries = std::vector<struct RangeEntry*>;

#pragma options align = reset

template <typename T>
    requires DebuggableBinary<T>
class Dwarf {
public:
    using Seg = typename BinaryFormatAttributes<T>::SegmentType;
    using Sect = typename BinaryFormatAttributes<T>::SectionType;
    using Sym = typename BinaryFormatAttributes<T>::SymbolType;

    explicit Dwarf(const char* debugSymbols);
    explicit Dwarf(T binary, const char* debugSymbols);

    CompilationUnit<T> getCompilationUnit(const char* source_file);

    DIE<T>* getDebugInfoEntryByName(const char* name);
    DIE<T>* getDebugInfoEntryByCode(UInt64 code);

    Seg getDwarfSegment() {
        return dwarf;
    }

    Sect getDebugLine() {
        return __debug_line;
    }
    Sect getDebugLoc() {
        return __debug_loc;
    }
    Sect getDebugAranges() {
        return __debug_aranges;
    }
    Sect getDebugInfo() {
        return __debug_info;
    }
    Sect getDebugAbbrev() {
        return __debug_abbrev;
    }
    Sect getDebugStr() {
        return __debug_str;
    }

    Sect getAppleNames() {
        return __apple_names;
    }
    Sect getAppleNamespac() {
        return __apple_namespac;
    }
    Sect getAppleTypes() {
        return __apple_types;
    }
    Sect getAppleObjc() {
        return __apple_objc;
    }

    std::vector<CompilationUnit<T>*>& getCompilationUnits() {
        return compilationUnits;
    }
    std::vector<LineTable<T>*>& getLineTables() {
        return lineTables;
    }

    LineTable<T>* getLineTable(const char* name);
    LineTable<T>* getLineTable(CompilationUnit<T>* unit);

    DIE<T>* getUnit(const char* name);
    DIE<T>* getFunction(const char* name);
    DIE<T>* getType(const char* name);

    void populateDebugSymbols();

    void parseDebugAbbrev();
    void parseDebugInfo();
    void parseDebugLocations();
    void parseDebugLines();
    void parseDebugRanges();
    void parseDebugAddressRanges();

    const char* getSourceFile(xnu::Mach::VmAddress instruction);

    Int64 getSourceLineNumber(xnu::Mach::VmAddress instruction);

private:
    T binary;

    T binaryWithDebugSymbols;

    std::vector<DIE<T>*> dies;
    std::vector<CompilationUnit<T>*> compilationUnits;

    std::vector<LineTable<T>*> lineTables;

    std::vector<struct LocationTableEntry*> locationTable;

    std::vector<RangeEntries*> ranges;
    std::vector<struct AddressRangeEntry*> addressRanges;

    Seg dwarf;

    Sect __debug_line;
    Sect __debug_loc;
    Sect __debug_aranges;
    Sect __debug_info;
    Sect __debug_ranges;
    Sect __debug_abbrev;
    Sect __debug_str;
    Sect __apple_names;
    Sect __apple_namespac;
    Sect __apple_types;
    Sect __apple_objc;
};

UInt64 GetStringSize(UInt8* p);

UInt64 ReadUleb128(UInt8* p, UInt8* end);
UInt64 ReadUleb128(UInt8* p, UInt8* end, UInt32* idx);

Int64 ReadSleb128(UInt8* p, UInt8* end);
Int64 ReadSleb128(UInt8* p, UInt8* end, UInt32* idx);
}; // namespace debug
