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

#include "dwarf.h"
#include "kernel.h"
#include "kernel_macho.h"

#include <string.h>

using namespace debug;

char* DWTagToString(enum DW_TAG tag) {
    switch (tag) {
    case DW_TAG::array_type:
        return "array_type";
    case DW_TAG::class_type:
        return "class_type";
    case DW_TAG::entry_point:
        return "entry_point";
    case DW_TAG::enumeration_type:
        return "enumeration_type";
    case DW_TAG::formal_parameter:
        return "formal_parameter";
    case DW_TAG::imported_declaration:
        return "imported_declaration";
    case DW_TAG::label:
        return "label";
    case DW_TAG::lexical_block:
        return "lexical_block";
    case DW_TAG::member:
        return "member";
    case DW_TAG::pointer_type:
        return "pointer_type";
    case DW_TAG::reference_type:
        return "reference_type";
    case DW_TAG::compile_unit:
        return "compile_unit";
    case DW_TAG::string_type:
        return "string_type";
    case DW_TAG::structure_type:
        return "structure_type";
    case DW_TAG::subroutine_type:
        return "subroutine_type";
    case DW_TAG::typedef_:
        return "typedef_";
    case DW_TAG::union_type:
        return "union_type";
    case DW_TAG::unspecified_parameters:
        return "unspecified_parameters";
    case DW_TAG::variant:
        return "variant";
    case DW_TAG::common_block:
        return "common_block";
    case DW_TAG::common_inclusion:
        return "common_inclusion";
    case DW_TAG::inheritance:
        return "inheritance";
    case DW_TAG::inlined_subroutine:
        return "inlined_subroutine";
    case DW_TAG::module:
        return "module";
    case DW_TAG::ptr_to_member_type:
        return "ptr_to_member_type";
    case DW_TAG::set_type:
        return "set_type";
    case DW_TAG::subrange_type:
        return "subrange_type";
    case DW_TAG::with_stmt:
        return "with_stmt";
    case DW_TAG::access_declaration:
        return "access_declaration";
    case DW_TAG::base_type:
        return "base_type";
    case DW_TAG::catch_block:
        return "catch_block";
    case DW_TAG::const_type:
        return "const_type";
    case DW_TAG::constant:
        return "constant";
    case DW_TAG::enumerator:
        return "enumerator";
    case DW_TAG::file_type:
        return "file_type";
    case DW_TAG::friend_:
        return "friend_";
    case DW_TAG::namelist:
        return "namelist";
    case DW_TAG::namelist_item:
        return "namelist_item";
    case DW_TAG::packed_type:
        return "packed_type";
    case DW_TAG::subprogram:
        return "subprogram";
    case DW_TAG::template_type_parameter:
        return "template_type_parameter";
    case DW_TAG::template_value_parameter:
        return "template_value_parameter";
    case DW_TAG::thrown_type:
        return "thrown_type";
    case DW_TAG::try_block:
        return "try_block";
    case DW_TAG::variant_part:
        return "variant_part";
    case DW_TAG::variable:
        return "variable";
    case DW_TAG::volatile_type:
        return "volatile_type";
    case DW_TAG::dwarf_procedure:
        return "dwarf_procedure";
    case DW_TAG::restrict_type:
        return "restrict_type";
    case DW_TAG::interface_type:
        return "interface_type";
    case DW_TAG::namespace_:
        return "namespace_";
    case DW_TAG::imported_module:
        return "imported_module";
    case DW_TAG::unspecified_type:
        return "unspecified_type";
    case DW_TAG::partial_unit:
        return "partial_unit";
    case DW_TAG::imported_unit:
        return "imported_unit";
    case DW_TAG::condition:
        return "condition";
    case DW_TAG::shared_type:
        return "shared_type";
    case DW_TAG::type_unit:
        return "type_unit";
    case DW_TAG::rvalue_reference_type:
        return "rvalue_reference_type";
    case DW_TAG::template_alias:
        return "template_alias";
    case DW_TAG::lo_user:
        return "lo_user";
    case DW_TAG::hi_user:
        return "hi_user";
    }
    char* ret = new char[1024];
    snprintf(ret, 1024, "unknown 0x%x", static_cast<UInt32>(tag));
    return ret;
}

char* DWAttrToString(enum DW_AT attr) {
    switch (attr) {
    case DW_AT::sibling:
        return "sibling";
    case DW_AT::location:
        return "location";
    case DW_AT::name:
        return "name";
    case DW_AT::ordering:
        return "ordering";
    case DW_AT::byte_size:
        return "byte_size";
    case DW_AT::bit_offset:
        return "bit_offset";
    case DW_AT::bit_size:
        return "bit_size";
    case DW_AT::stmt_list:
        return "stmt_list";
    case DW_AT::low_pc:
        return "low_pc";
    case DW_AT::high_pc:
        return "high_pc";
    case DW_AT::language:
        return "language";
    case DW_AT::discr:
        return "discr";
    case DW_AT::discr_value:
        return "discr_value";
    case DW_AT::visibility:
        return "visibility";
    case DW_AT::import:
        return "import";
    case DW_AT::string_length:
        return "string_length";
    case DW_AT::common_reference:
        return "common_reference";
    case DW_AT::comp_dir:
        return "comp_dir";
    case DW_AT::const_value:
        return "const_value";
    case DW_AT::containing_type:
        return "containing_type";
    case DW_AT::default_value:
        return "default_value";
    case DW_AT::inline_:
        return "inline_";
    case DW_AT::is_optional:
        return "is_optional";
    case DW_AT::lower_bound:
        return "lower_bound";
    case DW_AT::producer:
        return "producer";
    case DW_AT::prototyped:
        return "prototyped";
    case DW_AT::return_addr:
        return "return_addr";
    case DW_AT::start_scope:
        return "start_scope";
    case DW_AT::bit_stride:
        return "bit_stride";
    case DW_AT::upper_bound:
        return "upper_bound";
    case DW_AT::abstract_origin:
        return "abstract_origin";
    case DW_AT::accessibility:
        return "accessibility";
    case DW_AT::address_class:
        return "address_class";
    case DW_AT::artificial:
        return "artificial";
    case DW_AT::base_types:
        return "base_types";
    case DW_AT::calling_convention:
        return "calling_convention";
    case DW_AT::count:
        return "count";
    case DW_AT::data_member_location:
        return "data_member_location";
    case DW_AT::decl_column:
        return "decl_column";
    case DW_AT::decl_line:
        return "decl_line";
    case DW_AT::decl_file:
        return "decl_file";
    case DW_AT::declaration:
        return "declaration";
    case DW_AT::discr_list:
        return "discr_list";
    case DW_AT::encoding:
        return "encoding";
    case DW_AT::frame_base:
        return "frame_base";
    case DW_AT::friend_:
        return "friend_";
    case DW_AT::identifier_case:
        return "identifier_case";
    case DW_AT::macro_info:
        return "macro_info";
    case DW_AT::namelist_item:
        return "namelist_item";
    case DW_AT::priority:
        return "priority";
    case DW_AT::segment:
        return "segment";
    case DW_AT::specification:
        return "specification";
    case DW_AT::static_link:
        return "static_link";
    case DW_AT::type:
        return "type";
    case DW_AT::use_location:
        return "use_location";
    case DW_AT::variable_parameter:
        return "variable_parameter";
    case DW_AT::virtuality:
        return "virtuality";
    case DW_AT::vtable_elem_location:
        return "vtable_elem_location";
    case DW_AT::allocated:
        return "allocated";
    case DW_AT::associated:
        return "associated";
    case DW_AT::data_location:
        return "data_location";
    case DW_AT::byte_stride:
        return "byte_stride";
    case DW_AT::entry_pc:
        return "entry_pc";
    case DW_AT::use_UTF8:
        return "use_UTF8";
    case DW_AT::extension:
        return "extension";
    case DW_AT::ranges:
        return "ranges";
    case DW_AT::trampoline:
        return "trampoline";
    case DW_AT::call_column:
        return "call_column";
    case DW_AT::call_file:
        return "call_file";
    case DW_AT::description:
        return "description";
    case DW_AT::binary_scale:
        return "binary_scale";
    case DW_AT::decimal_scale:
        return "decimal_scale";
    case DW_AT::small:
        return "small";
    case DW_AT::decimal_sign:
        return "decimal_sign";
    case DW_AT::digit_count:
        return "digit_count";
    case DW_AT::picture_string:
        return "picture_string";
    case DW_AT::mutable_:
        return "mutable_";
    case DW_AT::threads_scaled:
        return "threads_scaled";
    case DW_AT::explicit_:
        return "explicit_";
    case DW_AT::object_pointer:
        return "object_pointer";
    case DW_AT::endianity:
        return "endianity";
    case DW_AT::elemental:
        return "elemental";
    case DW_AT::pure:
        return "pure";
    case DW_AT::recursive:
        return "recursive";
    case DW_AT::signature:
        return "signature";
    case DW_AT::main_subprogram:
        return "main_subprogram";
    case DW_AT::data_bit_offset:
        return "data_bit_offset";
    case DW_AT::const_expr:
        return "const_expr";
    case DW_AT::enum_class:
        return "enum_class";
    case DW_AT::linkage_name:
        return "linkage_name";
    case DW_AT::lo_user:
        return "lo_user";
    case DW_AT::hi_user:
        return "hi_user";
    case DW_AT::external:
        return "external";
    case DW_AT::call_line:
        return "call_line";
    }
    char* ret = new char[1024];
    snprintf(ret, 1024, "unknown 0x%x", static_cast<UInt32>(attr));
    return ret;
}

char* DWFormToString(enum DW_FORM form) {
    switch (form) {
    case DW_FORM::addr:
        return "addr";
    case DW_FORM::block2:
        return "block2";
    case DW_FORM::block4:
        return "block4";
    case DW_FORM::data1:
        return "data1";
    case DW_FORM::data2:
        return "data2";
    case DW_FORM::data4:
        return "data4";
    case DW_FORM::data8:
        return "data8";
    case DW_FORM::string:
        return "string";
    case DW_FORM::block:
        return "block";
    case DW_FORM::block1:
        return "block1";
    case DW_FORM::ref_addr:
        return "ref_addr";
    case DW_FORM::udata:
        return "udata";
    case DW_FORM::flag:
        return "flag";
    case DW_FORM::strp:
        return "strp";
    case DW_FORM::ref1:
        return "ref1";
    case DW_FORM::ref2:
        return "ref2";
    case DW_FORM::ref4:
        return "ref4";
    case DW_FORM::ref8:
        return "ref8";
    case DW_FORM::ref_udata:
        return "ref_udata";
    case DW_FORM::indirect:
        return "indirect";
    case DW_FORM::sec_offset:
        return "sec_offset";
    case DW_FORM::exprloc:
        return "exprloc";
    case DW_FORM::flag_present:
        return "flag_present";
    case DW_FORM::ref_sig8:
        return "ref_sig8";
    case DW_FORM::sdata:
        return "ref_sdata";
    }
    char* ret = new char[1024];
    snprintf(ret, 1024, "unknown 0x%x", static_cast<UInt32>(form));
    return ret;
}

Size DWFormSize(enum DW_FORM form) {
    switch (form) {
    case DW_FORM::addr:
        return 8;
    case DW_FORM::block2:
        return 2;
    case DW_FORM::block4:
        return 4;
    case DW_FORM::data1:
        return 1;
    case DW_FORM::data2:
        return 2;
    case DW_FORM::data4:
        return 4;
    case DW_FORM::data8:
        return 8;
    case DW_FORM::string:
        return 4;
    case DW_FORM::block:
        return 8;
    case DW_FORM::block1:
        return 8;
    case DW_FORM::ref_addr:
        return 4;
    case DW_FORM::udata:
        return 4;
    case DW_FORM::sdata:
        return 4;
    case DW_FORM::flag:
        return 4;
    case DW_FORM::strp:
        return 4;
    case DW_FORM::ref1:
        return 1;
    case DW_FORM::ref2:
        return 2;
    case DW_FORM::ref4:
        return 4;
    case DW_FORM::ref8:
        return 8;
    case DW_FORM::ref_udata:
        return 4;
    case DW_FORM::indirect:
        return 4;
    case DW_FORM::sec_offset:
        return 4;
    case DW_FORM::exprloc:
        return 4;
    case DW_FORM::flag_present:
        return 0;
    case DW_FORM::ref_sig8:
        return 8;
    }
    return 0;
}

char* SourceLineFlagsToString(struct LTSourceLine* sourceLine) {
    char* buffer = new char[1024];
    snprintf(buffer, 1024, "%s %s %s %s %s", sourceLine->state.statement > 0 ? "is_stmt" : "",
             sourceLine->state.basic_block > 0 ? "basic_block" : "",
             sourceLine->state.end_sequence > 0 ? "end_sequence" : "",
             sourceLine->state.prologue_end > 0 ? "prologue_end" : "",
             sourceLine->state.epilogue_begin > 0 ? "epilogue_begin" : "");
    return buffer;
}

UInt64 debug::GetStringSize(UInt8* p) {
    UInt8* s = p;
    UInt64 size = 0;
    while (*s++) {
        size++;
    }
    return size;
}

UInt64 debug::ReadUleb128(UInt8* p, UInt8* end) {
    UInt64 result = 0;
    int bit = 0;
    do {
        if (p == end) {
            DARWIN_KIT_LOG("malformed uleb128\n");
            break;
        }
        UInt64 slice = *p & 0x7F;
        if (bit > 63) {
            DARWIN_KIT_LOG("uleb128 too big for uint64\n");
            break;
        } else {
            result |= (slice << bit);
            bit += 7;
        }
    } while (*p++ & 0x80);
    return result;
}

UInt64 debug::ReadUleb128(UInt8* p, UInt8* end, UInt32* idx) {
    UInt64 result = 0;
    int bit = 0;
    do {
        if (p == end) {
            DARWIN_KIT_LOG("malformed uleb128\n");
            break;
        }
        UInt64 slice = *p & 0x7F;
        if (bit > 63) {
            DARWIN_KIT_LOG("uleb128 too big for uint64\n");
            break;
        } else {
            result |= (slice << bit);
            bit += 7;
        }
        *idx = *idx + 1;
    } while (*p++ & 0x80);
    return result;
}

int64_t debug::ReadSleb128(UInt8* p, UInt8* end) {
    int64_t result = 0;
    int bit = 0;
    UInt8 byte = 0;
    do {
        if (p == end) {
            DARWIN_KIT_LOG("malformed sleb128\n");
            break;
        }
        byte = *p++;
        result |= (((int64_t)(byte & 0x7f)) << bit);
        bit += 7;
    } while (byte & 0x80);
    // sign extend negative numbers
    if (((byte & 0x40) != 0) && (bit < 64)) {
        result |= (~0ULL) << bit;
    }
    return result;
}

int64_t debug::ReadSleb128(UInt8* p, UInt8* end, UInt32* idx) {
    int64_t result = 0;
    int bit = 0;
    UInt8 byte = 0;
    do {
        if (p == end) {
            DARWIN_KIT_LOG("malformed sleb128\n");
            break;
        }
        byte = *p++;
        *idx = *idx + 1;
        result |= (((int64_t)(byte & 0x7f)) << bit);
        bit += 7;
    } while (byte & 0x80);
    // sign extend negative numbers
    if (((byte & 0x40) != 0) && (bit < 64)) {
        result |= (~0ULL) << bit;
    }
    return result;
}

namespace debug {

static char kDwarfSegment[] = "__DWARF";

static char kDebugLine[] = "__debug_line";
static char kDebugLoc[] = "__debug_loc";
static char kDebugAranges[] = "__debug_aranges";
static char kDebugInfo[] = "__debug_info";
static char kDebugRanges[] = "__debug_ranges";
static char kDebugAbbrev[] = "__debug_abbrev";
static char kDebugStr[] = "__debug_str";
static char kAppleNames[] = "__apple_names";
static char kAppleNamesPac[] = "__apple_namespac";
static char kAppleTypes[] = "__apple_types";
static char kAppleObjC[] = "__apple_objc";

DIE::DIE(Dwarf* dwarf, UInt64 code, char* name, enum DW_TAG tag, enum DW_CHILDREN has_children)
    : dwarf(dwarf), code(code), name(name), tag(tag), has_children(has_children) {}

struct AttrAbbrev* DIE::GetAttribute(enum DW_AT attr) {
    for (int i = 0; i < abbreviationTable.size(); i++) {
        struct AttrAbbrev* ab = abbreviationTable.at(i);
        if (attr == ab->attr_spec.name) {
            return ab;
        }
    }
    return nullptr;
}

DwarfDIE::DwarfDIE(Dwarf* dwarf, CompilationUnit* unit, DIE* die, DwarfDIE* parent)
    : dwarf(dwarf), compilationUnit(unit), die(die), parent(parent) {}

struct Attribute* DwarfDIE::GetAttribute(enum DW_AT attr) {
    for (int i = 0; i < attributes.size(); i++) {
        struct Attribute* attribute = attributes.at(i);
        if (attribute->abbreviation.attr_spec.name == attr) {
            return attribute;
        }
    }
    return nullptr;
}

UInt64 DwarfDIE::GetAttributeValue(enum DW_AT attr) {
    for (int i = 0; i < attributes.size(); i++) {
        struct Attribute* attribute = attributes.at(i);
        if (attribute->abbreviation.attr_spec.name == attr) {
            return attribute->value;
        }
    }
    return 0;
}

CompilationUnit::CompilationUnit(Dwarf* dwarf, struct CompileUnitHeader* hdr, DIE* die)
    : dwarf(dwarf), header(hdr), die(die) {}

Dwarf::Dwarf(const char* debugSymbols)
#ifdef __USER__
    : macho(new KernelMachO(debugSymbols)),
#else
    : macho(new KDKKernelMachO(xnu::Kernel::Xnu(), debugSymbols)),
#endif
      machoWithDebug(macho), dwarf(macho->GetSegment(kDwarfSegment)),
      __debug_line(macho->GetSection(kDwarfSegment, kDebugLine)),
      __debug_loc(macho->GetSection(kDwarfSegment, kDebugLoc)),
      __debug_aranges(macho->GetSection(kDwarfSegment, kDebugAranges)),
      __debug_info(macho->GetSection(kDwarfSegment, kDebugInfo)),
      __debug_ranges(macho->GetSection(kDwarfSegment, kDebugRanges)),
      __debug_abbrev(macho->GetSection(kDwarfSegment, kDebugAbbrev)),
      __debug_str(macho->GetSection(kDwarfSegment, kDebugStr)),
      __apple_names(macho->GetSection(kDwarfSegment, kAppleNames)),
      __apple_namespac(macho->GetSection(kDwarfSegment, kAppleNamesPac)),
      __apple_types(macho->GetSection(kDwarfSegment, kAppleTypes)),
      __apple_objc(macho->GetSection(kDwarfSegment, kAppleObjC)) {
    PopulateDebugSymbols();
}

Dwarf::Dwarf(MachO* macho, const char* debugSymbols)
    : macho(macho), machoWithDebug(macho), dwarf(macho->GetSegment(kDwarfSegment)),
      __debug_line(macho->GetSection(kDwarfSegment, kDebugLine)),
      __debug_loc(macho->GetSection(kDwarfSegment, kDebugLoc)),
      __debug_aranges(macho->GetSection(kDwarfSegment, kDebugAranges)),
      __debug_info(macho->GetSection(kDwarfSegment, kDebugInfo)),
      __debug_ranges(macho->GetSection(kDwarfSegment, kDebugRanges)),
      __debug_abbrev(macho->GetSection(kDwarfSegment, kDebugAbbrev)),
      __debug_str(macho->GetSection(kDwarfSegment, kDebugStr)),
      __apple_names(macho->GetSection(kDwarfSegment, kAppleNames)),
      __apple_namespac(macho->GetSection(kDwarfSegment, kAppleNamesPac)),
      __apple_types(macho->GetSection(kDwarfSegment, kAppleTypes)),
      __apple_objc(macho->GetSection(kDwarfSegment, kAppleObjC)) {}

DIE* Dwarf::GetDebugInfoEntryByName(const char* name) {
    return nullptr;
}

DIE* GetDebugInfoEntryByCode(UInt64 code) {
    return nullptr;
}

void Dwarf::PopulateDebugSymbols() {
    ParseDebugAbbrev();
    ParseDebugInfo();
    ParseDebugLines();
    ParseDebugLocations();
    ParseDebugRanges();
    ParseDebugAddressRanges();
}

void Dwarf::ParseDebugAbbrev() {
    MachO* macho = macho;
    Segment* dwarf = dwarf;
    Section* debug_info = __debug_info;
    Section* debug_abbrev = __debug_abbrev;
    Section* debug_str = __debug_str;
    UInt8* debug_abbrev_begin = (*macho)[debug_abbrev->GetOffset()];
    UInt8* debug_abbrev_end = (*macho)[debug_abbrev->GetOffset() + debug_abbrev->GetSize()];
    UInt8* debug_str_begin = (*macho)[debug_str->GetOffset()];
    UInt8* debug_str_end = (*macho)[debug_str->GetOffset() + debug_str->GetSize()];
    Size debug_abbrev_size = debug_abbrev->GetSize();
    UInt32 debug_abbrev_offset = 0;
    std::vector<DIE*> stack;
    UInt64 code = 0;
    enum DW_TAG tag = static_cast<enum DW_TAG>(0);
    while (debug_abbrev_offset < debug_abbrev->GetSize() - sizeof(UInt32)) {
        if (code == 0 && static_cast<UInt32>(tag) == 0) {
            code = debug::ReadUleb128(debug_abbrev_begin + debug_abbrev_offset, debug_abbrev_end,
                                      &debug_abbrev_offset);
            tag = static_cast<enum DW_TAG>(debug::ReadUleb128(
                debug_abbrev_begin + debug_abbrev_offset, debug_abbrev_end, &debug_abbrev_offset));
            if (tag == DW_TAG::compile_unit) {
                enum DW_CHILDREN children = static_cast<enum DW_CHILDREN>(
                    debug::ReadUleb128(debug_abbrev_begin + debug_abbrev_offset, debug_abbrev_end,
                                       &debug_abbrev_offset));
                char* name = DWTagToString(tag);
                DIE* die = new DIE(this, code, name, tag, children);
                stack.push_back(die);
                dies.push_back(die);
                DARWIN_KIT_LOG("\n\n[%llu] DW_TAG = %s children = %u\n", code, name,
                               static_cast<UInt32>(children));
            }
        } else {
            UInt64 value;
            enum DW_AT attr = static_cast<enum DW_AT>(debug::ReadUleb128(
                debug_abbrev_begin + debug_abbrev_offset, debug_abbrev_end, &debug_abbrev_offset));
            enum DW_FORM form = static_cast<enum DW_FORM>(debug::ReadUleb128(
                debug_abbrev_begin + debug_abbrev_offset, debug_abbrev_end, &debug_abbrev_offset));
            if (static_cast<int>(attr) == 0 && static_cast<int>(form) == 0) {
                UInt32 tmp = debug_abbrev_offset;
                code = debug::ReadUleb128(debug_abbrev_begin + debug_abbrev_offset,
                                          debug_abbrev_end, &debug_abbrev_offset);
                while (!code) {
                    tmp = debug_abbrev_offset;
                    code = debug::ReadUleb128(debug_abbrev_begin + debug_abbrev_offset,
                                              debug_abbrev_end, &debug_abbrev_offset);
                }
                tag = static_cast<enum DW_TAG>(
                    debug::ReadUleb128(debug_abbrev_begin + debug_abbrev_offset, debug_abbrev_end,
                                       &debug_abbrev_offset));
                if (tag == DW_TAG::compile_unit) {
                    tag = static_cast<enum DW_TAG>(0);
                    code = 0;
                    debug_abbrev_offset = tmp;
                    continue;
                } else {
                    enum DW_CHILDREN children = static_cast<enum DW_CHILDREN>(
                        debug::ReadUleb128(debug_abbrev_begin + debug_abbrev_offset,
                                           debug_abbrev_end, &debug_abbrev_offset));
                    char* name = DWTagToString(tag);
                    DIE* die = new DIE(this, code, name, tag, children);
                    DARWIN_KIT_LOG("\n\n[%llu] DW_TAG = %s children = %u\n", code, name,
                                   static_cast<UInt32>(children));
                    stack.push_back(die);
                    dies.push_back(die);
                }
            } else {
                DARWIN_KIT_LOG("\tDW_AT = %s 0x%x DW_FORM = %s\n", DWAttrToString(attr),
                               static_cast<UInt32>(attr), DWFormToString(form));
                DIE* die = stack.at(stack.size() - 1);
                struct AttrAbbrev* ab = new AttrAbbrev;
                ab->tag = die->GetTag();
                ab->children = die->GetHasChildren();
                ab->code = die->GetCode();
                ab->attr_spec.name = attr;
                ab->attr_spec.form = form;
                die->AddAbbreviation(ab);
            }
        }
    }
    DARWIN_KIT_LOG("\n\n");
}

DIE* Dwarf::GetDebugInfoEntryByCode(UInt64 code) {
    for (int i = 0; i < dies.size(); i++) {
        DIE* die = dies.at(i);
        if (die->GetCode() == code) {
            return die;
        }
    }
    return nullptr;
}

void Dwarf::ParseDebugInfo() {
    MachO* macho = macho;
    Segment* dwarf = dwarf;
    Section* debug_info = __debug_info;
    Section* debug_abbrev = __debug_abbrev;
    Section* debug_str = __debug_str;
    UInt8* debug_info_begin = (*macho)[debug_info->GetOffset()];
    UInt8* debug_info_end = (*macho)[debug_info->GetOffset() + debug_info->GetSize()];
    UInt8* debug_abbrev_begin = (*macho)[debug_abbrev->GetOffset()];
    UInt8* debug_abbrev_end = (*macho)[debug_abbrev->GetOffset() + debug_abbrev->GetSize()];
    UInt8* debug_str_begin = (*macho)[debug_str->GetOffset()];
    UInt8* debug_str_end = (*macho)[debug_str->GetOffset() + debug_str->GetSize()];
    Size debug_info_size = debug_info->GetSize();
    Size debug_abbrev_size = debug_abbrev->GetSize();
    UInt32 debug_info_offset = 0;
    UInt32 debug_abbrev_offset = 0;
    struct CompilationUnit* compilationUnit = nullptr;
    struct CompileUnitHeader* header = nullptr;
    std::vector<DwarfDIE*> stack;
    UInt32 next_unit = 0;
    UInt32 consecutive_zeroes = 0;
    while (debug_info_offset < debug_info->GetSize() - sizeof(UInt32)) {
        UInt64 value;
        bool new_compile_unit = false;
        if (header == nullptr) {
            header =
                reinterpret_cast<struct CompileUnitHeader*>(debug_info_begin + debug_info_offset);
            debug_info_offset += sizeof(struct CompileUnitHeader);
            new_compile_unit = true;
        }
        UInt64 code = debug::ReadUleb128(debug_info_begin + debug_info_offset, debug_info_end,
                                         &debug_info_offset);
        if (code == 0) {
            stack.erase(stack.end() - 1);
            if (stack.size() == 0) {
                header = nullptr;
            }
            continue;
        }
        DIE* die = GetDebugInfoEntryByCode(code);
        DwarfDIE* parent = stack.size() > 0 ? stack.at(stack.size() - 1) : nullptr;
        DwarfDIE* dwarfDIE = new DwarfDIE(this, compilationUnit, die, parent);
        if (new_compile_unit) {
            compilationUnit = new CompilationUnit(this, header, die);
            compilationUnits.push_back(compilationUnit);
            new_compile_unit = false;
        }
        for (int i = 0; i < stack.size(); i++) {
            DARWIN_KIT_LOG("\t");
        }
        DARWIN_KIT_LOG("DW_TAG = %s depth = %zu\n", DWTagToString(die->GetTag()), stack.size());
        UInt64 die_code = die->GetCode();
        UInt32 attributes_count = die->GetAttributesCount();
        for (int i = 0; i < attributes_count; i++) {
            struct Attribute* attribute = new Attribute;
            struct AttrAbbrev* ab = die->GetAttribute(i);
            DW_AT attr = ab->attr_spec.name;
            DW_FORM form = ab->attr_spec.form;
            DW_TAG tag = ab->tag;
            DW_CHILDREN ch = ab->children;
            attribute->abbreviation.attr_spec.name = attr;
            attribute->abbreviation.attr_spec.form = form;
            attribute->abbreviation.tag = tag;
            attribute->abbreviation.children = ch;
            if (form == DW_FORM::flag_present) {
                continue;
            } else if (form == DW_FORM::block) {
                value = debug::ReadUleb128(debug_info_begin + debug_info_offset, debug_info_end,
                                           &debug_info_offset);
                continue;
            } else if (form == DW_FORM::block1) {
                value = *reinterpret_cast<UInt8*>(debug_info_begin + debug_info_offset);
                debug_info_offset += sizeof(UInt8);
                debug_info_offset += value;
                continue;
            } else if (form == DW_FORM::block2) {
                value = *reinterpret_cast<UInt16*>(debug_info_begin + debug_info_offset);
                debug_info_offset += sizeof(UInt16);
                debug_info_offset += value;
                continue;
            } else if (form == DW_FORM::block4) {
                value = *reinterpret_cast<UInt32*>(debug_info_begin + debug_info_offset);
                debug_info_offset += sizeof(UInt32);
                debug_info_offset += value;
                continue;
            } else if (form == DW_FORM::indirect) {
                value = debug::ReadUleb128(debug_info_begin + debug_info_offset, debug_info_end,
                                           &debug_info_offset);
                continue;
            } else if (form == DW_FORM::ref_udata) {
                value = debug::ReadUleb128(debug_info_begin + debug_info_offset, debug_info_end,
                                           &debug_info_offset);
                continue;
            } else if (form == DW_FORM::udata) {
                value = debug::ReadUleb128(debug_info_begin + debug_info_offset, debug_info_end,
                                           &debug_info_offset);
                continue;
            } else if (form == DW_FORM::sdata) {
                value = debug::ReadSleb128(debug_info_begin + debug_info_offset, debug_info_end,
                                           &debug_info_offset);
                continue;
            } else if (form == DW_FORM::string) {
                UInt64 string_size = GetStringSize(debug_info_begin + debug_info_offset);
                debug_info_offset += string_size;
                continue;
            } else if (form == DW_FORM::exprloc) {
                value = debug::ReadUleb128(debug_info_begin + debug_info_offset, debug_info_end,
                                           &debug_info_offset);
                debug_info_offset += value;
                continue;
            } else {
                Size form_size = DWFormSize(form);
                switch (form_size) {
                case 0:
                    break;
                case 1:
                    value = *reinterpret_cast<UInt8*>(debug_info_begin + debug_info_offset);
                    break;
                case 2:
                    value = *reinterpret_cast<UInt16*>(debug_info_begin + debug_info_offset);
                    break;
                case 4:
                    value = *reinterpret_cast<UInt32*>(debug_info_begin + debug_info_offset);
                    break;
                case 8:
                    value = *reinterpret_cast<UInt64*>(debug_info_begin + debug_info_offset);
                    break;
                default:
                    break;
                }
                debug_info_offset += form_size;
            }
            attribute->value = value;
            dwarfDIE->AddAttribute(attribute);
            for (int i = 0; i < stack.size(); i++) {
                DARWIN_KIT_LOG("\t");
            }
            DARWIN_KIT_LOG("\tDW_AT = %s value = 0x%llx\n", DWAttrToString(attr), value);
        }
        if (static_cast<bool>(die->GetHasChildren())) {
            stack.push_back(dwarfDIE);
        }
        if (parent) {
            parent->AddChild(dwarfDIE);
        }
        compilationUnit->AddDebugInfoEntry(dwarfDIE);
    }
}

void Dwarf::ParseDebugLines() {
    MachO* macho = macho;
    Segment* dwarf = dwarf;
    Section* debug_line = __debug_line;
    UInt8* debug_line_begin = (*macho)[debug_line->GetOffset()];
    UInt8* debug_line_end = (*macho)[debug_line->GetOffset() + debug_line->GetSize()];
    UInt32 debug_line_offset = 0;
    while (debug_line_offset < debug_line->GetSize()) {
        LineTable* lineTable = new LineTable(macho, this);
        struct LTPrologue prologue;
        struct LTStandardOpcodeLengths opcodes;
        memcpy(&prologue, debug_line_begin + debug_line_offset, sizeof(struct LTPrologue));
        UInt32 total_length = prologue.total_length;
        UInt32 prologue_length = prologue.prologue_length;
        UInt8* prologue_end = reinterpret_cast<UInt8*>(
            debug_line_begin + debug_line_offset + offsetof(struct LTPrologue, min_inst_length) +
            prologue_length);
        UInt8* end = reinterpret_cast<UInt8*>(debug_line_begin + debug_line_offset + total_length +
                                              sizeof(UInt32));
        debug_line_offset += sizeof(struct LTPrologue);
        memcpy(&opcodes, debug_line_begin + debug_line_offset,
               sizeof(struct LTStandardOpcodeLengths));
        debug_line_offset += sizeof(struct LTStandardOpcodeLengths);
        bool source_file_names = false;
        while ((debug_line_begin + debug_line_offset) < prologue_end) {
            if (source_file_names) {
                struct LTSourceFile* source_file = new LTSourceFile;
                char* source_file_name =
                    reinterpret_cast<char*>(debug_line_begin + debug_line_offset);
                DARWIN_KIT_LOG("Source File Name: %s\n", source_file_name);
                UInt32 string_size = GetStringSize(debug_line_begin + debug_line_offset);
                debug_line_offset += string_size + 1;
                lineTable->AddSourceFile(source_file);
                memcpy(&source_file->metadata, debug_line_begin + debug_line_offset,
                       sizeof(struct LTSourceFileMetadata));
                debug_line_offset += sizeof(struct LTSourceFileMetadata);
                if (*(debug_line_begin + debug_line_offset) == 0) {
                    debug_line_offset++;
                    break;
                }
            } else {
                char* include_directory =
                    reinterpret_cast<char*>(debug_line_begin + debug_line_offset);
                DARWIN_KIT_LOG("Include Directory: %s\n", include_directory);
                UInt32 string_size = GetStringSize(debug_line_begin + debug_line_offset);
                debug_line_offset += string_size + 1;
                lineTable->AddIncludeDirectory(include_directory);
                if (*(debug_line_begin + debug_line_offset) == 0) {
                    debug_line_offset++;
                    source_file_names = true;
                }
            }
        }
        DARWIN_KIT_LOG("%-20s %-6s %-6s %-6s %-4s %-13s %-13s\n", "Address", "Line", "Column",
                       "File", "ISA", "Discriminator", "Flags");
        DARWIN_KIT_LOG("%-20s %-6s %-6s %-6s %-4s %-13s %-13s\n", "--------------------",
                       "--------", "------", "------", "----", "-------------", "-------------");
        struct Sequence* sequence = new Sequence;
        struct LTSourceFile* sourceFile = nullptr;
        struct LTSourceLine* sourceLine = nullptr;
        sourceLine = new LTSourceLine;
        memcpy(&sourceLine->state, &gInitialState, sizeof(struct LTStateMachine));
        sourceFile = lineTable->GetSourceFile(sourceLine->state.file - 1);
        sourceLine->source_file = sourceFile;
        UInt8 op_index = 0;
        while ((debug_line_begin + debug_line_offset) < end) {
            UInt8 op = *(debug_line_begin + debug_line_offset);
            debug_line_offset++;
            if (op == 0) {
                UInt64 num_bytes = debug::ReadUleb128(debug_line_begin + debug_line_offset,
                                                      debug_line_end, &debug_line_offset);
                op = *reinterpret_cast<UInt8*>(debug_line_begin + debug_line_offset);
                debug_line_offset++;
                num_bytes--;
                switch (static_cast<DW_LNE>(op)) {
                case DW_LNE::end_sequence: {
                    sequence->sourceLines.push_back(sourceLine);
                    struct LTSourceLine* newSourceLine = new LTSourceLine;
                    memcpy(newSourceLine, sourceLine, sizeof(struct LTSourceLine));
                    sourceLine = newSourceLine;
                    sourceLine->state.end_sequence = 1;
                    DARWIN_KIT_LOG("0x%-20llx %-6lld %-8lld %-6u %-4u %-13u %-13s\n",
                                   sourceLine->state.address, sourceLine->state.line,
                                   sourceLine->state.column, sourceLine->state.file,
                                   sourceLine->state.isa, sourceLine->state.discriminator,
                                   SourceLineFlagsToString(sourceLine));
                    memcpy(&sourceLine->state, &gInitialState, sizeof(struct LTStateMachine));
                    sourceLine->state.discriminator = 0;
                    sourceLine->state.basic_block = 0;
                    sourceLine->state.prologue_end = 0;
                    sourceLine->state.epilogue_begin = 0;
                    sourceLine->state.end_sequence = 0;
                    break;
                }
                case DW_LNE::set_address: {
                    UInt64 program_counter =
                        *reinterpret_cast<UInt64*>(debug_line_begin + debug_line_offset);
                    sourceLine->state.address = program_counter;
                    DARWIN_KIT_LOG("0x%-20llx %-6lld %-8lld %-6u %-4u %-13u %-13s\n",
                                   sourceLine->state.address, sourceLine->state.line,
                                   sourceLine->state.column, sourceLine->state.file,
                                   sourceLine->state.isa, sourceLine->state.discriminator,
                                   SourceLineFlagsToString(sourceLine));
                    sequence->sourceLines.push_back(sourceLine);
                    struct LTSourceLine* newSourceLine = new LTSourceLine;
                    memcpy(newSourceLine, sourceLine, sizeof(struct LTSourceLine));
                    sourceLine = newSourceLine;
                    break;
                }
                case DW_LNE::define_file: {
                    break;
                }
                case DW_LNE::set_discriminator: {
                    UInt64 discriminator =
                        debug::ReadUleb128(debug_line_begin + debug_line_offset, debug_line_end);
                    sourceLine->state.discriminator = discriminator;
                    // DARWIN_KIT_LOG("0x%-20llx %-6lld %-8lld %-6u %-4u %-13u %-13s\n",
                    // sourceLine->state.address, sourceLine->state.line,
                    // sourceLine->state.column, sourceLine->state.file, sourceLine->state.isa,
                    // sourceLine->state.discriminator, SourceLineFlagsToString(sourceLine));
                    break;
                }
                case DW_LNE::lo_user: {
                    break;
                }
                case DW_LNE::hi_user: {
                    break;
                }
                }
                debug_line_offset += num_bytes;
            } else if (op > 0 && op < 13) {
                switch (static_cast<DW_LNS>(op)) {
                case DW_LNS::copy: {
                    // DARWIN_KIT_LOG("0x%-20llx %-6lld %-8lld %-6u %-4u %-13u %-13s\n",
                    // sourceLine->state.address, sourceLine->state.line, sourceLine->state.column,
                    // sourceLine->state.file, sourceLine->state.isa,
                    // sourceLine->state.discriminator, SourceLineFlagsToString(sourceLine));
                    sourceLine->state.discriminator = 0;
                    sourceLine->state.basic_block = 0;
                    sourceLine->state.prologue_end = 0;
                    sourceLine->state.epilogue_begin = 0;
                    sourceLine->state.end_sequence = 0;
                    break;
                }
                case DW_LNS::advance_pc: {
                    UInt64 program_counter = debug::ReadUleb128(
                        debug_line_begin + debug_line_offset, debug_line_end, &debug_line_offset);
                    sourceLine->state.address += program_counter;
                    sourceLine->state.prologue_end = 0;
                    // DARWIN_KIT_LOG("0x%-20llx %-6lld %-8lld %-6u %-4u %-13u %-13s\n",
                    // sourceLine->state.address, sourceLine->state.line,
                    // sourceLine->state.column, sourceLine->state.file, sourceLine->state.isa,
                    // sourceLine->state.discriminator, SourceLineFlagsToString(sourceLine));
                    break;
                }
                case DW_LNS::advance_line: {
                    int64_t line = debug::ReadSleb128(debug_line_begin + debug_line_offset,
                                                      debug_line_end, &debug_line_offset);
                    sourceLine->state.line += line;
                    // DARWIN_KIT_LOG("0x%-20llx %-6lld %-8lld %-6u %-4u %-13u %-13s\n",
                    // sourceLine->state.address, sourceLine->state.line,
                    // sourceLine->state.column, sourceLine->state.file, sourceLine->state.isa,
                    // sourceLine->state.discriminator, SourceLineFlagsToString(sourceLine));
                    break;
                }
                case DW_LNS::set_file: {
                    UInt64 file = debug::ReadUleb128(debug_line_begin + debug_line_offset,
                                                     debug_line_end, &debug_line_offset);
                    sourceLine->state.file = file;
                    // DARWIN_KIT_LOG("0x%-20llx %-6lld %-8lld %-6u %-4u %-13u %-13s\n",
                    // sourceLine->state.address, sourceLine->state.line,
                    // sourceLine->state.column, sourceLine->state.file, sourceLine->state.isa,
                    // sourceLine->state.discriminator, SourceLineFlagsToString(sourceLine));
                    break;
                }
                case DW_LNS::set_column: {
                    UInt64 column = debug::ReadUleb128(debug_line_begin + debug_line_offset,
                                                       debug_line_end, &debug_line_offset);
                    sourceLine->state.column = column;
                    // DARWIN_KIT_LOG("0x%-20llx %-6lld %-8lld %-6u %-4u %-13u %-13s\n",
                    // sourceLine->state.address, sourceLine->state.line,
                    // sourceLine->state.column, sourceLine->state.file, sourceLine->state.isa,
                    // sourceLine->state.discriminator, SourceLineFlagsToString(sourceLine));
                    break;
                }
                case DW_LNS::negate_stmt: {
                    sourceLine->state.statement = ~sourceLine->state.statement;
                    // DARWIN_KIT_LOG("0x%-20llx %-6lld %-8lld %-6u %-4u %-13u %-13s\n",
                    // sourceLine->state.address, sourceLine->state.line,
                    // sourceLine->state.column, sourceLine->state.file, sourceLine->state.isa,
                    // sourceLine->state.discriminator, SourceLineFlagsToString(sourceLine));
                    break;
                }
                case DW_LNS::set_basic_block: {
                    sourceLine->state.basic_block = 1;
                    // DARWIN_KIT_LOG("0x%-20llx %-6lld %-8lld %-6u %-4u %-13u %-13s\n",
                    // sourceLine->state.address, sourceLine->state.line,
                    // sourceLine->state.column, sourceLine->state.file, sourceLine->state.isa,
                    // sourceLine->state.discriminator, SourceLineFlagsToString(sourceLine));
                    break;
                }
                case DW_LNS::const_add_pc: {
                    int64_t line_base = prologue.line_base;
                    UInt8 line_range = prologue.line_range;
                    UInt8 opcode_base = prologue.opcode_base;
                    UInt8 min_inst_length = prologue.min_inst_length;
                    UInt64 inc = min_inst_length * ((255 - opcode_base) / line_range);
                    sourceLine->state.address += inc;
                    break;
                }
                case DW_LNS::fixed_advance_pc: {
                    UInt64 program_counter =
                        *reinterpret_cast<UInt16*>(debug_line_begin + debug_line_offset);
                    debug_line_offset += sizeof(UInt16);
                    sourceLine->state.address += program_counter;
                    sourceLine->state.prologue_end = 0;
                    // DARWIN_KIT_LOG("0x%-20llx %-6lld %-8lld %-6u %-4u %-13u %-13s\n",
                    // sourceLine->state.address, sourceLine->state.line,
                    // sourceLine->state.column, sourceLine->state.file, sourceLine->state.isa,
                    // sourceLine->state.discriminator, SourceLineFlagsToString(sourceLine));
                    break;
                }
                case DW_LNS::set_prologue_end: {
                    sourceLine->state.prologue_end = 1;
                    // DARWIN_KIT_LOG("0x%-20llx %-6lld %-8lld %-6u %-4u %-13u %-13s\n",
                    // sourceLine->state.address, sourceLine->state.line,
                    // sourceLine->state.column, sourceLine->state.file, sourceLine->state.isa,
                    // sourceLine->state.discriminator, SourceLineFlagsToString(sourceLine));
                    break;
                }
                case DW_LNS::set_epilogue_begin: {
                    sourceLine->state.epilogue_begin = 1;
                    // DARWIN_KIT_LOG("0x%-20llx %-6lld %-8lld %-6u %-4u %-13u %-13s\n",
                    // sourceLine->state.address, sourceLine->state.line,
                    // sourceLine->state.column, sourceLine->state.file, sourceLine->state.isa,
                    // sourceLine->state.discriminator, SourceLineFlagsToString(sourceLine));
                    break;
                }
                case DW_LNS::set_isa: {
                    UInt64 isa = debug::ReadUleb128(debug_line_begin + debug_line_offset,
                                                    debug_line_end, &debug_line_offset);
                    sourceLine->state.isa = isa;
                    // DARWIN_KIT_LOG("0x%-20llx %-6lld %-8lld %-6u %-4u %-13u %-13s\n",
                    // sourceLine->state.address, sourceLine->state.line,
                    // sourceLine->state.column, sourceLine->state.file, sourceLine->state.isa,
                    // sourceLine->state.discriminator, SourceLineFlagsToString(sourceLine));
                    break;
                }
                }

            } else {
                int64_t line_base = prologue.line_base;
                UInt8 line_range = prologue.line_range;
                UInt8 opcode_base = prologue.opcode_base;
                UInt8 min_inst_length = prologue.min_inst_length;
                int64_t address_change = ((op - opcode_base) / line_range) * min_inst_length;
                int64_t line_change = line_base + (op - opcode_base) % line_range;
                sourceLine->state.address += address_change;
                sourceLine->state.line += line_change;
                DARWIN_KIT_LOG("0x%-20llx %-6lld %-8lld %-6u %-4u %-13u %-13s\n",
                               sourceLine->state.address, sourceLine->state.line,
                               sourceLine->state.column, sourceLine->state.file,
                               sourceLine->state.isa, sourceLine->state.discriminator,
                               SourceLineFlagsToString(sourceLine));
                sourceLine->state.prologue_end = 0;
                sequence->sourceLines.push_back(sourceLine);
                struct LTSourceLine* newSourceLine = new LTSourceLine;
                memcpy(newSourceLine, sourceLine, sizeof(struct LTSourceLine));
                sourceLine = newSourceLine;
            }
        }
        debug_line_offset = (end - debug_line_begin);
        lineTables.push_back(lineTable);
    }
}

void Dwarf::ParseDebugLocations() {
    MachO* macho = macho;
    Segment* dwarf = dwarf;
    Section* debug_loc = __debug_loc;
    UInt8* debug_loc_begin = (*macho)[debug_loc->GetOffset()];
    UInt8* debug_loc_end = (*macho)[debug_loc->GetOffset() + debug_loc->GetSize()];
    UInt32 debug_loc_offset = 0;
    DARWIN_KIT_LOG("0x%08x:\n", debug_loc_offset);
    struct LocationTableEntry* location_entry = new LocationTableEntry;
    location_entry->offset = debug_loc_offset;
    while (debug_loc_offset < debug_loc->GetSize()) {
        UInt64 value0 = *reinterpret_cast<UInt64*>(debug_loc_begin + debug_loc_offset);
        UInt64 value1 =
            *reinterpret_cast<UInt64*>(debug_loc_begin + debug_loc_offset + sizeof(UInt64));
        if (value0 != 0 || value1 != 0) {
            debug_loc_offset += sizeof(UInt64) * 2;
            UInt16 bytes = *reinterpret_cast<UInt16*>(debug_loc_begin + debug_loc_offset);
            debug_loc_offset += sizeof(UInt16);
            DARWIN_KIT_LOG("\t(0x%016llx, 0x%016llx) ", value0, value1);
            for (int i = 0; i < bytes; i++) {
                UInt8 byte = *reinterpret_cast<UInt8*>(debug_loc_begin + debug_loc_offset);
                location_entry->location_ops.push_back(static_cast<DW_OP>(byte));
                DARWIN_KIT_LOG("0x%x ", byte);
                debug_loc_offset++;
            }
            DARWIN_KIT_LOG("\n");

        } else if (value0 == -1ULL) {
            debug_loc_offset += sizeof(UInt64) * 2;
            location_entry->kind = DW_LLE::base_address;
            location_entry->value0 = value1;
        } else {
            debug_loc_offset += sizeof(UInt64) * 2;
            location_entry->kind = DW_LLE::end_of_list;
            locationTable.push_back(location_entry);
            location_entry = new LocationTableEntry;
            DARWIN_KIT_LOG("0x%08x:\n", debug_loc_offset);
            location_entry->offset = debug_loc_offset;
        }
    }
}

void Dwarf::ParseDebugRanges() {
    MachO* macho = macho;
    Segment* dwarf = dwarf;
    Section* debug_ranges = __debug_ranges;
    UInt8* debug_ranges_begin = (*macho)[debug_ranges->GetOffset()];
    UInt8* debug_ranges_end = (*macho)[debug_ranges->GetOffset() + debug_ranges->GetSize()];
    UInt32 debug_ranges_offset = 0;
    UInt32 current_ranges_offset = 0;
    RangeEntries* rangeEntries = new RangeEntries;
    while (debug_ranges_offset < debug_ranges->GetSize()) {
        UInt64 value0 = *reinterpret_cast<UInt64*>(debug_ranges_begin + debug_ranges_offset);
        UInt64 value1 =
            *reinterpret_cast<UInt64*>(debug_ranges_begin + debug_ranges_offset + sizeof(UInt64));
        debug_ranges_offset += sizeof(UInt64) * 2;
        if (value0 == 0 && value1 == 0) {
            DARWIN_KIT_LOG("%08x <End of list>\n", current_ranges_offset);
            current_ranges_offset = debug_ranges_offset;
            ranges.push_back(rangeEntries);
            rangeEntries = new RangeEntries;
        } else {
            DARWIN_KIT_LOG("%08x %016llx %016llx\n", current_ranges_offset, value0, value1);
            struct RangeEntry* range = new RangeEntry;
            range->offset = current_ranges_offset;
            range->value0 = value0;
            range->value1 = value1;
            rangeEntries->push_back(range);
        }
    }
}

void Dwarf::ParseDebugAddressRanges() {
    MachO* macho = macho;
    Segment* dwarf = dwarf;
    Section* debug_aranges = __debug_aranges;
    UInt8* debug_aranges_begin = (*macho)[debug_aranges->GetOffset()];
    UInt8* debug_aranges_end = (*macho)[debug_aranges->GetOffset() + debug_aranges->GetSize()];
    UInt32 debug_aranges_offset = 0;
    UInt32 current_aranges_offset = 0;
    while (debug_aranges_offset < debug_aranges->GetSize()) {
        struct AddressRangeEntry* arange_entry = new AddressRangeEntry;
        struct AddressRangeHeader* address_range_header = &arange_entry->header;
        memcpy(address_range_header, debug_aranges_begin + debug_aranges_offset,
               sizeof(struct AddressRangeHeader));
        UInt32 length =
            address_range_header->length + sizeof(((struct AddressRangeHeader*)0)->length);
        UInt32 offset = debug_aranges_offset + sizeof(struct AddressRangeHeader);
        UInt32 segment_selector = *reinterpret_cast<UInt32*>(debug_aranges_begin + offset);
        offset += sizeof(UInt32);
        DARWIN_KIT_LOG(
            "Address Range Header: length = 0x%08x, version = 0x%04x, cu_offset = 0x%08x, "
            "addr_size = 0x%02x, seg_size = 0x%02x\n",
            address_range_header->length, address_range_header->version,
            address_range_header->offset, address_range_header->addr_size,
            address_range_header->seg_size);
        while (offset < debug_aranges_offset + length) {
            struct AddressRange* range = new AddressRange;
            UInt64 value0 = *reinterpret_cast<UInt64*>(debug_aranges_begin + offset);
            UInt64 value1 =
                *reinterpret_cast<UInt64*>(debug_aranges_begin + offset + sizeof(UInt64));
            if (value0 != 0 || value1 != 0) {
                UInt64 address = *reinterpret_cast<UInt64*>(debug_aranges_begin + offset);
                UInt64 size =
                    *reinterpret_cast<UInt64*>(debug_aranges_begin + offset + sizeof(UInt64));
                range->start = address;
                range->end = address + size;
                DARWIN_KIT_LOG("(0x%016llx, 0x%016llx)\n", address, address + size);
                arange_entry->ranges.push_back(range);
            }
            offset += (sizeof(UInt64) * 2);
        }
        addressRanges.push_back(arange_entry);
        debug_aranges_offset += length;
    }
}

} // namespace debug
