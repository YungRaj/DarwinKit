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

#include "objc.h"

#include "macho.h"
#include "macho_userspace.h"

#include "pac.h"

#include "swift.h"

#ifdef __arm64__
#include <arm64/isa_arm64.h>
#include <arm64/patch_finder_arm64.h>
#elif __x86_64__
#include <x86_64/isa_x86_64.h>
#include <x86_64/patch_finder_x86_64.h>
#endif

#include <assert.h>
#include <string.h>

namespace swift {

static char kTextSegment[] = "__TEXT";

static char kSwift5TypeRef[] = "__swift5_typeref";
static char kSwift5Entry[] = "__swift5_entry";
static char kSwift5BuiltIn[] = "__swift5_builtin";
static char kSwift5RefStr[] = "__swift5_refstr";
static char kSwift5FieldMd[] = "__swift5_fieldmd";
static char kSwift5Assocty[] = "__swift5_assocty";
static char kSwift5Proto[] = "__swift5_proto";
static char kSwift5Types[] = "__swift5_types";
static char kSwift5Protos[] = "__swift5_protos";
static char kSwift5Capture[]  = "__swift5_capture";
static char kSwift5Mpenum[] = "__swift5_mpenum";

SwiftABI* ParseSwift(darwin::MachOUserspace* macho) {
    return macho->GetObjCMetadata() ? new SwiftABI(macho, macho->GetObjCMetadata()) : nullptr;
}

void SwiftABI::PopulateSections() {
    if (!text) {
        text = macho->GetSegment(kTextSegment);
    }
    typeref = macho->GetSection(kTextSegment, kSwift5TypeRef);
    entry = macho->GetSection(kTextSegment, kSwift5Entry);
    builtin = macho->GetSection(kTextSegment, kSwift5BuiltIn);
    reflstr = macho->GetSection(kTextSegment, kSwift5RefStr);
    fieldmd = macho->GetSection(kTextSegment, kSwift5FieldMd);
    assocty = macho->GetSection(kTextSegment, kSwift5Assocty);
    proto = macho->GetSection(kTextSegment, kSwift5Proto);
    types = macho->GetSection(kTextSegment, kSwift5Types);
    protos = macho->GetSection(kTextSegment, kSwift5Protos);
    capture = macho->GetSection(kTextSegment, kSwift5Capture);
    mpenum = macho->GetSection(kTextSegment, kSwift5Mpenum);
}

void SwiftABI::ParseSwift() {
    EnumerateTypes();
}

void SwiftABI::EnumerateTypes() {
    Section* types = GetTypes();

    UInt8* swift_types_begin = (*macho)[types->GetOffset()];
    UInt8* swift_types_end = (*macho)[types->GetOffset() + types->GetSize()];

    UInt32 swift_types_offset = 0;

    while (swift_types_offset < types->GetSize()) {
        struct Type* type;

        UInt64 type_address;

        Int64 type_offset;

        type_offset = *reinterpret_cast<Int32*>((*macho)[swift_types_offset]);

        type_address += type_offset;

        struct TypeDescriptor* descriptor =
            reinterpret_cast<struct TypeDescriptor*>((*macho)[type_offset]);

        type = ParseTypeDescriptor(descriptor);

        swift_types_offset += sizeof(Int32);
    }
}

struct Type* SwiftABI::ParseTypeDescriptor(struct TypeDescriptor* typeDescriptor) {
    struct Type* type;

    struct TypeDescriptor* descriptor;

    struct FieldDescriptor* fieldDescriptor;

    descriptor = typeDescriptor;

    Int32 field_descriptor_offset = *reinterpret_cast<Int32*>(&typeDescriptor->field_descriptor);

    UInt64 field_descriptor_address =
        reinterpret_cast<UInt64>(&typeDescriptor->field_descriptor) + field_descriptor_offset;

    fieldDescriptor = reinterpret_cast<struct FieldDescriptor*>(field_descriptor_address);

    type = nullptr;

    switch (fieldDescriptor->kind) {
    case FDK_Struct: {
        struct Struct* structure = new Struct;

        memcpy(&structure->descriptor, typeDescriptor, sizeof(struct TypeDescriptor));

        type = dynamic_cast<struct Type*>(structure);
    }

    break;
    case FDK_Class: {
        struct Class* cls = new Class;

        memcpy(&cls->descriptor, typeDescriptor, sizeof(struct TypeDescriptor));

        type = dynamic_cast<struct Type*>(cls);

        UInt64 typeMetadata = GetTypeMetadata(typeDescriptor);

        if (typeMetadata) {
            objc::ObjCClass* objc_class = objc->GetClassByIsa(typeMetadata);

            if (objc_class) {
                cls->isa = objc_class;

                ParseClassMetadata(cls);
            }
        }
    }

    break;
    case FDK_Enum: {
        struct Enum* enumeration = new Enum;

        memcpy(&enumeration->descriptor, typeDescriptor, sizeof(struct TypeDescriptor));

        type = dynamic_cast<struct Type*>(enumeration);
    }

    break;
    case FDK_MultiPayloadEnum:
        break;
    case FDK_Protocol: {
        struct Protocol* protocol = new Protocol;

        memcpy(&protocol->descriptor, typeDescriptor, sizeof(struct TypeDescriptor));

        type = dynamic_cast<struct Type*>(protocol);
    }

    break;
    case FDK_ClassProtocol:
        break;
    case FDK_ObjCProtocol:
        break;
    case FDK_ObjCClass:
        break;
    default:
        break;
    }

    if (type)
        ParseFieldDescriptor(type, fieldDescriptor);

    return type;
}

UInt64 SwiftABI::GetTypeMetadata(struct TypeDescriptor* typeDescriptor) {
    UInt64 typeMetadata;

    UInt64 accessFunction = typeDescriptor->access_function;

#ifdef __arm64__

    using namespace arch::arm64;

    UInt64 xref = arch::arm64::patchfinder::Step64(macho, accessFunction, 0x100,
                                                   (bool (*)(UInt32*))is_adrp, -1, -1);

    adr_t adrp = *reinterpret_cast<adr_t*>(xref);

    add_imm_t add_imm = *reinterpret_cast<add_imm_t*>(xref + 0x4);

    typeMetadata = (xref & ~0xFFF) + ((((adrp.immhi << 2) | adrp.immlo)) << 12) +
                   (add_imm.sh ? (add_imm.imm << 12) : add_imm.imm);

    return typeMetadata;

#elif __x86_64__
    using namespace arch::x86_64;

    cs_insn insn;

    UInt64 mov = arch::x86_64::patchfinder::Step64(macho, accessFunction, 0x100, "mov", nullptr);

    // arch::x86_64::Disassemble(mov, arch::x86_64::MaxInstruction, &insn);

    // typeMetadata = insn.detail.x86->operands[1].mem.disp + mov;

    return typeMetadata;

#endif
}

void SwiftABI::ParseFieldDescriptor(struct Type* type,
                                         struct FieldDescriptor* fieldDescriptor) {
    struct Fields* fields = new Fields;

    UInt64 field_start = reinterpret_cast<UInt64>(fieldDescriptor) + sizeof(struct FieldDescriptor);

    fields->descriptor = fieldDescriptor;

    for (int i = 0; i < fieldDescriptor->num_fields; i++) {
        struct Field* field = new Field;

        memcpy(&field->record, reinterpret_cast<struct FieldRecord*>(field_start) + i,
               sizeof(struct FieldRecord));

        field->name = "";
        field->mangled_name = "";
        field->demangled_name = "";

        fields->records.push_back(field);

        type->field = field;
    }
}

void SwiftABI::ParseClassMetadata(Class* cls) {}

} // namespace swift