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

#include <vector>

#include <types.h>

#include "objc.h"
#include "dictionary.h"

class MachO;

class Segment;
class Section;

namespace swift {
const unsigned MetadataKindIsNonType = 0x400;

const unsigned MetadataKindIsNonHeap = 0x200;

const unsigned MetadataKindIsRuntimePrivate = 0x100;

enum class ContextDescriptorKind : UInt8 {
    Module = 0,
    Extension = 1,
    Anonymous = 2,
    Protocol = 3,
    OpaqueType = 4,
    Type_First = 16,
    Class = Type_First,
    Struct = Type_First + 1,
    Enum = Type_First + 2,
    Type_Last = 31,
};

enum MetadataKind : UInt16 {
    MK_Class = 0x0,
    MK_Struct = 0x200,
    MK_Enum = 0x201,
    MK_Optional = 0x202,
    MK_ForeignClass = 0x203,
    MK_ForeignReferenceType = 0x204,
    MK_Opaque = 0x300,
    MK_Tuple = 0x301,
    MK_Function = 0x302,
    MK_Existential = 0x303,
    MK_Metatype = 0x304,
    MK_ObjCClassWrapper = 0x305,
    MK_ExistentialMetatype = 0x306,
    MK_ExtendedExistential = 0x307,
    MK_HeapLocalVariable = 0x400,
    MK_HeapGenericLocalVariable = 0x500,
    MK_ErrorObject = 0x501,
    MK_Task = 0x502,
    MK_Job = 0x503,
    MK_LastEnumerated = 0x7FF,
};

enum FieldDescriptorKind : UInt16 {
    FDK_Struct = 0,
    FDK_Class = 1,
    FDK_Enum = 2,
    FDK_MultiPayloadEnum = 3,
    FDK_Protocol = 4,
    FDK_ClassProtocol = 5,
    FDK_ObjCProtocol = 6,
    FDK_ObjCClass = 7,
};

#pragma pack(1)

struct ValueMetadata {
    UInt64 kind;
    UInt64 description;
};

struct ValueWitnessTable {
    UInt64 initializeBufferWithCopyOfBuffer;
    UInt64 destroy;
    UInt64 initializeWithCopy;
    UInt64 assignWithCopy;
    UInt64 initializeWithTake;
    UInt64 assignWithTake;
    UInt64 GetEnumTagSinglePayload;
    UInt64 storeEnumTagSinglePayload;

    Size size;
    Size stride;

    UInt64 flags;
    UInt64 extra_inhabitant_count;
};

struct Type {
    struct ModuleDescriptor* module;

    enum MetadataKind kind;

    char* name;

    struct Field* field;
};

struct TypeDescriptor {
    UInt32 flags;
    Int32 parent;
    Int32 name;
    Int32 access_function;
    UInt32 field_descriptor;
};

struct AnonymousContextDescriptor {
    UInt32 flags;
    UInt32 parent;
};

struct ModuleDescriptor {
    UInt32 flags;
    Int32 parent;
    Int32 name;
};

struct ProtocolDescriptor {
    UInt32 flags;
    Int32 name;
    UInt32 num_requirements_in_signature;
    UInt32 num_requirements;
    Int32 associated_type_names;
};

struct ProtocolConformanceDescriptor {
    Int32 protocol_descriptor;
    Int32 nominal_type_descriptor;
    Int32 protocol_witness_table;
    UInt32 conformance_flags;
};

struct Protocol : Type {
    struct ProtocolDescriptor descriptor;

    char* name;
};

struct ClassDescriptor {
    struct TypeDescriptor type;

    UInt32 super_class_type;

    UInt32 metadata_negative_size_in_words;
    UInt32 metadata_positive_size_in_words;

    UInt32 num_immediate_members;
    UInt32 num_fields;

    UInt32 field_offset_vector_offset;
};

struct MethodDescriptor {
    UInt32 flags;
    Int32 impl;
};

struct Method {
    struct MethodDescriptor* descriptor;

    UInt64 impl;

    char* name;
};

struct ClassMetadata {
    UInt64 destructor;
    UInt64 value_witness_table;

    struct objc::_objc_2_class objc;

    UInt32 flags;
    UInt32 instance_address_point;
    UInt32 instance_size;
    UInt16 instance_alignment_mask;
    UInt16 reserved;
    UInt32 class_object_size;
    UInt32 class_address_point;

    UInt64 type_descriptor;
};

struct Class : Type {
    struct ClassDescriptor descriptor;

    objc::ObjCClass* isa;

    std::vector<Method*> methods;

    objc::ObjCClass* GetObjCClass() {
        return isa;
    }
};

struct StructDescriptor {
    struct TypeDescriptor type;

    UInt32 num_fields;
    UInt32 field_offset_vector_offset;
};

struct Struct : Type {
    struct StructDescriptor descriptor;
};

struct EnumDescriptor {
    struct TypeDescriptor type;

    UInt32 num_payload_cases_and_payload_size_offset;
    UInt32 num_empty_cases;
};

struct Enum : Type {
    struct EnumDescriptor descriptor;
};

struct FieldDescriptor {
    UInt32 type_ref;
    UInt32 mangled_type_name;
    UInt16 kind;
    UInt16 field_record_size;
    UInt32 num_fields;
};

struct FieldRecord {
    UInt32 flags;
    UInt32 mangled_type_name;
    UInt32 field_name;
};

struct Field {
    struct FieldRecord record;

    char* name;

    char* mangled_name;
    char* demangled_name;
};

struct Fields {
    struct FieldDescriptor* descriptor;

    std::vector<struct Field*> records;
};

struct AssociatedTypeRecord {
    Int32 name;
    Int32 substituted_type_name;
};

struct AssociatedTypeDescriptor {
    Int32 conforming_type_name;
    Int32 protocol_type_name;
    UInt32 num_associated_types;
    UInt32 associated_type_record_size;
};

struct BuiltinTypeDescriptor {
    Int32 type_name;
    UInt32 size;
    UInt32 alignment_and_flags;
    UInt32 stride;
    UInt32 num_extra_inhabitants;
};

struct CaptureTypeRecord {
    Int32 mangled_type_name;
};

struct MetadataSourceRecord {
    Int32 mangled_type_name;
    Int32 mangled_metadata_source;
};

struct CaptureDescriptor {
    UInt32 num_capture_types;
    UInt32 num_metadata_sources;
    UInt32 num_bindings;
};

#pragma options align = reset

class SwiftABI {
public:
    explicit SwiftABI(MachO* macho, objc::ObjCData* objc) : macho(macho), objc(objc) {
        PopulateSections();
        ParseSwift();
    }
    explicit SwiftABI(MachO* macho, objc::ObjCData* objc, Segment* text)
        : macho(macho), objc(objc), text(text) {
        PopulateSections();
        ParseSwift();
    }

    std::vector<Type*>* GetAllTypes() {
        return &swift_types;
    }

    objc::ObjCData* GetObjCMetaData() {
        return objc;
    }

    struct Class* GetClass(char* cl);
    struct Struct* GetStruct(char* st);
    struct Enum* GetEnum(char* en);
    struct Protocol* GetProtocol(char* p);

    Segment* GetTextSegment() {
        return text;
    }

    Section* GetTypeRef() {
        return typeref;
    }

    Section* GetEntry() {
        return entry;
    }

    Section* GetBuiltIn() {
        return builtin;
    }

    Section* GetReflStr() {
        return reflstr;
    }

    Section* GetFieldMd() {
        return fieldmd;
    }

    Section* GetAssocty() {
        return assocty;
    }

    Section* GetProto() {
        return proto;
    }

    Section* GetTypes() {
        return types;
    }

    Section* GetProtos() {
        return protos;
    }

    Section* GetCapture() {
        return capture;
    }

    Section* GetMpenum() {
        return mpenum;
    }

    void SetText(Segment* segment) {
        text = segment;
        PopulateSections();
        ParseSwift();
    }

    void PopulateSections();

    void ParseSwift();
    void ParseSwiftObjectiveC();

    void EnumerateTypes();

    UInt64 GetTypeMetadata(struct TypeDescriptor* typeDescriptor);

    struct Type* ParseTypeDescriptor(struct TypeDescriptor* typeDescriptor);

    struct Protocol* ParseProtocolDescriptor(struct ProtocolDescriptor* protocolDescriptor);

    void ParseFieldDescriptor(struct Type* type, struct FieldDescriptor* fieldDescriptor);

    void ParseClassMetadata(Class* cls);

private:
    MachO* macho;

    objc::ObjCData* objc;

    Segment* text;

    std::vector<struct Type*> swift_types;

    std::vector<struct Class*> classes;
    std::vector<struct Struct*> structs;
    std::vector<struct Enum*> enums;
    std::vector<struct Protocol*> protocols;

    Section* typeref;
    Section* entry;
    Section* builtin;
    Section* reflstr;
    Section* fieldmd;
    Section* assocty;
    Section* proto;
    Section* types;
    Section* protos;
    Section* capture;
    Section* mpenum;
};

SwiftABI* ParseSwift(darwin::MachOUserspace* macho);
}; // namespace swift
