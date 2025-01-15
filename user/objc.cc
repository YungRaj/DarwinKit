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

#include <assert.h>
#include <string.h>

namespace objc {

ObjCData* ParseObjectiveC(darwin::MachOUserspace* macho) {
    return new ObjCData(macho);
}

void ParseClassList(ObjCData* data, std::vector<ObjCClass*>& classes) {
    darwin::MachOUserspace* macho = data->GetMachO();

    Section* classlist = data->GetClassList();

    Section* classrefs = data->GetClassRefs();
    Section* superrefs = data->GetSuperRefs();

    Section* ivars = data->GetIvars();
    Section* objc_data = data->GetObjcData();

    Size classlist_size = classlist->GetSize();

    UInt64 address = classlist->GetAddress();

    UInt64 base = macho->GetBase() - data->GetMachO()->GetAslrSlide();

    UInt64 header = reinterpret_cast<UInt64>(macho->GetMachHeader());

    UInt64* clslist = reinterpret_cast<UInt64*>(header + classlist->GetOffset());

    for (UInt64 off = 0; off < classlist_size; off = off + sizeof(UInt64)) {
        ObjCClass* c;
        ObjCClass* metac;

        UInt64 cls = macho->GetBufferAddress(((*(clslist + off / sizeof(UInt64))) & 0xFFFFFFFFFFF) -
                                             macho->GetAslrSlide());

        if (!cls) {
            cls = header + *(clslist + off / sizeof(UInt64)) & 0xFFFFFFFFFFF;
        }

        struct _objc_2_class* objc_class = reinterpret_cast<struct _objc_2_class*>(cls);

        if (objc_class) {
            c = new ObjCClass(data, objc_class, false);

            if (c->IsValid()) {
                classes.push_back(c);
            }
        }

        struct _objc_2_class* objc_metaclass =
            reinterpret_cast<struct _objc_2_class*>((objc_class->isa & 0xFFFFFFFF) + header);

        if (objc_metaclass && objc_class != objc_metaclass) {
            metac = new ObjCClass(data, objc_metaclass, true);

            if (metac->IsValid()) {
                classes.push_back(metac);
            }
        }
    }
}

void ParseCategoryList(ObjCData* data, std::vector<Category*>& categories) {
    darwin::MachOUserspace* macho = data->GetMachO();

    Section* catlist = data->GetCategoryList();

    Size catlist_size = catlist->GetSize();

    UInt64 base = macho->GetBase() - data->GetMachO()->GetAslrSlide();

    UInt64 header = reinterpret_cast<UInt64>(macho->GetMachHeader());

    UInt64 address = catlist->GetAddress();

    UInt64* categorylist = reinterpret_cast<UInt64*>(header + catlist->GetOffset());

    for (UInt64 off = 0; off < catlist_size; off = off + sizeof(UInt64)) {
        Category* cat;

        UInt64 category = macho->GetBufferAddress(
            (*(categorylist + off / sizeof(UInt64)) & 0xFFFFFFFFFFF) - macho->GetAslrSlide());

        if (!category) {
            category = header + (*(categorylist + off / sizeof(UInt64)) & 0xFFFFFFFFFFF);
        }

        struct _objc_2_category* objc_category =
            reinterpret_cast<struct _objc_2_category*>(category);

        if (category) {
            if (!(objc_category->class_name & 0x4000000000000000)) {
                cat = new Category(data, objc_category);

                categories.push_back(cat);
            }
        }
    }
}

void ParseProtocolList(ObjCData* data, std::vector<Protocol*>& protocols) {
    darwin::MachOUserspace* macho = data->GetMachO();

    Section* protlist = data->GetProtocolList();

    Section* protrefs = data->GetProtoRefs();

    Size protolist_size = protlist->GetSize();

    UInt64 base = macho->GetBase() - data->GetMachO()->GetAslrSlide();

    UInt64 header = reinterpret_cast<UInt64>(macho->GetMachHeader());

    UInt64 address = protlist->GetAddress();

    UInt64* protolist = reinterpret_cast<UInt64*>(header + protlist->GetOffset());

    for (UInt64 off = 0; off < protolist_size; off = off + sizeof(UInt64)) {
        Protocol* p;

        UInt64 proto = macho->GetBufferAddress(
            ((*(protolist + off / sizeof(UInt64))) & 0xFFFFFFFFFFF) - macho->GetAslrSlide());

        if (!proto) {
            proto = header + *(protolist + off / sizeof(UInt64)) & 0xFFFFFFFFFFF;
        }

        struct _objc_2_class_protocol* objc_protocol =
            reinterpret_cast<struct _objc_2_class_protocol*>(proto);

        if (objc_protocol) {
            p = new Protocol(data, objc_protocol);

            protocols.push_back(p);
        }
    }
}

void ParseMethodList(ObjCData* metadata, ObjC* object, std::vector<Method*>& methodList,
                     enum MethodType methtype, struct _objc_2_class_method_info* methodInfo) {
    darwin::MachOUserspace* macho = metadata->GetMachO();

    struct _objc_2_class_method_info* methods;

    Offset off;

    UInt64 selectors = macho->IsDyldCache() ? objc::FindSelectorsBase(macho) : 0;

    if (!methodInfo) {
        return;
    }

    methods = reinterpret_cast<struct _objc_2_class_method_info*>(methodInfo);

    off = sizeof(struct _objc_2_class_method_info);

    char* type = "";
    char* prefix = "";

    switch (methtype) {
    case INSTANCE_METHOD:
        type = "Instance";
        prefix = "-";

        break;
    case CLASS_METHOD:
        type = "Class";
        prefix = "+";

        break;
    case OPT_INSTANCE_METHOD:
        type = "Optional Instance";
        prefix = "-";

        break;
    case OPT_CLASS_METHOD:
        type = "Optional Class";
        prefix = "+";

        break;
    default:
        break;
    }

    DARWIN_KIT_LOG("\t\t\t%s Methods\n", type);

    for (int i = 0; i < methods->count; i++) {
        UInt64 pointer_to_name;
        UInt64 offset_to_name;

        UInt8* q = reinterpret_cast<UInt8*>(reinterpret_cast<UInt8*>(methods) + off);

        if (macho->IsDyldCache() && dynamic_cast<Protocol*>(object)) {
            struct _objc_2_method* method = reinterpret_cast<struct _objc_2_method*>(q);

            Method* meth = new Method(object, method);

            DARWIN_KIT_LOG("\t\t\t\t0x%08llx: %s%s\n", meth->GetImpl(), prefix, meth->GetName());

            methodList.push_back(meth);

            off += sizeof(struct _objc_2_method);

            continue;
        } else if (macho->IsDyldCache()) {
            struct _objc_2_class_method* method = reinterpret_cast<struct _objc_2_class_method*>(q);

            pointer_to_name = selectors + method->name;

            if (macho->GetObjectiveCLibrary()->GetBufferAddress(pointer_to_name)) {
                Method* meth = new Method(object, method);

                methodList.push_back(meth);

                DARWIN_KIT_LOG("\t\t\t\t0x%08llx: %s%s\n", meth->GetImpl(), prefix, meth->GetName());
            }

        } else {
            struct _objc_2_class_method* method = reinterpret_cast<struct _objc_2_class_method*>(q);

            pointer_to_name = reinterpret_cast<UInt64>(macho->GetMachHeader()) +
                              reinterpret_cast<UInt32>(method->name & 0xFFFFFF);

            offset_to_name = ((*(UInt64*)pointer_to_name) & 0xFFFFFF);

            Method* meth = new Method(object, method);

            methodList.push_back(meth);

            DARWIN_KIT_LOG("\t\t\t\t0x%08llx: %s%s\n", meth->GetImpl(), prefix, meth->GetName());
        }

        off += sizeof(struct _objc_2_class_method);
    }
}

void ParsePropertyList(ObjCData* metadata, ObjC* object, std::vector<Property*>& propertyList,
                       struct _objc_2_class_property_info* propertyInfo) {
    struct _objc_2_class_property_info* properties;

    Offset off;

    if (!propertyInfo) {
        return;
    }

    properties = reinterpret_cast<struct _objc_2_class_property_info*>(propertyInfo);

    off = sizeof(struct _objc_2_class_property_info);

    DARWIN_KIT_LOG("\t\t\tProperties\n");

    for (int i = 0; i < properties->count; i++) {
        struct _objc_2_class_property* property = reinterpret_cast<struct _objc_2_class_property*>(
            reinterpret_cast<UInt8*>(properties) + off);

        Property* prop = new Property(object, property);

        propertyList.push_back(prop);

        DARWIN_KIT_LOG("\t\t\t\t%s %s\n", prop->GetAttributes(), prop->GetName());

        off += sizeof(struct _objc_2_class_property);
    }
}
} // namespace objc

namespace objc {

ObjCClass::ObjCClass(ObjCData* metadata, struct _objc_2_class* c, bool metaclass) {
    metadata = metadata;
    macho = metadata->GetMachO();
    metaclass = metaclass;
    cls = c;
    super = nullptr;

    data = reinterpret_cast<struct _objc_2_class_data*>((UInt64)c->data & 0xFFFFFFF8);

    if (macho->SectionForOffset(reinterpret_cast<UInt64>(data))) {
        data = reinterpret_cast<struct _objc_2_class_data*>(
            (UInt64)data + reinterpret_cast<UInt64>(macho->GetMachHeader()));
        name = reinterpret_cast<char*>((data->name & 0xFFFFFFFF) +
                                       reinterpret_cast<UInt64>(macho->GetMachHeader()));

        if (macho->SectionForOffset(reinterpret_cast<UInt64>((data->name & 0xFFFFFFFF)))) {
            if (metaclass)
                printf("\t\t$OBJC_METACLASS_%s\n", name);
            else
                printf("\t\t$OBJC_CLASS_%s\n", name);

            isa = reinterpret_cast<UInt64>(c->isa);
            superclass = reinterpret_cast<UInt64>(c->superclass);
            cache = reinterpret_cast<UInt64>(c->cache);
            vtable = reinterpret_cast<UInt64>(c->vtable);

            ParseMethods();
            ParseIvars();
            ParseProperties();
        }

    } else if (macho->SectionForAddress(reinterpret_cast<UInt64>(((UInt64)c->data & 0xFFFFFFFFF) -
                                                                 macho->GetAslrSlide()))) {
        data = reinterpret_cast<struct _objc_2_class_data*>(
            macho->GetBufferAddress(((UInt64)c->data & 0xFFFFFFFFF) - macho->GetAslrSlide()));

        name = reinterpret_cast<char*>(macho->GetBufferAddress(data->name - macho->GetAslrSlide()));

        if (metaclass)
            printf("\t\t$OBJC_METACLASS_%s\n", name);
        else
            printf("\t\t$OBJC_CLASS_%s\n", name);

        isa = reinterpret_cast<UInt64>(c->isa);
        superclass = reinterpret_cast<UInt64>(c->superclass);
        cache = reinterpret_cast<UInt64>(c->cache);
        vtable = reinterpret_cast<UInt64>(c->vtable);

        ParseMethods();
        ParseIvars();
        ParseProperties();
    } else {
        name = nullptr;
        data = nullptr;
        isa = 0;
        superclass = 0;
        vtable = 0;
        cache = 0;
    }
}

Protocol::Protocol(ObjCData* data, struct _objc_2_class_protocol* prot) {
    darwin::MachOUserspace* macho;

    struct _objc_2_class_method_info* instanceMethods;
    struct _objc_2_class_method_info* classMethods;

    struct _objc_2_class_method_info* optionalInstanceMethods;
    struct _objc_2_class_method_info* optionalClassMethods;

    struct _objc_2_class_property_info* instanceProperties;

    metadata = data;
    protocol = prot;

    macho = metadata->GetMachO();

    if (macho->IsDyldCache()) {
        name = reinterpret_cast<char*>(macho->GetBufferAddress(prot->name - macho->GetAslrSlide()));

        printf("\t\t$OBJC_PROTOCOL_%s\n", name);

        if (prot->instance_methods) {
            instanceMethods = reinterpret_cast<struct _objc_2_class_method_info*>(
                macho->GetBufferAddress(protocol->instance_methods - macho->GetAslrSlide()));

            objc::ParseMethodList(metadata, this, GetInstanceMethods(),
                                        INSTANCE_METHOD, instanceMethods);
        }

        if (prot->class_methods) {
            classMethods = reinterpret_cast<struct _objc_2_class_method_info*>(
                macho->GetBufferAddress(protocol->class_methods - macho->GetAslrSlide()));

            objc::ParseMethodList(metadata, this, GetClassMethods(), CLASS_METHOD,
                                        classMethods);
        }

        if (prot->opt_instance_methods) {
            optionalInstanceMethods =
                reinterpret_cast<struct _objc_2_class_method_info*>(macho->GetBufferAddress(
                    protocol->opt_instance_methods - macho->GetAslrSlide()));

            objc::ParseMethodList(metadata, this, GetOptionalInstanceMethods(),
                                        OPT_INSTANCE_METHOD, optionalInstanceMethods);
        }

        if (prot->opt_class_methods) {
            optionalClassMethods = reinterpret_cast<struct _objc_2_class_method_info*>(
                macho->GetBufferAddress(protocol->opt_class_methods - macho->GetAslrSlide()));

            objc::ParseMethodList(metadata, this, GetOptionalClassMethods(),
                                        OPT_CLASS_METHOD, optionalClassMethods);
        }

        if (prot->instance_properties) {
            instanceProperties =
                reinterpret_cast<struct _objc_2_class_property_info*>(macho->GetBufferAddress(
                    protocol->instance_properties - macho->GetAslrSlide()));

            objc::ParsePropertyList(metadata, this, GetInstanceProperties(),
                                          instanceProperties);
        }
    } else {
        name = reinterpret_cast<char*>((prot->name & 0xFFFFFFF) +
                                             reinterpret_cast<UInt64>(macho->GetMachHeader()));

        printf("\t\t$OBJC_PROTOCOL_%s\n", name);

        if (prot->instance_methods) {
            instanceMethods = reinterpret_cast<struct _objc_2_class_method_info*>(
                (protocol->instance_methods & 0xFFFFFFF) +
                reinterpret_cast<UInt64>(macho->GetMachHeader()));

            objc::ParseMethodList(metadata, this, GetInstanceMethods(),
                                        INSTANCE_METHOD, instanceMethods);
        }

        if (prot->class_methods) {
            classMethods = reinterpret_cast<struct _objc_2_class_method_info*>(
                (protocol->class_methods & 0xFFFFFFF) +
                reinterpret_cast<UInt64>(macho->GetMachHeader()));

            objc::ParseMethodList(metadata, this, GetClassMethods(), CLASS_METHOD,
                                        classMethods);
        }

        if (prot->opt_instance_methods) {
            optionalInstanceMethods = reinterpret_cast<struct _objc_2_class_method_info*>(
                (protocol->opt_instance_methods & 0xFFFFFFF) +
                reinterpret_cast<UInt64>(macho->GetMachHeader()));

            objc::ParseMethodList(metadata, this, GetOptionalInstanceMethods(),
                                        OPT_INSTANCE_METHOD, optionalInstanceMethods);
        }

        if (prot->opt_class_methods) {
            optionalClassMethods = reinterpret_cast<struct _objc_2_class_method_info*>(
                (protocol->opt_class_methods & 0xFFFFFFF) +
                reinterpret_cast<UInt64>(macho->GetMachHeader()));

            objc::ParseMethodList(metadata, this, GetOptionalClassMethods(),
                                        OPT_CLASS_METHOD, optionalClassMethods);
        }

        if (prot->instance_properties) {
            instanceProperties = reinterpret_cast<struct _objc_2_class_property_info*>(
                (protocol->instance_properties & 0xFFFFFFF) +
                reinterpret_cast<UInt64>(macho->GetMachHeader()));

            objc::ParsePropertyList(metadata, this, GetInstanceProperties(),
                                          instanceProperties);
        }
    }
}

Category::Category(ObjCData* data, struct _objc_2_category* cat) {
    darwin::MachOUserspace* macho = data->GetMachO();

    struct _objc_2_class_method_info* instanceMethods;
    struct _objc_2_class_method_info* classMethods;

    struct _objc_2_class_property_info* catProperties;

    metadata = data;
    category = cat;

    if (macho->IsDyldCache()) {
        name = reinterpret_cast<char*>(
            macho->GetBufferAddress(cat->category_name - macho->GetAslrSlide()));

        if (!name) {
            name = reinterpret_cast<char*>(macho->GetObjectiveCLibrary()->GetBufferAddress(
                cat->category_name - macho->GetAslrSlide()));
        }

        ObjCClass* isa = data->GetClassByName(name);

        if (isa) {
            class_name = isa->GetName();
        } else {
            class_name = "UNKNOWN";
        }

        printf("\t\t$OBJC_CATEGORY_%s+%s\n", class_name, "extra");

        if (cat->instance_methods) {
            instanceMethods = reinterpret_cast<struct _objc_2_class_method_info*>(
                macho->GetBufferAddress(category->instance_methods - macho->GetAslrSlide()));

            objc::ParseMethodList(metadata, this, GetInstanceMethods(),
                                        INSTANCE_METHOD, instanceMethods);
        }

        if (cat->class_methods) {
            classMethods = reinterpret_cast<struct _objc_2_class_method_info*>(
                macho->GetBufferAddress(category->class_methods - macho->GetAslrSlide()));

            objc::ParseMethodList(metadata, this, GetClassMethods(), CLASS_METHOD,
                                        classMethods);
        }

        if (cat->properties) {
            catProperties = reinterpret_cast<struct _objc_2_class_property_info*>(
                macho->GetBufferAddress(category->properties - macho->GetAslrSlide()));

            objc::ParsePropertyList(metadata, this, GetProperties(),
                                          catProperties);
        }

    } else {
        name = reinterpret_cast<char*>((cat->category_name & 0xFFFFFFF) +
                                       reinterpret_cast<UInt64>(macho->GetMachHeader()));

        if (!(cat->class_name & 0x4000000000000000)) {
            UInt64 cls =
                ((cat->class_name & 0xFFFFFFF) + reinterpret_cast<UInt64>(macho->GetMachHeader()));

            ObjCClass* isa = data->GetClassByIsa((UInt64)cls);

            if (isa) {
                class_name = isa->GetName();
            } else {
                class_name = "UNKNOWN";
            }
        } else {
            class_name = "UNKNOWN";
        }

        printf("\t\t$OBJC_CATEGORY_%s+%s\n", class_name, name);

        if (cat->instance_methods) {
            instanceMethods = reinterpret_cast<struct _objc_2_class_method_info*>(
                (category->instance_methods & 0xFFFFFFF) +
                reinterpret_cast<UInt64>(macho->GetMachHeader()));

            objc::ParseMethodList(metadata, this, GetInstanceMethods(),
                                        INSTANCE_METHOD, instanceMethods);
        }

        if (cat->class_methods) {
            classMethods = reinterpret_cast<struct _objc_2_class_method_info*>(
                (category->class_methods & 0xFFFFFFF) +
                reinterpret_cast<UInt64>(macho->GetMachHeader()));

            objc::ParseMethodList(metadata, this, GetClassMethods(), CLASS_METHOD,
                                        classMethods);
        }

        if (cat->properties) {
            catProperties = reinterpret_cast<struct _objc_2_class_property_info*>(
                (category->properties & 0xFFFFFFF) +
                reinterpret_cast<UInt64>(macho->GetMachHeader()));

            objc::ParsePropertyList(metadata, this, GetProperties(),
                                          catProperties);
        }
    }
}

Ivar::Ivar(ObjC* object, struct _objc_2_class_ivar* ivar) {
    darwin::MachOUserspace* macho = object->GetMetadata()->GetMachO();

    if (macho->IsDyldCache()) {
        object = object;
        ivar = ivar;
        name = reinterpret_cast<char*>(macho->GetBufferAddress(ivar->name - macho->GetAslrSlide()));

        if (!name) {
            name = reinterpret_cast<char*>(macho->GetObjectiveCLibrary()->GetBufferAddress(
                ivar->name - macho->GetAslrSlide()));
        }

        offset = ivar->offset - macho->GetAslrSlide();
        type = ivar->type;
        size = ivar->size;

    } else {
        object = object;
        ivar = ivar;
        offset = reinterpret_cast<UInt64>((ivar->offset & 0xFFFFFF) +
                                          reinterpret_cast<UInt64>(macho->GetMachHeader()));
        name = reinterpret_cast<char*>((ivar->name & 0xFFFFFF) +
                                       reinterpret_cast<char*>(macho->GetMachHeader()));
        type = ivar->type;
        size = ivar->size;
    }
}

Property::Property(ObjC* object, struct _objc_2_class_property* property) {
    darwin::MachOUserspace* macho = object->GetMetadata()->GetMachO();

    if (macho->IsDyldCache()) {
        object = object;
        property = property;
        name = reinterpret_cast<char*>(
            macho->GetBufferAddress(property->name - macho->GetAslrSlide()));

        if (!name) {
            name = reinterpret_cast<char*>(macho->GetObjectiveCLibrary()->GetBufferAddress(
                property->name - macho->GetAslrSlide()));
        }

        attributes = reinterpret_cast<char*>(
            macho->GetBufferAddress(property->attributes - macho->GetAslrSlide()));

        if (!attributes) {
            attributes = reinterpret_cast<char*>(macho->GetObjectiveCLibrary()->GetBufferAddress(
                property->attributes - macho->GetAslrSlide()));
        }

    } else {
        object = object;
        property = property;
        name = reinterpret_cast<char*>((property->name & 0xFFFFFF) +
                                       reinterpret_cast<char*>(macho->GetMachHeader()));
        attributes = reinterpret_cast<char*>((property->attributes & 0xFFFFFF) +
                                             reinterpret_cast<char*>(macho->GetMachHeader()));
    }
}

Method::Method(ObjC* object, struct _objc_2_class_method* method) {
    darwin::MachOUserspace* macho = object->GetMetadata()->GetMachO();

    UInt64 selectors;

    UInt64 pointer_to_type;

    UInt64 pointer_to_name;

    object = object;
    method = method;

    selectors = objc::FindSelectorsBase(macho);

    if (macho->IsDyldCache() && selectors) {
        pointer_to_name = selectors + method->name;

        pointer_to_name = macho->GetObjectiveCLibrary()->GetBufferAddress(pointer_to_name);

        name = reinterpret_cast<char*>(pointer_to_name);

        pointer_to_type = macho->OffsetToAddress((UInt64)&method->type -
                                                 reinterpret_cast<UInt64>(macho->GetMachHeader()));

        pointer_to_type += method->type;

        pointer_to_type = macho->GetBufferAddress(pointer_to_type);

        if (!pointer_to_type) {
            pointer_to_type = macho->GetObjectiveCLibrary()->GetBufferAddress(pointer_to_type);
        }

        type = pointer_to_type;

        impl = reinterpret_cast<UInt64>(
            method->imp + macho->OffsetToAddress(reinterpret_cast<UInt64>(&method->imp) -
                                                 reinterpret_cast<UInt64>(macho->GetMachHeader())));
    } else {
        if (dynamic_cast<ObjCClass*>(object) || dynamic_cast<Category*>(object)) {
            pointer_to_name = reinterpret_cast<UInt64>(&method->name) +
                              reinterpret_cast<UInt32>(method->name & 0xFFFFFF);

            pointer_to_name = reinterpret_cast<UInt64>(macho->GetMachHeader()) +
                              ((*(UInt64*)pointer_to_name) & 0xFFFFFF);
        } else {
            pointer_to_name = reinterpret_cast<UInt64>(macho->GetMachHeader()) +
                              reinterpret_cast<UInt32>(method->name & 0xFFFFFF);
        }

        name = reinterpret_cast<char*>(pointer_to_name);
        impl = reinterpret_cast<UInt64>((method->imp & 0xFFFFFF) +
                                        reinterpret_cast<UInt64>(macho->GetMachHeader()));
        type = method->type;
    }
}

Method::Method(ObjC* object, struct _objc_2_method* method) {
    darwin::MachOUserspace* macho = object->GetMetadata()->GetMachO();

    object = object;

    name = reinterpret_cast<char*>(macho->GetBufferAddress(method->name - macho->GetAslrSlide()));

    if (!name) {
        name = reinterpret_cast<char*>(
            macho->GetObjectiveCLibrary()->GetBufferAddress(method->name - macho->GetAslrSlide()));
    }

    impl = method->imp ? method->imp - macho->GetAslrSlide() : 0;
    type = macho->GetBufferAddress(method->type - macho->GetAslrSlide());
}
} // namespace objc

#ifdef __arm64__

#include <arm64/isa_arm64.h>
#include <arm64/patch_finder_arm64.h>

#elif __x86_64__

#include <x86_64/isa_x86_64.h>
#include <x86_64/patch_finder_x86_64.h>

#endif

namespace objc {

UInt64 FindSelectorsBase(darwin::MachOUserspace* macho) {
    UInt64 selectors;

    UInt64 method_getName;

    darwin::MachOUserspace* libobjc;

    Symbol* symbol;

    libobjc = macho->GetObjectiveCLibrary();

    if (!libobjc) {
        return 0;
    }

    symbol = libobjc->GetSymbolByName("_method_getName");

    if (!symbol) {
        return 0;
    }

    method_getName = symbol->GetAddress();

    if (!method_getName) {
        return 0;
    }

    UInt64 start = libobjc->GetBufferAddress(method_getName);

#ifdef __arm64__

    using namespace arch::arm64;

    UInt64 add = arch::arm64::patchfinder::Step64(libobjc, start, 0x100,
                                                  (bool (*)(UInt32*))is_add_reg, -1, -1);

    UInt64 xref = arch::arm64::patchfinder::StepBack64(libobjc, add, 0x100,
                                                       (bool (*)(UInt32*))is_adrp, -1, -1);

    adr_t adrp = *reinterpret_cast<adr_t*>(xref);

    add_imm_t add_imm = *reinterpret_cast<add_imm_t*>(xref + 0x4);

    selectors = (xref & ~0xFFF) + ((((adrp.immhi << 2) | adrp.immlo)) << 12) +
                (add_imm.sh ? (add_imm.imm << 12) : add_imm.imm);

    return (selectors - start) + method_getName;

#elif __x86_64__

    using namespace arch::x86_64;

    cs_insn insn;

    UInt64 add = arch::x86_64::patchfinder::Step64(libobjc, start, 0x100, "add", nullptr);

    UInt64 mov = arch::x86_64::patchfinder::StepBack64(libobjc, add, 0x100, "mov", nullptr);

    // arch::x86_64::Disassemble(mov, arch::x86_64::MaxInstruction, &insn);

    // UInt64 selectors = insn.detail.x86->operands[1].mem.disp + mov;

    return selectors;

#endif
}

Protocol* ObjCClass::GetProtocol(char* protocolname) {
    for (int i = 0; i < GetProtocols().size(); i++) {
        Protocol* protocol = GetProtocols().at(i);

        if (strcmp(protocol->GetName(), protocolname) == 0) {
            return protocol;
        }
    }

    return nullptr;
}

Method* ObjCClass::GetMethod(char* methodname) {
    for (int i = 0; i < GetMethods().size(); i++) {
        Method* method = GetMethods().at(i);

        if (strcmp(method->GetName(), methodname) == 0) {
            return method;
        }
    }

    return nullptr;
}

Ivar* ObjCClass::GetIvar(char* ivarname) {
    for (int i = 0; i < GetIvars().size(); i++) {
        Ivar* ivar = GetIvars().at(i);

        if (strcmp(ivar->GetName(), ivarname) == 0) {
            return ivar;
        }
    }

    return nullptr;
}

Property* ObjCClass::GetProperty(char* propertyname) {
    for (int i = 0; i < GetProperties().size(); i++) {
        Property* property = GetProperties().at(i);

        if (strcmp(property->GetName(), propertyname) == 0) {
            return property;
        }
    }

    return nullptr;
}

void ObjCClass::ParseMethods() {
    struct _objc_2_class* c;

    struct _objc_2_class_data* d;

    struct _objc_2_class_method_info* meths;

    UInt64 selectors = 0;

    Offset off;

    c = cls;

    d = data;

    if (!d->methods) {
        return;
    }

    if (macho->IsDyldCache()) {
        selectors = objc::FindSelectorsBase(macho);
    }

    meths = nullptr;

    if (macho->IsDyldCache()) {
        meths = reinterpret_cast<struct _objc_2_class_method_info*>(macho->GetBufferAddress(
            (d->methods & 0xFFFFFFFFFF) - macho->GetAslrSlide()));
    } else {
        meths = reinterpret_cast<struct _objc_2_class_method_info*>(
            (d->methods & 0xFFFFFFFFF) + reinterpret_cast<UInt64>(macho->GetMachHeader()));
    }

    if (!meths) {
        return;
    }

    off = sizeof(struct _objc_2_class_method_info);

    DARWIN_KIT_LOG("\t\t\tMethods\n");

    for (int i = 0; i < meths->count; i++) {
        struct _objc_2_class_method* method =
            reinterpret_cast<struct _objc_2_class_method*>(reinterpret_cast<UInt8*>(meths) + off);

        UInt64 pointer_to_name;
        UInt64 offset_to_name;

        if (selectors) {
            pointer_to_name = selectors + method->name;

            if (macho->GetObjectiveCLibrary()->GetBufferAddress(pointer_to_name)) {
                Method* meth = new Method(this, method);

                methods.push_back(meth);

                if (metaclass) {
                    DARWIN_KIT_LOG("\t\t\t\t0x%08llx: +%s\n", meth->GetImpl(), meth->GetName());
                } else {
                    DARWIN_KIT_LOG("\t\t\t\t0x%08llx: -%s\n", meth->GetImpl(), meth->GetName());
                }
            }

        } else {
            pointer_to_name = reinterpret_cast<UInt64>(&method->name) +
                              reinterpret_cast<UInt32>(method->name & 0xFFFFFFFF);

            offset_to_name = ((*(UInt64*)pointer_to_name));

            if (offset_to_name) {
                Section* sect = macho->SectionForOffset(offset_to_name);

                if (sect && strcmp(sect->GetSectionName(), "__objc_methname") == 0) {
                    Method* meth = new Method(this, method);

                    methods.push_back(meth);

                    if (metaclass) {
                        DARWIN_KIT_LOG("\t\t\t\t0x%08llx: +%s\n", meth->GetImpl(), meth->GetName());
                    } else {
                        DARWIN_KIT_LOG("\t\t\t\t0x%08llx: -%s\n", meth->GetImpl(), meth->GetName());
                    }
                }
            }
        }

        off += sizeof(struct _objc_2_class_method);
    }
}

void ObjCClass::ParseProtocols() {
    struct _objc_2_class* c;

    struct _objc_2_class_data* d;

    struct _objc_2_class_protocol_info* protocols;

    Offset off;

    c = cls;

    d = data;

    protocols = reinterpret_cast<struct _objc_2_class_protocol_info*>(data->protocols);

    off = sizeof(struct _objc_2_class_protocol_info);
}

void ObjCClass::ParseIvars() {
    struct _objc_2_class* c;

    struct _objc_2_class_data* d;

    struct _objc_2_class_ivar_info* ivs;

    Offset off;

    c = cls;

    d = data;

    if (!d->ivars) {
        return;
    }

    ivs = nullptr;

    if (macho->IsDyldCache()) {
        ivs = reinterpret_cast<struct _objc_2_class_ivar_info*>(
            macho->GetBufferAddress(d->ivars - macho->GetAslrSlide()));
    } else {
        ivs = reinterpret_cast<struct _objc_2_class_ivar_info*>(
            (d->ivars & 0xFFFFFFFF) + reinterpret_cast<UInt64>(macho->GetMachHeader()));
    }

    if (!ivs) {
        return;
    }

    off = sizeof(struct _objc_2_class_ivar_info);

    DARWIN_KIT_LOG("\t\t\tIvars\n");

    for (int i = 0; i < ivs->count; i++) {
        struct _objc_2_class_ivar* ivar =
            reinterpret_cast<struct _objc_2_class_ivar*>(reinterpret_cast<UInt8*>(ivs) + off);

        Ivar* iv = new Ivar(this, ivar);

        ivars.push_back(iv);

        DARWIN_KIT_LOG("\t\t\t\t0x%08llx: %s\n", iv->GetOffset(), iv->GetName());

        off += sizeof(struct _objc_2_class_ivar);
    }
}

void ObjCClass::ParseProperties() {
    struct _objc_2_class* c;

    struct _objc_2_class_data* d;

    struct _objc_2_class_property_info* props;

    Offset off;

    c = cls;

    d = data;

    if (!d->properties) {
        return;
    }

    props = nullptr;

    if (macho->IsDyldCache()) {
        props = reinterpret_cast<struct _objc_2_class_property_info*>(
            macho->GetBufferAddress(d->properties - macho->GetAslrSlide()));
    } else {
        props = reinterpret_cast<struct _objc_2_class_property_info*>(
            (d->properties & 0xFFFFFFFF) + reinterpret_cast<UInt64>(macho->GetMachHeader()));
    }

    if (!props) {
        return;
    }

    off = sizeof(struct _objc_2_class_property_info);

    DARWIN_KIT_LOG("\t\t\tProperties\n");

    for (int i = 0; i < props->count; i++) {
        struct _objc_2_class_property* property = reinterpret_cast<struct _objc_2_class_property*>(
            reinterpret_cast<UInt8*>(props) + off);

        Property* prop = new Property(this, property);

        properties.push_back(prop);

        DARWIN_KIT_LOG("\t\t\t\t%s %s\n", prop->GetAttributes(), prop->GetName());

        off += sizeof(struct _objc_2_class_property);
    }
}
} // namespace objc

namespace objc {

static char kDataSegment[] = "__DATA";
static char kDataConstSegment[] = "__DATA_CONST";

static char kObjCClassList[] = "__objc_classlist";
static char kObjCCatList[] = "__objc_catlist";
static char kObjCProtoList[] = "__objc_protolist";
static char kObjCSelRefs[] = "__objc_selrefs";
static char kObjCCProtorefs[] = "__objc_protorefs";
static char kObjCClassRefs[] = "__objc_classrefs";
static char kObjCSuperRefs[] = "__objc_superrefs";
static char kObjCIvar[] = "__objc_ivar";
static char kObjCData[] = "__objc_data";

void ObjCData::ParseObjC() {
    data = macho->GetSegment(kDataSegment);
    data_const = macho->GetSegment(kDataConstSegment);

    classlist = macho->GetSection(kDataConstSegment, kObjCClassList);
    catlist = macho->GetSection(kDataConstSegment, kObjCCatList);
    protolist = macho->GetSection(kDataConstSegment, kObjCProtoList);

    selrefs = macho->GetSection(kDataSegment, kObjCSelRefs);
    protorefs = macho->GetSection(kDataSegment, kObjCCProtorefs);
    classrefs = macho->GetSection(kDataSegment, kObjCClassRefs);
    superrefs = macho->GetSection(kDataSegment, kObjCSuperRefs);

    ivar = macho->GetSection(kDataSegment, kObjCIvar);
    objc_data = macho->GetSection(kDataSegment, kObjCData);

    assert(data);
    assert(data);

    assert(classlist);

    assert(selrefs);

    assert(ivar);
    assert(objc_data);

    ParseClassList(this, classes);

    if (protolist)
        ParseProtocolList(this, protocols);

    if (catlist)
        ParseCategoryList(this, categories);

    if (!macho->IsDyldCache()) {
        // do not Parse categories and protocols when dyld cache is being Parsed
        // all of the class pointers will be invalid because they will exist in other libraries
        // we aren't going to need categories during runtime anyways
    }
}

ObjCClass* ObjCData::GetClassByName(char* classname) {
    for (int i = 0; i < classes.size(); i++) {
        ObjCClass* cls = classes.at(i);

        if (cls->GetName() && strcmp(cls->GetName(), classname) == 0) {
            return cls;
        }
    }

    return nullptr;
}

ObjCClass* ObjCData::GetClassByIsa(UInt64 isa) {
    for (int i = 0; i < classes.size(); i++) {
        ObjCClass* cls = classes.at(i);

        if (reinterpret_cast<UInt64>(cls->GetClass()) == isa) {
            return cls;
        }
    }

    return nullptr;
}

Protocol* ObjCData::GetProtocol(char* protoname) {
    for (int i = 0; i < protocols.size(); i++) {
        Protocol* protocol = protocols.at(i);

        if (strcmp(protocol->GetName(), protoname) == 0) {
            return protocol;
        }
    }

    return nullptr;
}

Category* ObjCData::GetCategory(char* catname) {
    for (int i = 0; i < categories.size(); i++) {
        Category* category = categories.at(i);

        if (strcmp(category->GetName(), catname) == 0) {
            return category;
        }
    }

    return nullptr;
}

Method* ObjCData::GetMethod(char* classname, char* methodname) {
    ObjCClass* cls = GetClassByName(classname);

    return cls ? cls->GetMethod(methodname) : nullptr;
}

Ivar* ObjCData::GetIvar(char* classname, char* ivarname) {
    ObjCClass* cls = GetClassByName(classname);

    return cls ? cls->GetIvar(ivarname) : nullptr;
}

Property* ObjCData::GetProperty(char* classname, char* propertyname) {
    ObjCClass* cls = GetClassByName(classname);

    return cls ? cls->GetProperty(propertyname) : nullptr;
}

} // namespace objc