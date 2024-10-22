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
#include "user_macho.h"

#include "pac.h"

#include <assert.h>
#include <string.h>

namespace objc {

ObjCData* parseObjectiveC(darwin::UserMachO* macho) {
    return new ObjCData(macho);
}

void parseClassList(ObjCData* data, std::vector<ObjCClass*>& classes) {
    darwin::UserMachO* macho = data->getMachO();

    Section* classlist = data->getClassList();

    Section* classrefs = data->getClassRefs();
    Section* superrefs = data->getSuperRefs();

    Section* ivars = data->getIvars();
    Section* objc_data = data->getObjcData();

    Size classlist_size = classlist->getSize();

    UInt64 address = classlist->getAddress();

    UInt64 base = macho->getBase() - data->getMachO()->getAslrSlide();

    UInt64 header = reinterpret_cast<UInt64>(macho->getMachHeader());

    UInt64* clslist = reinterpret_cast<UInt64*>(header + classlist->getOffset());

    for (UInt64 off = 0; off < classlist_size; off = off + sizeof(UInt64)) {
        ObjCClass* c;
        ObjCClass* metac;

        UInt64 cls = macho->getBufferAddress(((*(clslist + off / sizeof(UInt64))) & 0xFFFFFFFFFFF) -
                                             macho->getAslrSlide());

        if (!cls) {
            cls = header + *(clslist + off / sizeof(UInt64)) & 0xFFFFFFFFFFF;
        }

        struct _objc_2_class* objc_class = reinterpret_cast<struct _objc_2_class*>(cls);

        if (objc_class) {
            c = new ObjCClass(data, objc_class, false);

            if (c->isValid()) {
                classes.push_back(c);
            }
        }

        struct _objc_2_class* objc_metaclass =
            reinterpret_cast<struct _objc_2_class*>((objc_class->isa & 0xFFFFFFFF) + header);

        if (objc_metaclass && objc_class != objc_metaclass) {
            metac = new ObjCClass(data, objc_metaclass, true);

            if (metac->isValid()) {
                classes.push_back(metac);
            }
        }
    }
}

void parseCategoryList(ObjCData* data, std::vector<Category*>& categories) {
    darwin::UserMachO* macho = data->getMachO();

    Section* catlist = data->getCategoryList();

    Size catlist_size = catlist->getSize();

    UInt64 base = macho->getBase() - data->getMachO()->getAslrSlide();

    UInt64 header = reinterpret_cast<UInt64>(macho->getMachHeader());

    UInt64 address = catlist->getAddress();

    UInt64* categorylist = reinterpret_cast<UInt64*>(header + catlist->getOffset());

    for (UInt64 off = 0; off < catlist_size; off = off + sizeof(UInt64)) {
        Category* cat;

        UInt64 category = macho->getBufferAddress(
            (*(categorylist + off / sizeof(UInt64)) & 0xFFFFFFFFFFF) - macho->getAslrSlide());

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

void parseProtocolList(ObjCData* data, std::vector<Protocol*>& protocols) {
    darwin::UserMachO* macho = data->getMachO();

    Section* protlist = data->getProtocolList();

    Section* protrefs = data->getProtoRefs();

    Size protolist_size = protlist->getSize();

    UInt64 base = macho->getBase() - data->getMachO()->getAslrSlide();

    UInt64 header = reinterpret_cast<UInt64>(macho->getMachHeader());

    UInt64 address = protlist->getAddress();

    UInt64* protolist = reinterpret_cast<UInt64*>(header + protlist->getOffset());

    for (UInt64 off = 0; off < protolist_size; off = off + sizeof(UInt64)) {
        Protocol* p;

        UInt64 proto = macho->getBufferAddress(
            ((*(protolist + off / sizeof(UInt64))) & 0xFFFFFFFFFFF) - macho->getAslrSlide());

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

void parseMethodList(ObjCData* metadata, ObjC* object, std::vector<Method*>& methodList,
                     enum MethodType methtype, struct _objc_2_class_method_info* methodInfo) {
    darwin::UserMachO* macho = metadata->getMachO();

    struct _objc_2_class_method_info* methods;

    Offset off;

    UInt64 selectors = macho->isDyldCache() ? objc::findSelectorsBase(macho) : 0;

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

    DARWIN_RK_LOG("\t\t\t%s Methods\n", type);

    for (int i = 0; i < methods->count; i++) {
        UInt64 pointer_to_name;
        UInt64 offset_to_name;

        UInt8* q = reinterpret_cast<UInt8*>(reinterpret_cast<UInt8*>(methods) + off);

        if (macho->isDyldCache() && dynamic_cast<Protocol*>(object)) {
            struct _objc_2_method* method = reinterpret_cast<struct _objc_2_method*>(q);

            Method* meth = new Method(object, method);

            DARWIN_RK_LOG("\t\t\t\t0x%08llx: %s%s\n", meth->getImpl(), prefix, meth->getName());

            methodList.push_back(meth);

            off += sizeof(struct _objc_2_method);

            continue;
        } else if (macho->isDyldCache()) {
            struct _objc_2_class_method* method = reinterpret_cast<struct _objc_2_class_method*>(q);

            pointer_to_name = selectors + method->name;

            if (macho->getObjectiveCLibrary()->getBufferAddress(pointer_to_name)) {
                Method* meth = new Method(object, method);

                methodList.push_back(meth);

                DARWIN_RK_LOG("\t\t\t\t0x%08llx: %s%s\n", meth->getImpl(), prefix, meth->getName());
            }

        } else {
            struct _objc_2_class_method* method = reinterpret_cast<struct _objc_2_class_method*>(q);

            pointer_to_name = reinterpret_cast<UInt64>(macho->getMachHeader()) +
                              reinterpret_cast<UInt32>(method->name & 0xFFFFFF);

            offset_to_name = ((*(UInt64*)pointer_to_name) & 0xFFFFFF);

            Method* meth = new Method(object, method);

            methodList.push_back(meth);

            DARWIN_RK_LOG("\t\t\t\t0x%08llx: %s%s\n", meth->getImpl(), prefix, meth->getName());
        }

        off += sizeof(struct _objc_2_class_method);
    }
}

void parsePropertyList(ObjCData* metadata, ObjC* object, std::vector<Property*>& propertyList,
                       struct _objc_2_class_property_info* propertyInfo) {
    struct _objc_2_class_property_info* properties;

    Offset off;

    if (!propertyInfo) {
        return;
    }

    properties = reinterpret_cast<struct _objc_2_class_property_info*>(propertyInfo);

    off = sizeof(struct _objc_2_class_property_info);

    DARWIN_RK_LOG("\t\t\tProperties\n");

    for (int i = 0; i < properties->count; i++) {
        struct _objc_2_class_property* property = reinterpret_cast<struct _objc_2_class_property*>(
            reinterpret_cast<UInt8*>(properties) + off);

        Property* prop = new Property(object, property);

        propertyList.push_back(prop);

        DARWIN_RK_LOG("\t\t\t\t%s %s\n", prop->getAttributes(), prop->getName());

        off += sizeof(struct _objc_2_class_property);
    }
}
} // namespace objc

namespace objc {

ObjCClass::ObjCClass(ObjCData* metadata, struct _objc_2_class* c, bool metaclass) {
    metadata = metadata;
    macho = metadata->getMachO();
    metaclass = metaclass;
    cls = c;
    super = nullptr;

    data = reinterpret_cast<struct _objc_2_class_data*>((UInt64)c->data & 0xFFFFFFF8);

    if (macho->sectionForOffset(reinterpret_cast<UInt64>(data))) {
        data = reinterpret_cast<struct _objc_2_class_data*>(
            (UInt64)data + reinterpret_cast<UInt64>(macho->getMachHeader()));
        name = reinterpret_cast<char*>((data->name & 0xFFFFFFFF) +
                                       reinterpret_cast<UInt64>(macho->getMachHeader()));

        if (macho->sectionForOffset(reinterpret_cast<UInt64>((data->name & 0xFFFFFFFF)))) {
            if (metaclass)
                printf("\t\t$OBJC_METACLASS_%s\n", name);
            else
                printf("\t\t$OBJC_CLASS_%s\n", name);

            isa = reinterpret_cast<UInt64>(c->isa);
            superclass = reinterpret_cast<UInt64>(c->superclass);
            cache = reinterpret_cast<UInt64>(c->cache);
            vtable = reinterpret_cast<UInt64>(c->vtable);

            parseMethods();
            parseIvars();
            parseProperties();
        }

    } else if (macho->sectionForAddress(reinterpret_cast<UInt64>(((UInt64)c->data & 0xFFFFFFFFF) -
                                                                 macho->getAslrSlide()))) {
        data = reinterpret_cast<struct _objc_2_class_data*>(
            macho->getBufferAddress(((UInt64)c->data & 0xFFFFFFFFF) - macho->getAslrSlide()));

        name = reinterpret_cast<char*>(macho->getBufferAddress(data->name - macho->getAslrSlide()));

        if (metaclass)
            printf("\t\t$OBJC_METACLASS_%s\n", name);
        else
            printf("\t\t$OBJC_CLASS_%s\n", name);

        isa = reinterpret_cast<UInt64>(c->isa);
        superclass = reinterpret_cast<UInt64>(c->superclass);
        cache = reinterpret_cast<UInt64>(c->cache);
        vtable = reinterpret_cast<UInt64>(c->vtable);

        parseMethods();
        parseIvars();
        parseProperties();
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
    darwin::UserMachO* macho;

    struct _objc_2_class_method_info* instanceMethods;
    struct _objc_2_class_method_info* classMethods;

    struct _objc_2_class_method_info* optionalInstanceMethods;
    struct _objc_2_class_method_info* optionalClassMethods;

    struct _objc_2_class_property_info* instanceProperties;

    metadata = data;
    protocol = prot;

    macho = metadata->getMachO();

    if (macho->isDyldCache()) {
        name = reinterpret_cast<char*>(macho->getBufferAddress(prot->name - macho->getAslrSlide()));

        printf("\t\t$OBJC_PROTOCOL_%s\n", name);

        if (prot->instance_methods) {
            instanceMethods = reinterpret_cast<struct _objc_2_class_method_info*>(
                macho->getBufferAddress(protocol->instance_methods - macho->getAslrSlide()));

            objc::parseMethodList(metadata, this, getInstanceMethods(),
                                        INSTANCE_METHOD, instanceMethods);
        }

        if (prot->class_methods) {
            classMethods = reinterpret_cast<struct _objc_2_class_method_info*>(
                macho->getBufferAddress(protocol->class_methods - macho->getAslrSlide()));

            objc::parseMethodList(metadata, this, getClassMethods(), CLASS_METHOD,
                                        classMethods);
        }

        if (prot->opt_instance_methods) {
            optionalInstanceMethods =
                reinterpret_cast<struct _objc_2_class_method_info*>(macho->getBufferAddress(
                    protocol->opt_instance_methods - macho->getAslrSlide()));

            objc::parseMethodList(metadata, this, getOptionalInstanceMethods(),
                                        OPT_INSTANCE_METHOD, optionalInstanceMethods);
        }

        if (prot->opt_class_methods) {
            optionalClassMethods = reinterpret_cast<struct _objc_2_class_method_info*>(
                macho->getBufferAddress(protocol->opt_class_methods - macho->getAslrSlide()));

            objc::parseMethodList(metadata, this, getOptionalClassMethods(),
                                        OPT_CLASS_METHOD, optionalClassMethods);
        }

        if (prot->instance_properties) {
            instanceProperties =
                reinterpret_cast<struct _objc_2_class_property_info*>(macho->getBufferAddress(
                    protocol->instance_properties - macho->getAslrSlide()));

            objc::parsePropertyList(metadata, this, getInstanceProperties(),
                                          instanceProperties);
        }
    } else {
        name = reinterpret_cast<char*>((prot->name & 0xFFFFFFF) +
                                             reinterpret_cast<UInt64>(macho->getMachHeader()));

        printf("\t\t$OBJC_PROTOCOL_%s\n", name);

        if (prot->instance_methods) {
            instanceMethods = reinterpret_cast<struct _objc_2_class_method_info*>(
                (protocol->instance_methods & 0xFFFFFFF) +
                reinterpret_cast<UInt64>(macho->getMachHeader()));

            objc::parseMethodList(metadata, this, getInstanceMethods(),
                                        INSTANCE_METHOD, instanceMethods);
        }

        if (prot->class_methods) {
            classMethods = reinterpret_cast<struct _objc_2_class_method_info*>(
                (protocol->class_methods & 0xFFFFFFF) +
                reinterpret_cast<UInt64>(macho->getMachHeader()));

            objc::parseMethodList(metadata, this, getClassMethods(), CLASS_METHOD,
                                        classMethods);
        }

        if (prot->opt_instance_methods) {
            optionalInstanceMethods = reinterpret_cast<struct _objc_2_class_method_info*>(
                (protocol->opt_instance_methods & 0xFFFFFFF) +
                reinterpret_cast<UInt64>(macho->getMachHeader()));

            objc::parseMethodList(metadata, this, getOptionalInstanceMethods(),
                                        OPT_INSTANCE_METHOD, optionalInstanceMethods);
        }

        if (prot->opt_class_methods) {
            optionalClassMethods = reinterpret_cast<struct _objc_2_class_method_info*>(
                (protocol->opt_class_methods & 0xFFFFFFF) +
                reinterpret_cast<UInt64>(macho->getMachHeader()));

            objc::parseMethodList(metadata, this, getOptionalClassMethods(),
                                        OPT_CLASS_METHOD, optionalClassMethods);
        }

        if (prot->instance_properties) {
            instanceProperties = reinterpret_cast<struct _objc_2_class_property_info*>(
                (protocol->instance_properties & 0xFFFFFFF) +
                reinterpret_cast<UInt64>(macho->getMachHeader()));

            objc::parsePropertyList(metadata, this, getInstanceProperties(),
                                          instanceProperties);
        }
    }
}

Category::Category(ObjCData* data, struct _objc_2_category* cat) {
    darwin::UserMachO* macho = data->getMachO();

    struct _objc_2_class_method_info* instanceMethods;
    struct _objc_2_class_method_info* classMethods;

    struct _objc_2_class_property_info* catProperties;

    metadata = data;
    category = cat;

    if (macho->isDyldCache()) {
        name = reinterpret_cast<char*>(
            macho->getBufferAddress(cat->category_name - macho->getAslrSlide()));

        if (!name) {
            name = reinterpret_cast<char*>(macho->getObjectiveCLibrary()->getBufferAddress(
                cat->category_name - macho->getAslrSlide()));
        }

        ObjCClass* isa = data->getClassByName(name);

        if (isa) {
            class_name = isa->getName();
        } else {
            class_name = "UNKNOWN";
        }

        printf("\t\t$OBJC_CATEGORY_%s+%s\n", class_name, "extra");

        if (cat->instance_methods) {
            instanceMethods = reinterpret_cast<struct _objc_2_class_method_info*>(
                macho->getBufferAddress(category->instance_methods - macho->getAslrSlide()));

            objc::parseMethodList(metadata, this, getInstanceMethods(),
                                        INSTANCE_METHOD, instanceMethods);
        }

        if (cat->class_methods) {
            classMethods = reinterpret_cast<struct _objc_2_class_method_info*>(
                macho->getBufferAddress(category->class_methods - macho->getAslrSlide()));

            objc::parseMethodList(metadata, this, getClassMethods(), CLASS_METHOD,
                                        classMethods);
        }

        if (cat->properties) {
            catProperties = reinterpret_cast<struct _objc_2_class_property_info*>(
                macho->getBufferAddress(category->properties - macho->getAslrSlide()));

            objc::parsePropertyList(metadata, this, getProperties(),
                                          catProperties);
        }

    } else {
        name = reinterpret_cast<char*>((cat->category_name & 0xFFFFFFF) +
                                       reinterpret_cast<UInt64>(macho->getMachHeader()));

        if (!(cat->class_name & 0x4000000000000000)) {
            UInt64 cls =
                ((cat->class_name & 0xFFFFFFF) + reinterpret_cast<UInt64>(macho->getMachHeader()));

            ObjCClass* isa = data->getClassByIsa((UInt64)cls);

            if (isa) {
                class_name = isa->getName();
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
                reinterpret_cast<UInt64>(macho->getMachHeader()));

            objc::parseMethodList(metadata, this, getInstanceMethods(),
                                        INSTANCE_METHOD, instanceMethods);
        }

        if (cat->class_methods) {
            classMethods = reinterpret_cast<struct _objc_2_class_method_info*>(
                (category->class_methods & 0xFFFFFFF) +
                reinterpret_cast<UInt64>(macho->getMachHeader()));

            objc::parseMethodList(metadata, this, getClassMethods(), CLASS_METHOD,
                                        classMethods);
        }

        if (cat->properties) {
            catProperties = reinterpret_cast<struct _objc_2_class_property_info*>(
                (category->properties & 0xFFFFFFF) +
                reinterpret_cast<UInt64>(macho->getMachHeader()));

            objc::parsePropertyList(metadata, this, getProperties(),
                                          catProperties);
        }
    }
}

Ivar::Ivar(ObjC* object, struct _objc_2_class_ivar* ivar) {
    darwin::UserMachO* macho = object->getMetadata()->getMachO();

    if (macho->isDyldCache()) {
        object = object;
        ivar = ivar;
        name = reinterpret_cast<char*>(macho->getBufferAddress(ivar->name - macho->getAslrSlide()));

        if (!name) {
            name = reinterpret_cast<char*>(macho->getObjectiveCLibrary()->getBufferAddress(
                ivar->name - macho->getAslrSlide()));
        }

        offset = ivar->offset - macho->getAslrSlide();
        type = ivar->type;
        size = ivar->size;

    } else {
        object = object;
        ivar = ivar;
        offset = reinterpret_cast<UInt64>((ivar->offset & 0xFFFFFF) +
                                          reinterpret_cast<UInt64>(macho->getMachHeader()));
        name = reinterpret_cast<char*>((ivar->name & 0xFFFFFF) +
                                       reinterpret_cast<char*>(macho->getMachHeader()));
        type = ivar->type;
        size = ivar->size;
    }
}

Property::Property(ObjC* object, struct _objc_2_class_property* property) {
    darwin::UserMachO* macho = object->getMetadata()->getMachO();

    if (macho->isDyldCache()) {
        object = object;
        property = property;
        name = reinterpret_cast<char*>(
            macho->getBufferAddress(property->name - macho->getAslrSlide()));

        if (!name) {
            name = reinterpret_cast<char*>(macho->getObjectiveCLibrary()->getBufferAddress(
                property->name - macho->getAslrSlide()));
        }

        attributes = reinterpret_cast<char*>(
            macho->getBufferAddress(property->attributes - macho->getAslrSlide()));

        if (!attributes) {
            attributes = reinterpret_cast<char*>(macho->getObjectiveCLibrary()->getBufferAddress(
                property->attributes - macho->getAslrSlide()));
        }

    } else {
        object = object;
        property = property;
        name = reinterpret_cast<char*>((property->name & 0xFFFFFF) +
                                       reinterpret_cast<char*>(macho->getMachHeader()));
        attributes = reinterpret_cast<char*>((property->attributes & 0xFFFFFF) +
                                             reinterpret_cast<char*>(macho->getMachHeader()));
    }
}

Method::Method(ObjC* object, struct _objc_2_class_method* method) {
    darwin::UserMachO* macho = object->getMetadata()->getMachO();

    UInt64 selectors;

    UInt64 pointer_to_type;

    UInt64 pointer_to_name;

    object = object;
    method = method;

    selectors = objc::findSelectorsBase(macho);

    if (macho->isDyldCache() && selectors) {
        pointer_to_name = selectors + method->name;

        pointer_to_name = macho->getObjectiveCLibrary()->getBufferAddress(pointer_to_name);

        name = reinterpret_cast<char*>(pointer_to_name);

        pointer_to_type = macho->offsetToAddress((UInt64)&method->type -
                                                 reinterpret_cast<UInt64>(macho->getMachHeader()));

        pointer_to_type += method->type;

        pointer_to_type = macho->getBufferAddress(pointer_to_type);

        if (!pointer_to_type) {
            pointer_to_type = macho->getObjectiveCLibrary()->getBufferAddress(pointer_to_type);
        }

        type = pointer_to_type;

        impl = reinterpret_cast<UInt64>(
            method->imp + macho->offsetToAddress(reinterpret_cast<UInt64>(&method->imp) -
                                                 reinterpret_cast<UInt64>(macho->getMachHeader())));
    } else {
        if (dynamic_cast<ObjCClass*>(object) || dynamic_cast<Category*>(object)) {
            pointer_to_name = reinterpret_cast<UInt64>(&method->name) +
                              reinterpret_cast<UInt32>(method->name & 0xFFFFFF);

            pointer_to_name = reinterpret_cast<UInt64>(macho->getMachHeader()) +
                              ((*(UInt64*)pointer_to_name) & 0xFFFFFF);
        } else {
            pointer_to_name = reinterpret_cast<UInt64>(macho->getMachHeader()) +
                              reinterpret_cast<UInt32>(method->name & 0xFFFFFF);
        }

        name = reinterpret_cast<char*>(pointer_to_name);
        impl = reinterpret_cast<UInt64>((method->imp & 0xFFFFFF) +
                                        reinterpret_cast<UInt64>(macho->getMachHeader()));
        type = method->type;
    }
}

Method::Method(ObjC* object, struct _objc_2_method* method) {
    darwin::UserMachO* macho = object->getMetadata()->getMachO();

    object = object;

    name = reinterpret_cast<char*>(macho->getBufferAddress(method->name - macho->getAslrSlide()));

    if (!name) {
        name = reinterpret_cast<char*>(
            macho->getObjectiveCLibrary()->getBufferAddress(method->name - macho->getAslrSlide()));
    }

    impl = method->imp ? method->imp - macho->getAslrSlide() : 0;
    type = macho->getBufferAddress(method->type - macho->getAslrSlide());
}
} // namespace objc

#ifdef __arm64__

#include <arm64/isa_arm64.h>
#include <arm64/patch_finder_arm64.h>

#elif

#include <x86_64/isa_x86_64.h>
#include <x86_64/patch_finder_x86_64.h>

#endif

namespace objc {

UInt64 findSelectorsBase(darwin::UserMachO* macho) {
    UInt64 selectors;

    UInt64 method_getName;

    darwin::UserMachO* libobjc;

    Symbol* symbol;

    libobjc = macho->getObjectiveCLibrary();

    if (!libobjc) {
        return 0;
    }

    symbol = libobjc->getSymbolByName("_method_getName");

    if (!symbol) {
        return 0;
    }

    method_getName = symbol->getAddress();

    if (!method_getName) {
        return 0;
    }

    UInt64 start = libobjc->getBufferAddress(method_getName);

#ifdef __arm64__

    using namespace arch::arm64;

    UInt64 add = arch::arm64::PatchFinder::step64(libobjc, start, 0x100,
                                                  (bool (*)(UInt32*))is_add_reg, -1, -1);

    UInt64 xref = arch::arm64::PatchFinder::stepBack64(libobjc, add, 0x100,
                                                       (bool (*)(UInt32*))is_adrp, -1, -1);

    adr_t adrp = *reinterpret_cast<adr_t*>(xref);

    add_imm_t add_imm = *reinterpret_cast<add_imm_t*>(xref + 0x4);

    selectors = (xref & ~0xFFF) + ((((adrp.immhi << 2) | adrp.immlo)) << 12) +
                (add_imm.sh ? (add_imm.imm << 12) : add_imm.imm);

    return (selectors - start) + method_getName;

#elif __x86_64__

    using namespace arch::x86_64;

    cs_insn insn;

    UInt64 add = arch::x86_64::PatchFinder::step64(libobjc, start, 0x100, "add", nullptr);

    UInt64 mov = arch::x86_64::PatchFinder::stepBack64(libobjc, add, 0x100, "mov", nullptr);

    arch::x86_64::disassemble(mov, arch::x86_64::MaxInstruction, &insn);

    UInt64 selectors = insn.detail.x86->operands[1].mem.disp + mov;

    return selectors;

#endif
}

Protocol* ObjCClass::getProtocol(char* protocolname) {
    for (int i = 0; i < getProtocols().size(); i++) {
        Protocol* protocol = getProtocols().at(i);

        if (strcmp(protocol->getName(), protocolname) == 0) {
            return protocol;
        }
    }

    return nullptr;
}

Method* ObjCClass::getMethod(char* methodname) {
    for (int i = 0; i < getMethods().size(); i++) {
        Method* method = getMethods().at(i);

        if (strcmp(method->getName(), methodname) == 0) {
            return method;
        }
    }

    return nullptr;
}

Ivar* ObjCClass::getIvar(char* ivarname) {
    for (int i = 0; i < getIvars().size(); i++) {
        Ivar* ivar = getIvars().at(i);

        if (strcmp(ivar->getName(), ivarname) == 0) {
            return ivar;
        }
    }

    return nullptr;
}

Property* ObjCClass::getProperty(char* propertyname) {
    for (int i = 0; i < getProperties().size(); i++) {
        Property* property = getProperties().at(i);

        if (strcmp(property->getName(), propertyname) == 0) {
            return property;
        }
    }

    return nullptr;
}

void ObjCClass::parseMethods() {
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

    if (macho->isDyldCache()) {
        selectors = objc::findSelectorsBase(macho);
    }

    meths = nullptr;

    if (macho->isDyldCache()) {
        meths = reinterpret_cast<struct _objc_2_class_method_info*>(macho->getBufferAddress(
            (d->methods & 0xFFFFFFFFFF) - macho->getAslrSlide()));
    } else {
        meths = reinterpret_cast<struct _objc_2_class_method_info*>(
            (d->methods & 0xFFFFFFFFF) + reinterpret_cast<UInt64>(macho->getMachHeader()));
    }

    if (!meths) {
        return;
    }

    off = sizeof(struct _objc_2_class_method_info);

    DARWIN_RK_LOG("\t\t\tMethods\n");

    for (int i = 0; i < meths->count; i++) {
        struct _objc_2_class_method* method =
            reinterpret_cast<struct _objc_2_class_method*>(reinterpret_cast<UInt8*>(meths) + off);

        UInt64 pointer_to_name;
        UInt64 offset_to_name;

        if (selectors) {
            pointer_to_name = selectors + method->name;

            if (macho->getObjectiveCLibrary()->getBufferAddress(pointer_to_name)) {
                Method* meth = new Method(this, method);

                methods.push_back(meth);

                if (metaclass) {
                    DARWIN_RK_LOG("\t\t\t\t0x%08llx: +%s\n", meth->getImpl(), meth->getName());
                } else {
                    DARWIN_RK_LOG("\t\t\t\t0x%08llx: -%s\n", meth->getImpl(), meth->getName());
                }
            }

        } else {
            pointer_to_name = reinterpret_cast<UInt64>(&method->name) +
                              reinterpret_cast<UInt32>(method->name & 0xFFFFFFFF);

            offset_to_name = ((*(UInt64*)pointer_to_name));

            if (offset_to_name) {
                Section* sect = macho->sectionForOffset(offset_to_name);

                if (sect && strcmp(sect->getSectionName(), "__objc_methname") == 0) {
                    Method* meth = new Method(this, method);

                    methods.push_back(meth);

                    if (metaclass) {
                        DARWIN_RK_LOG("\t\t\t\t0x%08llx: +%s\n", meth->getImpl(), meth->getName());
                    } else {
                        DARWIN_RK_LOG("\t\t\t\t0x%08llx: -%s\n", meth->getImpl(), meth->getName());
                    }
                }
            }
        }

        off += sizeof(struct _objc_2_class_method);
    }
}

void ObjCClass::parseProtocols() {
    struct _objc_2_class* c;

    struct _objc_2_class_data* d;

    struct _objc_2_class_protocol_info* protocols;

    Offset off;

    c = cls;

    d = data;

    protocols = reinterpret_cast<struct _objc_2_class_protocol_info*>(data->protocols);

    off = sizeof(struct _objc_2_class_protocol_info);
}

void ObjCClass::parseIvars() {
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

    if (macho->isDyldCache()) {
        ivs = reinterpret_cast<struct _objc_2_class_ivar_info*>(
            macho->getBufferAddress(d->ivars - macho->getAslrSlide()));
    } else {
        ivs = reinterpret_cast<struct _objc_2_class_ivar_info*>(
            (d->ivars & 0xFFFFFFFF) + reinterpret_cast<UInt64>(macho->getMachHeader()));
    }

    if (!ivs) {
        return;
    }

    off = sizeof(struct _objc_2_class_ivar_info);

    DARWIN_RK_LOG("\t\t\tIvars\n");

    for (int i = 0; i < ivs->count; i++) {
        struct _objc_2_class_ivar* ivar =
            reinterpret_cast<struct _objc_2_class_ivar*>(reinterpret_cast<UInt8*>(ivs) + off);

        Ivar* iv = new Ivar(this, ivar);

        ivars.push_back(iv);

        DARWIN_RK_LOG("\t\t\t\t0x%08llx: %s\n", iv->getOffset(), iv->getName());

        off += sizeof(struct _objc_2_class_ivar);
    }
}

void ObjCClass::parseProperties() {
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

    if (macho->isDyldCache()) {
        props = reinterpret_cast<struct _objc_2_class_property_info*>(
            macho->getBufferAddress(d->properties - macho->getAslrSlide()));
    } else {
        props = reinterpret_cast<struct _objc_2_class_property_info*>(
            (d->properties & 0xFFFFFFFF) + reinterpret_cast<UInt64>(macho->getMachHeader()));
    }

    if (!props) {
        return;
    }

    off = sizeof(struct _objc_2_class_property_info);

    DARWIN_RK_LOG("\t\t\tProperties\n");

    for (int i = 0; i < props->count; i++) {
        struct _objc_2_class_property* property = reinterpret_cast<struct _objc_2_class_property*>(
            reinterpret_cast<UInt8*>(props) + off);

        Property* prop = new Property(this, property);

        properties.push_back(prop);

        DARWIN_RK_LOG("\t\t\t\t%s %s\n", prop->getAttributes(), prop->getName());

        off += sizeof(struct _objc_2_class_property);
    }
}
} // namespace objc

namespace objc {
void ObjCData::parseObjC() {
    data = macho->getSegment("__DATA");
    data_const = macho->getSegment("__DATA_CONST");

    classlist = macho->getSection("__DATA_CONST", "__objc_classlist");
    catlist = macho->getSection("__DATA_CONST", "__objc_catlist");
    protolist = macho->getSection("__DATA_CONST", "__objc_protolist");

    selrefs = macho->getSection("__DATA", "__objc_selrefs");
    protorefs = macho->getSection("__DATA", "__objc_protorefs");
    classrefs = macho->getSection("__DATA", "__objc_classrefs");
    superrefs = macho->getSection("__DATA", "__objc_superrefs");

    ivar = macho->getSection("__DATA", "__objc_ivar");
    objc_data = macho->getSection("__DATA", "__objc_data");

    assert(data);
    assert(data);

    assert(classlist);

    assert(selrefs);

    assert(ivar);
    assert(objc_data);

    parseClassList(this, classes);

    if (protolist)
        parseProtocolList(this, protocols);

    if (catlist)
        parseCategoryList(this, categories);

    if (!macho->isDyldCache()) {
        // do not parse categories and protocols when dyld cache is being parsed
        // all of the class pointers will be invalid because they will exist in other libraries
        // we aren't going to need categories during runtime anyways
    }
}

ObjCClass* ObjCData::getClassByName(char* classname) {
    for (int i = 0; i < classes.size(); i++) {
        ObjCClass* cls = classes.at(i);

        if (cls->getName() && strcmp(cls->getName(), classname) == 0) {
            return cls;
        }
    }

    return nullptr;
}

ObjCClass* ObjCData::getClassByIsa(UInt64 isa) {
    for (int i = 0; i < classes.size(); i++) {
        ObjCClass* cls = classes.at(i);

        if (reinterpret_cast<UInt64>(cls->getClass()) == isa) {
            return cls;
        }
    }

    return nullptr;
}

Protocol* ObjCData::getProtocol(char* protoname) {
    for (int i = 0; i < protocols.size(); i++) {
        Protocol* protocol = protocols.at(i);

        if (strcmp(protocol->getName(), protoname) == 0) {
            return protocol;
        }
    }

    return nullptr;
}

Category* ObjCData::getCategory(char* catname) {
    for (int i = 0; i < categories.size(); i++) {
        Category* category = categories.at(i);

        if (strcmp(category->getName(), catname) == 0) {
            return category;
        }
    }

    return nullptr;
}

Method* ObjCData::getMethod(char* classname, char* methodname) {
    ObjCClass* cls = getClassByName(classname);

    return cls ? cls->getMethod(methodname) : nullptr;
}

Ivar* ObjCData::getIvar(char* classname, char* ivarname) {
    ObjCClass* cls = getClassByName(classname);

    return cls ? cls->getIvar(ivarname) : nullptr;
}

Property* ObjCData::getProperty(char* classname, char* propertyname) {
    ObjCClass* cls = getClassByName(classname);

    return cls ? cls->getProperty(propertyname) : nullptr;
}

} // namespace objc