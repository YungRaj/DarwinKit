import re
import struct
import sys


# Define the C structure and macro definitions
c_code = """
#define NX_MAX_FILE_SYSTEMS 100
#define NX_EPH_INFO_COUNT 4
#define NX_EPH_MIN_BLOCK_COUNT 8
#define NX_MAX_FILE_SYSTEM_EPH_STRUCTS 4
#define NX_TX_MIN_CHECKPOINT_COUNT 4
#define NX_EPH_INFO_VERSION_1 1

#define NX_NUM_COUNTERS 32

typedef int64_t     paddr_t;

typedef uint64_t oid_t;
typedef uint64_t xid_t;

struct prange {
  paddr_t     pr_start_paddr;
  uint64_t    pr_block_count;
};

typedef struct prange prange_t;

struct obj_phys {
  uint8_t     o_cksum[8];
  oid_t       o_oid;
  xid_t       o_xid;
  uint32_t    o_type;
  uint32_t    o_subtype;
};

typedef struct obj_phys obj_phys_t;

typedef char uuid_t[16];

struct nx_superblock {
  obj_phys_t  nx_o;

  uint32_t    nx_magic;
  uint32_t    nx_block_size;
  uint64_t    nx_block_count;
 
  uint64_t nx_features;
  uint64_t nx_readonly_compatible_features;
  uint64_t nx_incompatible_features;
  
  uuid_t nx_uuid;

  oid_t nx_next_oid;
  xid_t nx_next_xid;
  
  uint32_t    nx_xp_desc_blocks;
  uint32_t    nx_xp_data_blocks;
  paddr_t     nx_xp_desc_base;
  paddr_t     nx_xp_data_base;
  uint32_t    nx_xp_desc_next;
  uint32_t    nx_xp_data_next;
  uint32_t    nx_xp_desc_index;
  uint32_t    nx_xp_desc_len;
  uint32_t    nx_xp_data_index;
  uint32_t    nx_xp_data_len;
  oid_t       nx_spaceman_oid;
  oid_t       nx_omap_oid;
  oid_t       nx_reaper_oid;

  uint32_t    nx_test_type;
  uint32_t    nx_max_file_systems;

  oid_t     nx_fs_oid[NX_MAX_FILE_SYSTEMS];
  uint64_t  nx_counters[NX_NUM_COUNTERS];

  prange_t  nx_blocked_out_prange;
  
  oid_t nx_evict_mapping_tree_oid;
  
  uint64_t nx_flags;
  paddr_t  nx_efi_jumpstart;

  uuid_t   nx_fusion_uuid;
  prange_t nx_keylocker;
  uint64_t nx_ephemeral_info[NX_EPH_INFO_COUNT];
  
  oid_t nx_test_oid;
  oid_t nx_fusion_mt_oid;
  oid_t nx_fusion_wbc_oid;

  prange_t    nx_fusion_wbc;
  uint64_t    nx_newest_mounted_version;
  prange_t    nx_mkb_locker;
};

typedef struct nx_superblock nx_superblock_t;

"""

# Define the template for ctypes structure class
class_template = """
class {class_name}(ctypes.Structure):
    _fields_ = [
{field_definitions}
    ]
"""

# Regular expression pattern for matching typedefs
typedef_pattern = re.compile(r"typedef\s+(?:struct\s+)?(\S+)\s+(\S+)\s*;")

# Mapping of primitive C types to ctypes types
primitive_to_ctypes = {
    'int': 'ctypes.c_int',
    'uint8_t': 'ctypes.c_uint8',
    'uint16_t': 'ctypes.c_uint16',
    'uint32_t': 'ctypes.c_uint32',
    'uint64_t': 'ctypes.c_uint64',
    'int8_t': 'ctypes.c_int8',
    'int16_t': 'ctypes.c_int16',
    'int32_t': 'ctypes.c_int32',
    'int64_t': 'ctypes.c_int64',
    'unsigned char' : 'ctypes.c_uint8_t',
    'char': 'ctypes.c_char',
}

macro_definition_names = []
macro_definition_values = []

# Find all macro definitions using regular expression
macro_definitions = re.findall(r'#define\s+(\w+)\s+([^\r\n]+)', c_code)

macros = dict(macro_definitions)

# Process macro occurrences in the code
processed_code = c_code
for macro_name, macro_value in macros.items():
    # Match only standalone occurrences of the macro name
    pattern = r'(?<!#define\s)' + re.escape(macro_name) + r'\b'
    processed_code = re.sub(pattern, macro_value, processed_code)

c_code = processed_code

type_definitions_types = []
type_definitions_names = []
type_definitions_sizes = []

# Extract typedefs
typedefs = re.findall(typedef_pattern, c_code)

# Replace typedefs in the code
for typedef_type, typedef_name in typedefs:
    pattern = r"\[(\d+)\]"

    match = re.search(pattern, typedef_name)

    if match:
        typedef_size = int(match.group(1))

        # Regular expression pattern to match the word before the square brackets
        pattern = r"(\w+)\[\d+\]"

        match = re.search(pattern, typedef_name)

        typedef_name = match.group(1)
    else:
        typedef_size = 1

    type_definitions_types.append(typedef_type)
    type_definitions_names.append(typedef_name)
    type_definitions_sizes.append(typedef_size)

# Extract struct names and definitions using regular expressions
struct_definitions = re.findall(r"struct ([a-zA-Z_]+) \{([\s\S]+?)\};", c_code)

print(struct_definitions)

# Process struct definitions and generate ctypes structure classes
for struct_name, struct_body in struct_definitions:
    field_definitions = []
    struct_body = struct_body.strip()
    lines = re.split(r'[;\n]', struct_body)
    for line in lines:
        line = line.strip()
        if line:
            if "[" in line and "]" in line:
                array_declaration = re.search(r'(\w+)\s+(\w+)\[(\d+)\]', line)
                array_type = array_declaration.group(1)
                array_name = array_declaration.group(2)
                array_size = int(array_declaration.group(3))

                if array_type in primitive_to_ctypes:
                    ctypes_field_type = primitive_to_ctypes[array_type]
                else:
                    try:
                        index = type_definitions_names.index(array_type)

                        typedef_type = type_definitions_types[index]
                        typedef_name = type_definitions_names[index]
                        typedef_size = type_definitions_sizes[index]

                        if typedef_type in primitive_to_ctypes:
                            ctypes_field_type = primitive_to_ctypes[typedef_type]
                        else:
                            ctypes_field_type = f"{array_type.replace('_t', '').replace(';', '')}"

                        if(typedef_size > 1):
                            ctypes_field_type += f" * {typedef_size}"

                    except ValueError:
                        pass

                ctypes_array_type = ctypes_field_type
                ctypes_field_type = f"{ctypes_array_type} * {array_size}"
                field_definitions.append(f'        ("{array_name}", {ctypes_field_type}),')
            else:
                field_type, field_name = line.split()

                resolved_type = field_type

                if resolved_type in primitive_to_ctypes:
                    ctypes_field_type = primitive_to_ctypes[resolved_type]
                else:
                    try:
                        index = type_definitions_names.index(resolved_type)

                        typedef_type = type_definitions_types[index]
                        typedef_name = type_definitions_names[index]
                        typedef_size = type_definitions_sizes[index]

                        if typedef_type in primitive_to_ctypes:
                            ctypes_field_type = primitive_to_ctypes[typedef_type]
                        else:
                            ctypes_field_type = f"{resolved_type.replace('_t', '').replace(';', '')}"

                        if(typedef_size > 1):
                            ctypes_field_type += f" * {typedef_size}"

                    except ValueError:
                        pass

                field_definitions.append(f'        ("{field_name}", {ctypes_field_type}),')

    class_code = class_template.format(class_name=struct_name, field_definitions='\n'.join(field_definitions))
    print(class_code)
    print()

    class_code = 'import re\nimport ctypes' + class_code

    exec(class_code)


# Check if field types are valid based on the generated class definitions
for struct_name, struct_body in struct_definitions:
    class_def = globals().get(struct_name)

    for field_def, field_type in class_def._fields_:
        if not hasattr(globals().get(struct_name), field_def):
            print(f"Warning: Unknown or non-existent type '{field_type}' with name '{field_def}' in struct '{struct_name}'.")

def get_ctypes_to_struct_format(ctypes_data_type):
    ctypes_to_struct_format = {
        ctypes.c_char: 'B',
        ctypes.c_uint8: 'B',
        ctypes.c_uint16: 'H',
        ctypes.c_uint32: 'I',
        ctypes.c_uint64: 'Q',
        ctypes.c_int8: 'b',
        ctypes.c_int16: 'h',
        ctypes.c_int32: 'i',
        ctypes.c_int64: 'q',
    }
    return ctypes_to_struct_format.get(ctypes_data_type, '')

def get_struct_format_from_ctypes_structure(ctypes_structure):
    struct_format_list = []
    for field_name, field_type in ctypes_structure._fields_:
        if issubclass(field_type, ctypes.Array):
            item_type = field_type._type_
            item_count = field_type._length_
            item_format = get_ctypes_to_struct_format(item_type)

            struct_format_list.append(f'{item_count}{item_format}')
        else:
            field_format = get_ctypes_to_struct_format(field_type)

            if(not field_format):
                field_format = get_struct_format_from_ctypes_structure(field_type)

            struct_format_list.append(field_format)
    return ''.join(struct_format_list)

# Get the struct format string for each class
prange_format = get_struct_format_from_ctypes_structure(prange)
obj_phys_format = get_struct_format_from_ctypes_structure(obj_phys)
nx_superblock_format = get_struct_format_from_ctypes_structure(nx_superblock)

nx_superblock_size = struct.calcsize(nx_superblock_format)

print(f"prange_t format: {prange_format}")
print(f"obj_phys_t format: {obj_phys_format}")
print(f"nx_superblock_t format: {nx_superblock_format}") 
print(f"nx_superblock_t size: {nx_superblock_size}")