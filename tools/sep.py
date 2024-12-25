import re
import struct
import sys

# Define the C structure and macro definitions
c_code = """
#define kEndpointSEPROM 255

struct sep_message {
    uint8_t     endpoint;
    uint8_t     tag;
    uint8_t     opcode;
    uint8_t     param;
    uint32_t    data;
};

static const
struct sep_message (*mailbox_get_message)() = (void *)TARGET_MAILBOX_GET_MESSAGE;

static const
void (*mailbox_discard)(struct sep_message *msg) = (void *)TARGET_MAILBOX_DISCARD;

static const
void (*mailbox_send_message)(
    uint8_t opcode,
    uint8_t param,
    uint32_t data
) = (void *)TARGET_MAILBOX_SEND_MESSAGE;

static
uint8_t *const mailbox_pending = (void *)TARGET_MAILBOX_PENDING;
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

sep_message_format = get_struct_format_from_ctypes_structure(sep_message)
sep_message_size = struct.calcsize(sep_message_format)

print(f"sep_message format: {sep_message_format}")
print(f"sep_message size: {sep_message_size}")
