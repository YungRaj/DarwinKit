import lldb
import os

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f populate_symbols.populate_symbols populate_symbols')

def populate_symbols(debugger, command, result, internal_dict):
    '''
    Populate symbols from a linker map file produced by IDA Pro.

    Usage: populate_symbols <map_file_path>
    '''
    command_args = command.split()
    if len(command_args) != 1:
        result.SetError('Usage: populate_symbols <map_file_path>')
        return

    map_file_path = command_args[0]

    if not os.path.isfile(map_file_path):
        result.SetError(f'Map file not found: {map_file_path}')
        return

    target = debugger.GetSelectedTarget()
    if not target:
        result.SetError('No target found. Please ensure you have a target loaded.')
        return

    with open(map_file_path, 'r') as map_file:
        for line in map_file:
            line = line.strip()
            if not line:
                continue

            # Example map file line: 0x0000000000401000 T _start
            parts = line.split()
            if len(parts) != 3:
                continue

            try:
                address = int(parts[0], 16)
                symbol_type = parts[1]
                symbol_name = parts[2]

                # Add symbol to target
                target.GetDebugger().HandleCommand(f'target symbols add -n {symbol_name} -a {address:x}')

            except ValueError:
                continue

    result.AppendMessage(f'Successfully populated symbols from {map_file_path}')
