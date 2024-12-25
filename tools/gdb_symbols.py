import gdb

class SymbolPopulator(gdb.Command):
    def __init__(self):
        super(SymbolPopulator, self).__init__("populate_symbols", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        # Parse the argument to get the file path
        args = gdb.string_to_argv(arg)
        if len(args) != 1:
            gdb.write("Usage: populate_symbols <path_to_debug_map>\n")
            return
        
        debug_map_path = args[0]
        
        # Read the debug map file
        try:
            with open(debug_map_path, "r") as f:
                lines = f.readlines()
        except Exception as e:
            gdb.write(f"Error reading file: {e}\n")
            return

        for line in lines:
            line = line.strip()
            if line and not line.startswith("#"):  # Ignore empty lines and comments
                try:
                    address, symbol = line.split(",")
                    address = int(address, 16)
                    gdb.execute(f"set symbol-file-add-symbol {symbol} {address}")
                except Exception as e:
                    gdb.write(f"Error processing line '{line}': {e}\n")
        
        gdb.write("Symbols populated successfully.\n")

# Register the command with GDB
SymbolPopulator()
