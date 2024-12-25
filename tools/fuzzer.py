import lldb

import time

import struct
import ctypes

import random
import afl

import sys
import os

from construct import Struct, Int32ul

def suppress_output():
    # Save the original standard output and standard error streams
    original_stdout = sys.stdout
    original_stderr = sys.stderr

    # Redirect standard output and standard error to /dev/null
    sys.stdout = open(os.devnull, 'w')
    sys.stderr = open(os.devnull, 'w')

    return original_stdout, original_stderr

def restore_output(original_stdout, original_stderr):
    # Restore the original standard output and standard error streams
    sys.stdout = original_stdout
    sys.stderr = original_stderr

def set_intermittent_breakpoints(target, process, function_name, delay, suppress_output):
    # Continue program execution until the breakpoint is hit
    process.Continue()

    time.sleep(delay)

    if suppress_output:
        original_stdout, original_stderr = suppress_output()

    process.SendAsyncInterrupt()

    # Continue the execution after the async interrupt
    while process.IsValid() and not process.GetState() == lldb.eStateStopped:
        pass

    # Set up a breakpoint at the beginning of the  function
    breakpoint = target.BreakpointCreateByName(function_name)

    process.Continue()

    # Continue the execution after the async interrupt
    while process.IsValid() and not process.GetSelectedThread().GetStopReason() == lldb.eStopReasonBreakpoint:
        pass

    if suppress_output:
        restore_output(original_stdout, original_stderr)

    time.sleep(delay)

    target.DeleteAllBreakpoints()

def print_backtrace(thread):
    # Get the stack frames of the thread
    frames = thread.frames

    print("Backtrace:")
    for frame_idx, frame in enumerate(frames):
        pc = frame.pc
        function_name = frame.GetFunctionName()
        file_name = frame.GetLineEntry().GetFileSpec().GetFilename()
        line_number = frame.GetLineEntry().GetLine()

        print(f"Frame {frame_idx}: PC: 0x{pc:x} Function: {function_name}")

def __lldb_init_module(debugger, internal_dict):
    # Connect to the LLDB debugger and the target executable
    target = debugger.GetSelectedTarget()

    process = target.process
                                                                              
    breakpoint = target.BreakpointCreateByName("btree_node_get")

    # Fuzzing loop
    while True:
        time.sleep(1)

        process.Continue()

        thread = process.GetSelectedThread()

        # Check if the process crashed
        if process.GetState() == lldb.eStateCrashed or "Global buffer overflow" in thread.GetStopDescription(100):
            # If a crash is detected, print the inputs that triggered the crash
            print("Crash detected")

            print_backtrace(thread)

            debugger.Terminate()

            break
        
        frame = thread.GetFrameAtIndex(0)

        arg0_address = frame.FindRegister("x0").GetValueAsUnsigned()

        size = struct.calcsize('q i')

        error = lldb.SBError()

        data = target.process.ReadMemory(arg0_address, size, error)

        if(data == None):
            continue

        original_data = data

        unpacked_struct = struct.unpack('q i', original_data)

        mutable_list = list(unpacked_struct)

        # mutable_list[1] = random.randint(10000, 100000)

        unpacked_struct = tuple(mutable_list)

        packed_struct = struct.pack('q i', unpacked_struct[0], unpacked_struct[1])

        data = lldb.SBData.CreateDataFromCString(lldb.eByteOrderLittle, size, str(packed_struct))

        error = lldb.SBError()

        # if(random.randint(0, 5) == 1):
            # target.process.WriteMemory(arg0_address, packed_struct, error)

        # if(random.randint(0, 50) == 1):
            # frame.registers[0].GetChildMemberWithName('x0').SetValueFromCString(str(a), error)

        '''

