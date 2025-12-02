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

#include <arch.h>
#include <types.h>
#include <vector.h>

namespace xnu {
class Kernel;
class Thread;
} // namespace xnu

namespace darwin {
class DarwinKit;
class KernelPatcher;
}; // namespace darwin

namespace debug {
enum class DebuggerAction {
    Interrupt,
    Continue,
    StepThreadLocked,
    StepThreadUnlocked,
    ShutdownEmulation,
};

constexpr char GDB_STUB_START = '$';
constexpr char GDB_STUB_END = '#';
constexpr char GDB_STUB_ACK = '+';
constexpr char GDB_STUB_NACK = '-';
constexpr char GDB_STUB_INT3 = 0x03;
constexpr int GDB_STUB_SIGTRAP = 5;

constexpr char GDB_STUB_REPLY_ERR[] = "E01";
constexpr char GDB_STUB_REPLY_OK[] = "OK";
constexpr char GDB_STUB_REPLY_EMPTY[] = "";

class Debugger {
public:
    explicit Debugger(xnu::Kernel* kernel);

    virtual void Connected() = 0;

    virtual UInt8* ReadFromClient() = 0;

    virtual void WriteToClient(std::span<const u8> data) = 0;

    virtual xnu::Thread* GetActiveThread() = 0;

    virtual void SetActiveThread(xnu::Thread* thread) = 0;

    virtual void Stopped(xnu::Thread* thread) = 0;

    virtual void ShuttingDown() = 0;

    virtual void Watchpoint(xnu::Thread* thread) = 0;

    virtual std::vector<DebuggerAction> ClientData(UInt8* data) = 0;

    bool NotifyThreadStopped(Kernel::KThread* thread);

    void NotifyShutdown();

    bool NotifyThreadWatchpoint(xnu::Thread* thread);

protected:
    GDBStubArch* arch;
    xnu::Kernel* kernel;
    debug::Dwarf* dwarf;
    xnu::KernelMachO* macho;
    darwin::DarwinKit* darwin;
};

class GdbStubA64 : public Debugger {
public:
    explicit GdbStubA64(xnu::Kernel* kernel);

    void AddBreakpoint(xnu::mach::VmAddress address);

    void RemoveBreakpoint(xnu::mach::VmAddress address);

    // std::String RegisterWrite(xnu::Thread* thread, std::String value) const override;

    // std::String RegisterRead(xnu::Thread* thread, Size id) const override;

    // void RegisterWrite(xnu::Thread* thread, Size id, std::String value) const override;

    // void WriteRegisters(xnu::Thread* thread, std::String register_data) const override;

    // std::String ThreadStatus(xnu::Thread* thread, u8 signal) const override;

private:
    arch::Architecture architecture;
    Array<Hook*> breakpoints;
};

class GdbStubX64 : public Debugger {
public:
    explicit GdbStubX64(xnu::Kernel* kernel);

    void AddBreakpoint(xnu::mach::VmAddress address);

    void RemoveBreakpoint(xnu::mach::VmAddress address);

    // std::String RegisterWrite(xnu::Thread* thread, std::String value) const override;

    // std::String RegisterRead(xnu::Thread* thread, Size id) const override;

    // void RegisterWrite(xnu::Thread* thread, Size id, std::String value) const override;

    // void WriteRegisters(xnu::Thread* thread, std::String register_data) const override;

    // std::String ThreadStatus(xnu::Thread* thread, u8 signal) const override;

private:
    arch::Architecture architecture;
    Array<Hook*> breakpoints;
}
}; // namespace debug
