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

#include <types.h>

#include <arch.h>
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

    virtual void connected() = 0;

    virtual UInt8* readFromClient() = 0;

    virtual void writeToClient(std::span<const u8> data) = 0;

    virtual xnu::Thread* getActiveThread() = 0;

    virtual void setActiveThread(xnu::Thread* thread) = 0;

    virtual void stopped(xnu::Thread* thread) = 0;

    virtual void shuttingDown() = 0;

    virtual void watchpoint(xnu::Thread* thread) = 0;

    virtual std::vector<DebuggerAction> clientData(UInt8* data) = 0;

    bool notifyThreadStopped(Kernel::KThread* thread);

    void notifyShutdown();

    bool notifyThreadWatchpoint(xnu::Thread* thread);

protected:
    GDBStubArch* arch;

    xnu::Kernel* kernel;

    debug::Dwarf* dwarf;

    xnu::KernelMachO* macho;

    darwin::DarwinKit* darwin;
};

class GDBStubA64 : public Debugger {
public:
    explicit GDBStubArm64(xnu::Kernel* kernel);

    void addBreakpoint(xnu::Mach::VmAddress address);

    void removeBreakpoint(xnu::Mach::VmAddress address);

    // std::String registerWrite(xnu::Thread* thread, std::String value) const override;

    // std::String registerRead(xnu::Thread* thread, Size id) const override;

    // void registerWrite(xnu::Thread* thread, Size id, std::String value) const override;

    // void writeRegisters(xnu::Thread* thread, std::String register_data) const override;

    // std::String threadStatus(xnu::Thread* thread, u8 signal) const override;

private:
    arch::Architecture architecture;

    Array<Hook*> breakpoints;
};

class GDBStubX64 : public Debugger {
public:
    explicit GDBStubX64(xnu::Kernel* kernel);

    void addBreakpoint(xnu::Mach::VmAddress address);

    void removeBreakpoint(xnu::Mach::VmAddress address);

    // std::String registerWrite(xnu::Thread* thread, std::String value) const override;

    // std::String registerRead(xnu::Thread* thread, Size id) const override;

    // void registerWrite(xnu::Thread* thread, Size id, std::String value) const override;

    // void writeRegisters(xnu::Thread* thread, std::String register_data) const override;

    // std::String threadStatus(xnu::Thread* thread, u8 signal) const override;

private:
    arch::Architecture architecture;

    Array<Hook*> breakpoints;
}
}; // namespace debug
