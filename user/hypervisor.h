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

#ifdef __arm64__

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include <Hypervisor/Hypervisor.h>

#include <types.h>
#include <iboot.h>

#include "emu_fuzzer.h"
#include "virt.h"

namespace darwin {
namespace vm {

/* Valid Syndrome Register EC field values */
enum arm_exception_class {
    EC_UNCATEGORIZED = 0x00,
    EC_WFX_TRAP = 0x01,
    EC_CP15RTTRAP = 0x03,
    EC_CP15RRTTRAP = 0x04,
    EC_CP14RTTRAP = 0x05,
    EC_CP14DTTRAP = 0x06,
    EC_ADVSIMDFPACCESSTRAP = 0x07,
    EC_FPIDTRAP = 0x08,
    EC_PACTRAP = 0x09,
    EC_BXJTRAP = 0x0a,
    EC_CP14RRTTRAP = 0x0c,
    EC_BTITRAP = 0x0d,
    EC_ILLEGALSTATE = 0x0e,
    EC_AA32_SVC = 0x11,
    EC_AA32_HVC = 0x12,
    EC_AA32_SMC = 0x13,
    EC_AA64_SVC = 0x15,
    EC_AA64_HVC = 0x16,
    EC_AA64_SMC = 0x17,
    EC_SYSTEMREGISTERTRAP = 0x18,
    EC_SVEACCESSTRAP = 0x19,
    EC_SMETRAP = 0x1d,
    EC_INSNABORT = 0x20,
    EC_INSNABORT_SAME_EL = 0x21,
    EC_PCALIGNMENT = 0x22,
    EC_DATAABORT = 0x24,
    EC_DATAABORT_SAME_EL = 0x25,
    EC_SPALIGNMENT = 0x26,
    EC_AA32_FPTRAP = 0x28,
    EC_AA64_FPTRAP = 0x2c,
    EC_SERROR = 0x2f,
    EC_BREAKPOINT = 0x30,
    EC_BREAKPOINT_SAME_EL = 0x31,
    EC_SOFTWARESTEP = 0x32,
    EC_SOFTWARESTEP_SAME_EL = 0x33,
    EC_WATCHPOINT = 0x34,
    EC_WATCHPOINT_SAME_EL = 0x35,
    EC_AA32_BKPT = 0x38,
    EC_VECTORCATCH = 0x3a,
    EC_AA64_BKPT = 0x3c,
    EC_AA64_APPLE = 0x3f,
};

// ARM64 reset tramp
// I don't know why the CPU resets at EL0, so this is a trampoline
// that takes you to EL1.

// UPDATE: See CPSR below

const UInt8 sArm64ResetVector[] = {
    0x01, 0x00, 0x00, 0xD4, // SVC #0
    0x00, 0x00, 0x20, 0xD4, // BRK #0
};

const UInt8 sArm64ResetTrampoline[] = {
    0x00, 0x00, 0xB0, 0xD2, // MOV X0, #0x80000000
    0x00, 0x00, 0x1F, 0xD6, // BR  X0
    0x00, 0x00, 0x20, 0xD4, // BRK #0
};

#define HYP_ASSERT_SUCCESS(ret) assert((hv_return_t)(ret) == HV_SUCCESS)

static constexpr UInt64 gAdrResetTrampoline = 0xF0000000;
static constexpr UInt64 gResetTrampolineMemorySize = 0x10000;

static constexpr UInt64 gMainMemory = 0x80000000;
static constexpr UInt64 gMainMemSize = 0x40000000;

class Hypervisor {
public:
    explicit Hypervisor(fuzzer::Harness* harness, xnu::mach::VmAddress virtualBase, UInt64 base,
                        Size size, xnu::mach::VmAddress entryPoint);

    fuzzer::Harness* GetHarness() {
        return harness;
    }

    void* GetPhysicalMainMemory() {
        return mainMemory;
    }

    hv_vcpu_t GetVirtualCpu() {
        return vcpu;
    }

    hv_vcpu_exit_t* GetVirtualCpuExit() {
        return vcpu_exit;
    }

    UInt64 GetBase() {
        return base;
    }

    Size GetSize() {
        return size;
    }

    xnu::mach::VmAddress GetEntryPoint() {
        return entryPoint;
    }

    void SynchronizeCpuState();

    void FlushCpuState();

    int SysregRead(UInt32 reg, UInt32 rt);
    int SysregWrite(UInt32 reg, UInt64 val);

    int PrepareSystemMemory();

    void PrepareBootArgs(const char* deviceTreePath);

    void Configure();

    void Start();

    void Destroy();

private:
    fuzzer::Harness* harness;

    HvfArm64State state;

    struct boot_args boot_args;

    UInt64 base;

    xnu::mach::VmAddress virtualBase;

    Size size;

    xnu::mach::VmAddress entryPoint;

    hv_vcpu_t vcpu;

    hv_vcpu_exit_t* vcpu_exit;

    void* resetTrampolineMemory;
    void* mainMemory;

    UInt64 bootArgsOffset;
    UInt64 deviceTreeOffset;

    UInt64 framebufferOffset;
};

} // namespace vm
} // namespace darwin

#endif
