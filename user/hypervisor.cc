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

#ifdef __arm64__

#include "hypervisor.h"

#include "kernel_macho.h"

static inline int64_t get_clock(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

namespace darwin {
namespace vm {

Hypervisor::Hypervisor(fuzzer::Harness* harness, xnu::mach::VmAddress virtualBase, UInt64 base,
                       Size size, xnu::mach::VmAddress entryPoint)
    : harness(harness), virtualBase(virtualBase), base(base), size(size), entryPoint(entryPoint) {
    int ret;
    // Create the VM
    HYP_ASSERT_SUCCESS(hv_vm_create(nullptr));
    ret = PrepareSystemMemory();
    if (ret != 0) {
        printf("Failed to prepare Hypervisor's System Memory!\n");
        exit(-1);
    }
    PrepareBootArgs("DeviceTree_vma2");
    Configure();
    Start();
}

#define ARRAY_SIZE(x) ((sizeof(x) / sizeof((x)[0])))

void Hypervisor::SynchronizeCpuState() {
    HvfArm64State* env = &state;
    hv_return_t ret;
    UInt64 val;
    hv_simd_fp_uchar16_t fpval;
    int i;
    for (i = 0; i < ARRAY_SIZE(hvf_reg_match); i++) {
        HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(vcpu, (hv_reg_t)hvf_reg_match[i].reg, &val));
        *(UInt64*)((void*)((UInt64)env + hvf_reg_match[i].offset)) = val;
    }
    for (i = 0; i < ARRAY_SIZE(hvf_fpreg_match); i++) {
        HYP_ASSERT_SUCCESS(
            hv_vcpu_get_simd_fp_reg(vcpu, (hv_simd_fp_reg_t)hvf_fpreg_match[i].reg, &fpval));
        memcpy((void*)((UInt64)env + hvf_fpreg_match[i].offset), &fpval, sizeof(fpval));
    }
    /*
    val = 0;
    HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(vcpu, HV_REG_FPCR, &val));
    vfp_set_fpcr(env, val);

    val = 0;
    HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(vcpu, HV_REG_FPSR, &val));

    vfp_set_fpsr(env, val);
    */
    HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(vcpu, HV_REG_CPSR, &val));
    env->ZF = (~val) & PSTATE_Z;
    env->NF = val;
    env->CF = (val >> 29) & 1;
    env->VF = (val << 3) & 0x80000000;
    env->daif = val & PSTATE_DAIF;
    env->btype = (val >> 10) & 3;
    env->pstate = val & ~CACHED_PSTATE_BITS;
    for (i = 0; i < ARRAY_SIZE(hvf_sreg_match); i++) {
        if (hvf_sreg_match[i].cp_idx == -1) {
            continue;
        }
        if (0) {
            /* Handle debug registers */
            switch (hvf_sreg_match[i].reg) {
            case HV_SYS_REG_DBGBVR0_EL1:
            case HV_SYS_REG_DBGBCR0_EL1:
            case HV_SYS_REG_DBGWVR0_EL1:
            case HV_SYS_REG_DBGWCR0_EL1:
            case HV_SYS_REG_DBGBVR1_EL1:
            case HV_SYS_REG_DBGBCR1_EL1:
            case HV_SYS_REG_DBGWVR1_EL1:
            case HV_SYS_REG_DBGWCR1_EL1:
            case HV_SYS_REG_DBGBVR2_EL1:
            case HV_SYS_REG_DBGBCR2_EL1:
            case HV_SYS_REG_DBGWVR2_EL1:
            case HV_SYS_REG_DBGWCR2_EL1:
            case HV_SYS_REG_DBGBVR3_EL1:
            case HV_SYS_REG_DBGBCR3_EL1:
            case HV_SYS_REG_DBGWVR3_EL1:
            case HV_SYS_REG_DBGWCR3_EL1:
            case HV_SYS_REG_DBGBVR4_EL1:
            case HV_SYS_REG_DBGBCR4_EL1:
            case HV_SYS_REG_DBGWVR4_EL1:
            case HV_SYS_REG_DBGWCR4_EL1:
            case HV_SYS_REG_DBGBVR5_EL1:
            case HV_SYS_REG_DBGBCR5_EL1:
            case HV_SYS_REG_DBGWVR5_EL1:
            case HV_SYS_REG_DBGWCR5_EL1:
            case HV_SYS_REG_DBGBVR6_EL1:
            case HV_SYS_REG_DBGBCR6_EL1:
            case HV_SYS_REG_DBGWVR6_EL1:
            case HV_SYS_REG_DBGWCR6_EL1:
            case HV_SYS_REG_DBGBVR7_EL1:
            case HV_SYS_REG_DBGBCR7_EL1:
            case HV_SYS_REG_DBGWVR7_EL1:
            case HV_SYS_REG_DBGWCR7_EL1:
            case HV_SYS_REG_DBGBVR8_EL1:
            case HV_SYS_REG_DBGBCR8_EL1:
            case HV_SYS_REG_DBGWVR8_EL1:
            case HV_SYS_REG_DBGWCR8_EL1:
            case HV_SYS_REG_DBGBVR9_EL1:
            case HV_SYS_REG_DBGBCR9_EL1:
            case HV_SYS_REG_DBGWVR9_EL1:
            case HV_SYS_REG_DBGWCR9_EL1:
            case HV_SYS_REG_DBGBVR10_EL1:
            case HV_SYS_REG_DBGBCR10_EL1:
            case HV_SYS_REG_DBGWVR10_EL1:
            case HV_SYS_REG_DBGWCR10_EL1:
            case HV_SYS_REG_DBGBVR11_EL1:
            case HV_SYS_REG_DBGBCR11_EL1:
            case HV_SYS_REG_DBGWVR11_EL1:
            case HV_SYS_REG_DBGWCR11_EL1:
            case HV_SYS_REG_DBGBVR12_EL1:
            case HV_SYS_REG_DBGBCR12_EL1:
            case HV_SYS_REG_DBGWVR12_EL1:
            case HV_SYS_REG_DBGWCR12_EL1:
            case HV_SYS_REG_DBGBVR13_EL1:
            case HV_SYS_REG_DBGBCR13_EL1:
            case HV_SYS_REG_DBGWVR13_EL1:
            case HV_SYS_REG_DBGWCR13_EL1:
            case HV_SYS_REG_DBGBVR14_EL1:
            case HV_SYS_REG_DBGBCR14_EL1:
            case HV_SYS_REG_DBGWVR14_EL1:
            case HV_SYS_REG_DBGWCR14_EL1:
            case HV_SYS_REG_DBGBVR15_EL1:
            case HV_SYS_REG_DBGBCR15_EL1:
            case HV_SYS_REG_DBGWVR15_EL1:
            case HV_SYS_REG_DBGWCR15_EL1: {
                /*
                 * If the guest is being debugged, the vCPU's debug registers
                 * are holding the gdbstub's view of the registers (set in
                 * hvf_arch_update_guest_debug()).
                 * Since the environment is used to store only the guest's view
                 * of the registers, don't update it with the values from the
                 * vCPU but simply keep the values from the previous
                 * environment.
                 */

                /*
                const ARMCPRegInfo *ri;
                ri = get_arm_cp_reginfo(arm_cpu->cp_regs, hvf_sreg_match[i].key);
                val = read_raw_cp_reg(env, ri);

                arm_cpu->cpreg_values[hvf_sreg_match[i].cp_idx] = val;
                */
                continue;
            }
            }
        }
        HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(vcpu, (hv_sys_reg_t)hvf_sreg_match[i].reg, &val));
        // arm_cpu->cpreg_values[hvf_sreg_match[i].cp_idx] = val;
    }
    // assert(write_list_to_cpustate(arm_cpu));
    int el;
    if (env->aarch64) {
        el = extract32(env->pstate, 2, 2);
    }
    switch (env->uncached_cpsr & 0x1f) {
    case ARM_CPU_MODE_USR:
        el = 0;
    case ARM_CPU_MODE_HYP:
        el = 2;
    case ARM_CPU_MODE_MON:
        el = 3;
    default:
        el = 1;
    }
    if (env->pstate & PSTATE_SP) {
        env->sp_el[el] = env->xregs[31];
    } else {
        env->sp_el[0] = env->xregs[31];
    }
}

void Hypervisor::FlushCpuState() {
    HvfArm64State* env = &state;
    hv_return_t ret;
    UInt64 val;
    hv_simd_fp_uchar16_t fpval;
    int i;
    for (i = 0; i < ARRAY_SIZE(hvf_reg_match); i++) {
        val = *(UInt64*)((void*)((UInt64)env + hvf_reg_match[i].offset));
        HYP_ASSERT_SUCCESS(hv_vcpu_set_reg(vcpu, (hv_reg_t)hvf_reg_match[i].reg, val));
    }
    for (i = 0; i < ARRAY_SIZE(hvf_fpreg_match); i++) {
        memcpy(&fpval, (void*)((UInt64)env + hvf_fpreg_match[i].offset), sizeof(fpval));
        HYP_ASSERT_SUCCESS(
            hv_vcpu_set_simd_fp_reg(vcpu, (hv_simd_fp_reg_t)hvf_fpreg_match[i].reg, fpval));
    }
    // HYP_ASSERT_SUCCESS(hv_vcpu_set_reg(vcpu, HV_REG_FPCR, vfp_get_fpcr(env)));
    // HYP_ASSERT_SUCCESS(hv_vcpu_set_reg(vcpu, HV_REG_FPSR, vfp_get_fpsr(env)));
    int ZF;
    ZF = (env->ZF == 0);
    UInt32 cpsr = (env->NF & 0x80000000) | (ZF << 30) | (env->CF << 29) |
                  ((env->VF & 0x80000000) >> 3) | env->pstate | env->daif | (env->btype << 10);
    HYP_ASSERT_SUCCESS(hv_vcpu_set_reg(vcpu, HV_REG_CPSR, cpsr));
    int el;
    if (env->aarch64) {
        el = extract32(env->pstate, 2, 2);
    }
    switch (env->uncached_cpsr & 0x1f) {
    case ARM_CPU_MODE_USR:
        el = 0;
    case ARM_CPU_MODE_HYP:
        el = 2;
    case ARM_CPU_MODE_MON:
        el = 3;
    default:
        el = 1;
    }
    if (env->pstate & PSTATE_SP) {
        env->sp_el[el] = env->xregs[31];
    } else {
        env->sp_el[0] = env->xregs[31];
    }
    for (i = 0; i < ARRAY_SIZE(hvf_sreg_match); i++) {
        if (hvf_sreg_match[i].cp_idx == -1) {
            continue;
        }
        if (0) {
            /* Handle debug registers */
            switch (hvf_sreg_match[i].reg) {
            case HV_SYS_REG_DBGBVR0_EL1:
            case HV_SYS_REG_DBGBCR0_EL1:
            case HV_SYS_REG_DBGWVR0_EL1:
            case HV_SYS_REG_DBGWCR0_EL1:
            case HV_SYS_REG_DBGBVR1_EL1:
            case HV_SYS_REG_DBGBCR1_EL1:
            case HV_SYS_REG_DBGWVR1_EL1:
            case HV_SYS_REG_DBGWCR1_EL1:
            case HV_SYS_REG_DBGBVR2_EL1:
            case HV_SYS_REG_DBGBCR2_EL1:
            case HV_SYS_REG_DBGWVR2_EL1:
            case HV_SYS_REG_DBGWCR2_EL1:
            case HV_SYS_REG_DBGBVR3_EL1:
            case HV_SYS_REG_DBGBCR3_EL1:
            case HV_SYS_REG_DBGWVR3_EL1:
            case HV_SYS_REG_DBGWCR3_EL1:
            case HV_SYS_REG_DBGBVR4_EL1:
            case HV_SYS_REG_DBGBCR4_EL1:
            case HV_SYS_REG_DBGWVR4_EL1:
            case HV_SYS_REG_DBGWCR4_EL1:
            case HV_SYS_REG_DBGBVR5_EL1:
            case HV_SYS_REG_DBGBCR5_EL1:
            case HV_SYS_REG_DBGWVR5_EL1:
            case HV_SYS_REG_DBGWCR5_EL1:
            case HV_SYS_REG_DBGBVR6_EL1:
            case HV_SYS_REG_DBGBCR6_EL1:
            case HV_SYS_REG_DBGWVR6_EL1:
            case HV_SYS_REG_DBGWCR6_EL1:
            case HV_SYS_REG_DBGBVR7_EL1:
            case HV_SYS_REG_DBGBCR7_EL1:
            case HV_SYS_REG_DBGWVR7_EL1:
            case HV_SYS_REG_DBGWCR7_EL1:
            case HV_SYS_REG_DBGBVR8_EL1:
            case HV_SYS_REG_DBGBCR8_EL1:
            case HV_SYS_REG_DBGWVR8_EL1:
            case HV_SYS_REG_DBGWCR8_EL1:
            case HV_SYS_REG_DBGBVR9_EL1:
            case HV_SYS_REG_DBGBCR9_EL1:
            case HV_SYS_REG_DBGWVR9_EL1:
            case HV_SYS_REG_DBGWCR9_EL1:
            case HV_SYS_REG_DBGBVR10_EL1:
            case HV_SYS_REG_DBGBCR10_EL1:
            case HV_SYS_REG_DBGWVR10_EL1:
            case HV_SYS_REG_DBGWCR10_EL1:
            case HV_SYS_REG_DBGBVR11_EL1:
            case HV_SYS_REG_DBGBCR11_EL1:
            case HV_SYS_REG_DBGWVR11_EL1:
            case HV_SYS_REG_DBGWCR11_EL1:
            case HV_SYS_REG_DBGBVR12_EL1:
            case HV_SYS_REG_DBGBCR12_EL1:
            case HV_SYS_REG_DBGWVR12_EL1:
            case HV_SYS_REG_DBGWCR12_EL1:
            case HV_SYS_REG_DBGBVR13_EL1:
            case HV_SYS_REG_DBGBCR13_EL1:
            case HV_SYS_REG_DBGWVR13_EL1:
            case HV_SYS_REG_DBGWCR13_EL1:
            case HV_SYS_REG_DBGBVR14_EL1:
            case HV_SYS_REG_DBGBCR14_EL1:
            case HV_SYS_REG_DBGWVR14_EL1:
            case HV_SYS_REG_DBGWCR14_EL1:
            case HV_SYS_REG_DBGBVR15_EL1:
            case HV_SYS_REG_DBGBCR15_EL1:
            case HV_SYS_REG_DBGWVR15_EL1:
            case HV_SYS_REG_DBGWCR15_EL1:
                /*
                 * If the guest is being debugged, the vCPU's debug registers
                 * are already holding the gdbstub's view of the registers (set
                 * in hvf_arch_update_guest_debug()).
                 */
                continue;
            }
        }
        // val = arm_cpu->cpreg_values[hvf_sreg_match[i].cp_idx];
        HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(vcpu, (hv_sys_reg_t)hvf_sreg_match[i].reg, val));
    }
    // HYP_ASSERT_SUCCESS(hv_vcpu_set_vtimer_offset(cpu->accel->fd, hvf_state->vtimer_offset));
}

int Hypervisor::SysregRead(UInt32 reg, UInt32 rt) {
    HvfArm64State* env = &state;
    UInt64 val = 0;
    switch (reg) {
    case SYSREG_CNTPCT_EL0:
        UInt64 gt_cntfrq_hz;
        asm volatile("mrs %0, cntfrq_el0" : "=r"(gt_cntfrq_hz));
#define NANOSECONDS_PER_SECOND 1000000000LL
        val = get_clock() /
              (NANOSECONDS_PER_SECOND > gt_cntfrq_hz ? NANOSECONDS_PER_SECOND / gt_cntfrq_hz : 1);
        break;
    case SYSREG_PMCR_EL0:
        val = env->cp15.c9_pmcr;
        break;
    case SYSREG_PMCCNTR_EL0:
        // pmu_op_start(env);
        val = env->cp15.c15_ccnt;
        // pmu_op_finish(env);
        break;
    case SYSREG_PMCNTENCLR_EL0:
        val = env->cp15.c9_pmcnten;
        break;
    case SYSREG_PMOVSCLR_EL0:
        val = env->cp15.c9_pmovsr;
        break;
    case SYSREG_PMSELR_EL0:
        val = env->cp15.c9_pmselr;
        break;
    case SYSREG_PMINTENCLR_EL1:
        val = env->cp15.c9_pminten;
        break;
    case SYSREG_PMCCFILTR_EL0:
        val = env->cp15.pmccfiltr_el0;
        break;
    case SYSREG_PMCNTENSET_EL0:
        val = env->cp15.c9_pmcnten;
        break;
    case SYSREG_PMUSERENR_EL0:
        val = env->cp15.c9_pmuserenr;
        break;
    case SYSREG_PMCEID0_EL0:
    case SYSREG_PMCEID1_EL0:
        /* We can't really count anything yet, declare all events invalid */
        val = 0;
        break;
    case SYSREG_OSLSR_EL1:
        val = env->cp15.oslsr_el1;
        break;
    case SYSREG_OSDLR_EL1:
        /* Dummy register */
        break;
    case SYSREG_ICC_AP0R0_EL1:
    case SYSREG_ICC_AP0R1_EL1:
    case SYSREG_ICC_AP0R2_EL1:
    case SYSREG_ICC_AP0R3_EL1:
    case SYSREG_ICC_AP1R0_EL1:
    case SYSREG_ICC_AP1R1_EL1:
    case SYSREG_ICC_AP1R2_EL1:
    case SYSREG_ICC_AP1R3_EL1:
    case SYSREG_ICC_ASGI1R_EL1:
    case SYSREG_ICC_BPR0_EL1:
    case SYSREG_ICC_BPR1_EL1:
    case SYSREG_ICC_DIR_EL1:
    case SYSREG_ICC_EOIR0_EL1:
    case SYSREG_ICC_EOIR1_EL1:
    case SYSREG_ICC_HPPIR0_EL1:
    case SYSREG_ICC_HPPIR1_EL1:
    case SYSREG_ICC_IAR0_EL1:
    case SYSREG_ICC_IAR1_EL1:
    case SYSREG_ICC_IGRPEN0_EL1:
    case SYSREG_ICC_IGRPEN1_EL1:
    case SYSREG_ICC_PMR_EL1:
    case SYSREG_ICC_SGI0R_EL1:
    case SYSREG_ICC_SGI1R_EL1:
    case SYSREG_ICC_SRE_EL1:
    case SYSREG_ICC_CTLR_EL1:
        /* Call the TCG sysreg handler. This is only safe for GICv3 regs. */
        // if (!hvf_sysreg_read_cp(cpu, reg, &val)) {
        //    hvf_raise_exception(cpu, EXCP_UDEF, syn_uncategorized());
        // }
        break;
    case SYSREG_MDSCR_EL1:
        val = env->cp15.mdscr_el1;
        break;
    case SYSREG_DBGBVR0_EL1:
    case SYSREG_DBGBVR1_EL1:
    case SYSREG_DBGBVR2_EL1:
    case SYSREG_DBGBVR3_EL1:
    case SYSREG_DBGBVR4_EL1:
    case SYSREG_DBGBVR5_EL1:
    case SYSREG_DBGBVR6_EL1:
    case SYSREG_DBGBVR7_EL1:
    case SYSREG_DBGBVR8_EL1:
    case SYSREG_DBGBVR9_EL1:
    case SYSREG_DBGBVR10_EL1:
    case SYSREG_DBGBVR11_EL1:
    case SYSREG_DBGBVR12_EL1:
    case SYSREG_DBGBVR13_EL1:
    case SYSREG_DBGBVR14_EL1:
    case SYSREG_DBGBVR15_EL1:
        val = env->cp15.dbgbvr[SYSREG_CRM(reg)];
        break;
    case SYSREG_DBGBCR0_EL1:
    case SYSREG_DBGBCR1_EL1:
    case SYSREG_DBGBCR2_EL1:
    case SYSREG_DBGBCR3_EL1:
    case SYSREG_DBGBCR4_EL1:
    case SYSREG_DBGBCR5_EL1:
    case SYSREG_DBGBCR6_EL1:
    case SYSREG_DBGBCR7_EL1:
    case SYSREG_DBGBCR8_EL1:
    case SYSREG_DBGBCR9_EL1:
    case SYSREG_DBGBCR10_EL1:
    case SYSREG_DBGBCR11_EL1:
    case SYSREG_DBGBCR12_EL1:
    case SYSREG_DBGBCR13_EL1:
    case SYSREG_DBGBCR14_EL1:
    case SYSREG_DBGBCR15_EL1:
        val = env->cp15.dbgbcr[SYSREG_CRM(reg)];
        break;
    case SYSREG_DBGWVR0_EL1:
    case SYSREG_DBGWVR1_EL1:
    case SYSREG_DBGWVR2_EL1:
    case SYSREG_DBGWVR3_EL1:
    case SYSREG_DBGWVR4_EL1:
    case SYSREG_DBGWVR5_EL1:
    case SYSREG_DBGWVR6_EL1:
    case SYSREG_DBGWVR7_EL1:
    case SYSREG_DBGWVR8_EL1:
    case SYSREG_DBGWVR9_EL1:
    case SYSREG_DBGWVR10_EL1:
    case SYSREG_DBGWVR11_EL1:
    case SYSREG_DBGWVR12_EL1:
    case SYSREG_DBGWVR13_EL1:
    case SYSREG_DBGWVR14_EL1:
    case SYSREG_DBGWVR15_EL1:
        val = env->cp15.dbgwvr[SYSREG_CRM(reg)];
        break;
    case SYSREG_DBGWCR0_EL1:
    case SYSREG_DBGWCR1_EL1:
    case SYSREG_DBGWCR2_EL1:
    case SYSREG_DBGWCR3_EL1:
    case SYSREG_DBGWCR4_EL1:
    case SYSREG_DBGWCR5_EL1:
    case SYSREG_DBGWCR6_EL1:
    case SYSREG_DBGWCR7_EL1:
    case SYSREG_DBGWCR8_EL1:
    case SYSREG_DBGWCR9_EL1:
    case SYSREG_DBGWCR10_EL1:
    case SYSREG_DBGWCR11_EL1:
    case SYSREG_DBGWCR12_EL1:
    case SYSREG_DBGWCR13_EL1:
    case SYSREG_DBGWCR14_EL1:
    case SYSREG_DBGWCR15_EL1:
        val = env->cp15.dbgwcr[SYSREG_CRM(reg)];
        break;
    default:
        if (SYSREG_OP0(reg) == 3 && SYSREG_OP1(reg) == 0 && SYSREG_CRN(reg) == 0 &&
            SYSREG_CRM(reg) >= 1 && SYSREG_CRM(reg) < 8) {
            val = 0;

            break;
        }

        printf("Failed!\n");

        return 1;
    }
    printf("Success!\n");
    HYP_ASSERT_SUCCESS(hv_vcpu_set_reg(vcpu, (hv_reg_t)(HV_REG_X0 + rt), val));
    return 0;
}

int Hypervisor::SysregWrite(UInt32 reg, UInt64 val) {
    HvfArm64State* env = &state;
    switch (reg) {
    case SYSREG_PMCCNTR_EL0:
        env->cp15.c15_ccnt = val;
        break;
    case SYSREG_PMCR_EL0:
        if (val & PMCRC) {
            /* The counter has been reset */
            env->cp15.c15_ccnt = 0;
        }
        if (val & PMCRP) {
            unsigned int i;
            for (i = 0; i < pmu_num_counters(env); i++) {
                env->cp15.c14_pmevcntr[i] = 0;
            }
        }
        env->cp15.c9_pmcr &= ~PMCR_WRITABLE_MASK;
        env->cp15.c9_pmcr |= (val & PMCR_WRITABLE_MASK);
        break;
    case SYSREG_PMUSERENR_EL0:
        env->cp15.c9_pmuserenr = val & 0xf;
        break;
    case SYSREG_PMCNTENSET_EL0:
        env->cp15.c9_pmcnten |= (val & pmu_counter_mask(env));
        break;
    case SYSREG_PMCNTENCLR_EL0:
        env->cp15.c9_pmcnten &= ~(val & pmu_counter_mask(env));
        break;
    case SYSREG_PMINTENCLR_EL1:
        env->cp15.c9_pminten |= val;
        break;
    case SYSREG_PMOVSCLR_EL0:
        env->cp15.c9_pmovsr &= ~val;
        break;
    case SYSREG_PMSWINC_EL0:
        break;
    case SYSREG_PMSELR_EL0:
        env->cp15.c9_pmselr = val & 0x1f;
        break;
    case SYSREG_PMCCFILTR_EL0:
        env->cp15.pmccfiltr_el0 = val & PMCCFILTR_EL0;
        break;
    case SYSREG_OSLAR_EL1:
        env->cp15.oslsr_el1 = val & 1;
        break;
    case SYSREG_OSDLR_EL1:
        /* Dummy register */
        break;
    case SYSREG_ICC_AP0R0_EL1:
    case SYSREG_ICC_AP0R1_EL1:
    case SYSREG_ICC_AP0R2_EL1:
    case SYSREG_ICC_AP0R3_EL1:
    case SYSREG_ICC_AP1R0_EL1:
    case SYSREG_ICC_AP1R1_EL1:
    case SYSREG_ICC_AP1R2_EL1:
    case SYSREG_ICC_AP1R3_EL1:
    case SYSREG_ICC_ASGI1R_EL1:
    case SYSREG_ICC_BPR0_EL1:
    case SYSREG_ICC_BPR1_EL1:
    case SYSREG_ICC_CTLR_EL1:
    case SYSREG_ICC_DIR_EL1:
    case SYSREG_ICC_EOIR0_EL1:
    case SYSREG_ICC_EOIR1_EL1:
    case SYSREG_ICC_HPPIR0_EL1:
    case SYSREG_ICC_HPPIR1_EL1:
    case SYSREG_ICC_IAR0_EL1:
    case SYSREG_ICC_IAR1_EL1:
    case SYSREG_ICC_IGRPEN0_EL1:
    case SYSREG_ICC_IGRPEN1_EL1:
    case SYSREG_ICC_PMR_EL1:
    case SYSREG_ICC_SGI0R_EL1:
    case SYSREG_ICC_SGI1R_EL1:
    case SYSREG_ICC_SRE_EL1:
        /* Call the TCG sysreg handler. This is only safe for GICv3 regs. */
        // if (!hvf_sysreg_write_cp(cpu, reg, val)) {
        //     hvf_raise_exception(cpu, EXCP_UDEF, syn_uncategorized());
        // }
        break;
    case SYSREG_MDSCR_EL1:
        env->cp15.mdscr_el1 = val;
        break;
    case SYSREG_DBGBVR0_EL1:
    case SYSREG_DBGBVR1_EL1:
    case SYSREG_DBGBVR2_EL1:
    case SYSREG_DBGBVR3_EL1:
    case SYSREG_DBGBVR4_EL1:
    case SYSREG_DBGBVR5_EL1:
    case SYSREG_DBGBVR6_EL1:
    case SYSREG_DBGBVR7_EL1:
    case SYSREG_DBGBVR8_EL1:
    case SYSREG_DBGBVR9_EL1:
    case SYSREG_DBGBVR10_EL1:
    case SYSREG_DBGBVR11_EL1:
    case SYSREG_DBGBVR12_EL1:
    case SYSREG_DBGBVR13_EL1:
    case SYSREG_DBGBVR14_EL1:
    case SYSREG_DBGBVR15_EL1:
        env->cp15.dbgbvr[SYSREG_CRM(reg)] = val;
        break;
    case SYSREG_DBGBCR0_EL1:
    case SYSREG_DBGBCR1_EL1:
    case SYSREG_DBGBCR2_EL1:
    case SYSREG_DBGBCR3_EL1:
    case SYSREG_DBGBCR4_EL1:
    case SYSREG_DBGBCR5_EL1:
    case SYSREG_DBGBCR6_EL1:
    case SYSREG_DBGBCR7_EL1:
    case SYSREG_DBGBCR8_EL1:
    case SYSREG_DBGBCR9_EL1:
    case SYSREG_DBGBCR10_EL1:
    case SYSREG_DBGBCR11_EL1:
    case SYSREG_DBGBCR12_EL1:
    case SYSREG_DBGBCR13_EL1:
    case SYSREG_DBGBCR14_EL1:
    case SYSREG_DBGBCR15_EL1:
        env->cp15.dbgbcr[SYSREG_CRM(reg)] = val;
        break;
    case SYSREG_DBGWVR0_EL1:
    case SYSREG_DBGWVR1_EL1:
    case SYSREG_DBGWVR2_EL1:
    case SYSREG_DBGWVR3_EL1:
    case SYSREG_DBGWVR4_EL1:
    case SYSREG_DBGWVR5_EL1:
    case SYSREG_DBGWVR6_EL1:
    case SYSREG_DBGWVR7_EL1:
    case SYSREG_DBGWVR8_EL1:
    case SYSREG_DBGWVR9_EL1:
    case SYSREG_DBGWVR10_EL1:
    case SYSREG_DBGWVR11_EL1:
    case SYSREG_DBGWVR12_EL1:
    case SYSREG_DBGWVR13_EL1:
    case SYSREG_DBGWVR14_EL1:
    case SYSREG_DBGWVR15_EL1:
        env->cp15.dbgwvr[SYSREG_CRM(reg)] = val;
        break;
    case SYSREG_DBGWCR0_EL1:
    case SYSREG_DBGWCR1_EL1:
    case SYSREG_DBGWCR2_EL1:
    case SYSREG_DBGWCR3_EL1:
    case SYSREG_DBGWCR4_EL1:
    case SYSREG_DBGWCR5_EL1:
    case SYSREG_DBGWCR6_EL1:
    case SYSREG_DBGWCR7_EL1:
    case SYSREG_DBGWCR8_EL1:
    case SYSREG_DBGWCR9_EL1:
    case SYSREG_DBGWCR10_EL1:
    case SYSREG_DBGWCR11_EL1:
    case SYSREG_DBGWCR12_EL1:
    case SYSREG_DBGWCR13_EL1:
    case SYSREG_DBGWCR14_EL1:
    case SYSREG_DBGWCR15_EL1:
        env->cp15.dbgwcr[SYSREG_CRM(reg)] = val;
        break;
    default:
        printf("Failed!\n");

        return 0;
    }
    printf("Success!\n");
    return 0;
}

void Hypervisor::PrepareBootArgs(const char* deviceTreePath) {
    int fd = open(deviceTreePath, O_RDONLY);
    if (!fd) {
        fprintf(stderr, "Failed to open DeviceTree at path %s\n", deviceTreePath);

        exit(-1);
    }
    Size deviceTreeSize = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);
    char* deviceTree = reinterpret_cast<char*>(malloc(deviceTreeSize));
    Size bytes_read;
    bytes_read = read(fd, deviceTree, size);
    close(fd);
    printf("deviceTree = 0x%llx\n", (UInt64)deviceTree);
    printf("deviceTreeSize = 0x%llx\n", (UInt64)deviceTreeSize);
    char* CommandLineArguments = "-s";
    bootArgsOffset = size + 0x10000;
    framebufferOffset = size + 0x10000 * 4;
    deviceTreeOffset = size + 0x10000 * 32;
    boot_args.Revision = kBootArgsRevision2;
    boot_args.Version = kBootArgsVersion2;
    boot_args.virtBase = virtualBase;
    boot_args.physBase = gMainMemory;
    boot_args.memSize = gMainMemSize;
    boot_args.topOfKernelData = base + size;
    boot_args.Video.v_baseAddr = gMainMemory + framebufferOffset;
    boot_args.Video.v_display = 1;
    boot_args.Video.v_rowBytes = FRAMEBUFFER_STRIDE_BYTES;
    boot_args.Video.v_width = FRAMEBUFFER_WIDTH;
    boot_args.Video.v_height = FRAMEBUFFER_HEIGHT;
    boot_args.Video.v_depth = FRAMEBUFFER_DEPTH_BITS;
    boot_args.machineType = 0;
    boot_args.deviceTreeP = (void*)(gMainMemory + deviceTreeOffset);
    boot_args.deviceTreeLength = deviceTreeSize;
    strlcpy(boot_args.CommandLine, CommandLineArguments, strlen(CommandLineArguments));
    boot_args.bootFlags = 0;
    boot_args.memSizeActual = gMainMemSize;
    memcpy((void*)((UInt64)mainMemory + deviceTreeOffset), (void*)deviceTree, deviceTreeSize);
    memcpy((void*)((UInt64)mainMemory + bootArgsOffset), (void*)&boot_args,
           sizeof(struct boot_args));
    printf("deviceTreeP = 0x%llx\n", (UInt64)boot_args.deviceTreeP);
    printf("deviceTreeLength = 0x%llx\n", (UInt64)boot_args.deviceTreeLength);
    printf("virtBase = 0x%llx\n", boot_args.virtBase);
    printf("physBase = 0x%llx\n", boot_args.physBase);
}

int Hypervisor::PrepareSystemMemory() {
    // Reset trampoline
    // Well, dear Apple, why you reset the CPU at EL0
    posix_memalign(&resetTrampolineMemory, 0x10000, gResetTrampolineMemorySize);
    if (resetTrampolineMemory == nullptr) {
        printf("Failed to posix_memalign() g_pMainMemory!\n");

        return -ENOMEM;
    }
    memset(resetTrampolineMemory, 0, gResetTrampolineMemorySize);
    for (UInt64 offset = 0; offset < 0x780; offset += 0x80) {
        memcpy((void*)((UInt64)resetTrampolineMemory + offset), sArm64ResetTrampoline,
               sizeof(sArm64ResetTrampoline));
    }
    // memcpy((void*) ((UInt64) resetTrampolineMemory + 0x800), sArm64ResetVector,
    // sizeof(sArm64ResetVector));
    // Map the RAM into the VM
    HYP_ASSERT_SUCCESS(hv_vm_map(resetTrampolineMemory, gAdrResetTrampoline,
                                 gResetTrampolineMemorySize, HV_MEMORY_READ | HV_MEMORY_EXEC));
    // Main memory.
    posix_memalign(&mainMemory, 0x1000, gMainMemSize);
    if (mainMemory == nullptr) {
        printf("Failed to posix_memalign() g_pMainMemory!\n");
        return -ENOMEM;
    }
    // Copy our code into the VM's RAM
    memset(mainMemory, 0, gMainMemSize);
    memcpy(mainMemory, (void*)base, size);
    // Map the RAM into the VM
    HYP_ASSERT_SUCCESS(hv_vm_map(mainMemory, gMainMemory, gMainMemSize,
                                 HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC));
    return 0;
}

void Hypervisor::Configure() {
    xnu::mach::VmAddress __start = (entryPoint - virtualBase) + gMainMemory;
    printf("entryPoint = 0x%llx\n", entryPoint);
    printf("virtualBase = 0x%llx\n", virtualBase);
    printf("__start physical address = 0x%llx\n", __start);
    // Add a virtual CPU to our VM
    HYP_ASSERT_SUCCESS(hv_vcpu_create(&vcpu, &vcpu_exit, nullptr));
    // Configure initial VBAR_EL1 to the trampoline
    HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_VBAR_EL1, gAdrResetTrampoline));
#if USE_EL0_TRAMPOILNE
    // Set the CPU's PC to execute from the trampoline
    HYP_ASSERT_SUCCESS(hv_vcpu_set_reg(vcpu, HV_REG_PC, gAdrResetTrampoline + 0x800));
#else
    // Or explicitly set CPSR
    HYP_ASSERT_SUCCESS(hv_vcpu_set_reg(vcpu, HV_REG_CPSR, 0x3c4));
    HYP_ASSERT_SUCCESS(hv_vcpu_set_reg(vcpu, HV_REG_PC, __start));
#endif
    // Configure misc
    HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_SP_EL0, gMainMemory + size + 0x4000));
    HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_SP_EL1, gMainMemory + size + 0x8000));
    HYP_ASSERT_SUCCESS(hv_vcpu_set_reg(vcpu, HV_REG_FP, gMainMemory + size + 0xC000));
    // Trap debug access (BRK)
    HYP_ASSERT_SUCCESS(hv_vcpu_set_trap_debug_exceptions(vcpu, true));
    HYP_ASSERT_SUCCESS(hv_vcpu_set_trap_debug_reg_accesses(vcpu, true));
    HYP_ASSERT_SUCCESS(hv_vcpu_set_reg(vcpu, HV_REG_X0, (UInt64)gMainMemory + bootArgsOffset));
}

void Hypervisor::Start() {
    // start the VM
    while (true) {
        // Run the VM until a VM exit
        HYP_ASSERT_SUCCESS(hv_vcpu_run(vcpu));
        // Check why we exited the VM
        if (vcpu_exit->reason == HV_EXIT_REASON_EXCEPTION) {
            // Check if this is an HVC call
            // https://developer.arm.com/docs/ddi0595/e/aarch64-system-registers/esr_el2
            UInt64 syndrome = vcpu_exit->exception.syndrome;
            UInt8 ec = (syndrome >> 26) & 0x3f;
            // check Exception Class
            printf("EC = %u Syndrome %llu\n", ec, syndrome);
            SynchronizeCpuState();
            if (ec == EC_AA32_HVC) {
                // Exception Class 0x16 is
                // "HVC instruction execution in AArch64 state, when HVC is not disabled."
                UInt64 x0;
                HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(vcpu, HV_REG_X0, &x0));
                printf("VM made an HVC call! x0 register holds 0x%llx\n", x0);
                break;
            } else if (ec == EC_AA64_SMC) {
                // Exception Class 0x17 is
                // "SMC instruction execution in AArch64 state, when SMC is not disabled."
                // Yes despite M1 doesn't have EL3, it is capable to trap it too. :)
                UInt64 x0;
                HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(vcpu, HV_REG_X0, &x0));
                printf("VM made an SMC call! x0 register holds 0x%llx\n", x0);
                printf("Return to get on next instruction.\n");
                // ARM spec says trapped SMC have different return path, so it is required
                // to increment elr_el2 by 4 (one instruction.)
                UInt64 pc;
                HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(vcpu, HV_REG_PC, &pc));
                pc += 4;
                HYP_ASSERT_SUCCESS(hv_vcpu_set_reg(vcpu, HV_REG_PC, pc));
            } else if (ec == EC_SYSTEMREGISTERTRAP) {
                UInt64 pc;
                bool isread = (syndrome >> 0) & 1;
                UInt32 rt = (syndrome >> 5) & 0x1f;
                UInt32 reg = syndrome & SYSREG_MASK;
                UInt64 val;
                int ret = 0;
                if (isread) {
                    ret = SysregRead(reg, rt);
                } else {
                    HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(vcpu, (hv_reg_t)rt, &val));
                    ret = SysregWrite(reg, val);
                }
                HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(vcpu, HV_REG_PC, &pc));
                printf("EC_SYSTEMREGISTERTRAP isread = %u pc 0x%llx %u %u 0x%x!\n", isread, pc, rt,
                       reg, *(UInt32*)((pc - gMainMemory) + (UInt64)mainMemory));
                pc += 4;
                HYP_ASSERT_SUCCESS(hv_vcpu_set_reg(vcpu, HV_REG_PC, pc));
                UInt64 ttbr;
                HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_TTBR0_EL1, &ttbr));
                printf("TTBR0_EL1 0x%llx\n", ttbr);
            } else if (ec == EC_AA64_BKPT) {
                // Exception Class 0x3C is BRK in AArch64 state
                UInt64 reg;
                printf("VM made an BRK call!\n");
                printf("Reg dump:\n");
                HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(vcpu, HV_REG_PC, &reg));
                printf("PC: 0x%llx\n", reg);
                HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(vcpu, HV_REG_FP, &reg));
                printf("FP: 0x%llx\n", reg);
                HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(vcpu, HV_REG_LR, &reg));
                printf("LR: 0x%llx\n", reg);
                for (UInt32 reg = HV_REG_X0; reg <= HV_REG_FP; reg++) {
                    UInt64 s;
                    HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(vcpu, (hv_reg_t)reg, &s));
                    printf("X%d: 0x%llx\n", reg, s);
                }
                break;
            } else {
                UInt64 pc, sp, fp, lr;
                UInt64 x[30];
                HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(vcpu, HV_REG_PC, &pc));
                HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(vcpu, HV_REG_FP, &fp));
                HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(vcpu, HV_REG_LR, &lr));
                for (int i = 0; i < 30; i++) {
                    HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(vcpu, (hv_reg_t)(HV_REG_X0 + i), &x[i]));
                }
                fprintf(stderr,
                        "Unexpected VM exception: 0x%llx, EC 0x%x, VirtAddr 0x%llx, IPA 0x%llx "
                        "Reason 0x%x\nPC 0x%llx\nFP 0x%llx\nLR 0x%llx\nX0 0x%llx\nX1 0x%llx\nX2 "
                        "0x%llx\nX3 0x%llx\nX4 0x%llx\nX5 0x%llx\nX6 0x%llx\nX7 0x%llx\nX8 "
                        "0x%llx\nX9 0x%llx\nX10 0x%llx\nX11 0x%llx\nX12 0x%llx\nX13 0x%llx\nX14 "
                        "0x%llx\nX15 0x%llx\nX16 0x%llx\nX17 0x%llx\nX18 0x%llx\nX19 0x%llx\nX20 "
                        "0x%llx\nX21 0x%llx\nX22 0x%llx\nX23 0x%llx\nX24 0x%llx\nX25 0x%llx\nX26 "
                        "0x%llx\nX27 0x%llx\nX28 0x%llx\nX29 0x%llx\n",
                        syndrome, ec, vcpu_exit->exception.virtual_address,
                        vcpu_exit->exception.physical_address, vcpu_exit->reason, pc, fp, lr, x[0],
                        x[1], x[2], x[3], x[4], x[5], x[6], x[7], x[8], x[9], x[10], x[11], x[12],
                        x[13], x[14], x[15], x[16], x[17], x[18], x[19], x[20], x[21], x[22], x[23],
                        x[24], x[25], x[26], x[27], x[28], x[29]);
                UInt64 ttbr;
                HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_TTBR0_EL1, &ttbr));
                printf("TTBR0_EL1 0x%llx\n", ttbr);
                break;
            }
        } else {
            fprintf(stderr, "Unexpected VM exit reason: %d\n", vcpu_exit->reason);
            break;
        }
    }
    Destroy();
}

void Hypervisor::Destroy() {
    // Tear down the VM
    hv_vcpu_destroy(vcpu);
    hv_vm_destroy();
    // Free memory
    free(resetTrampolineMemory);
    free(mainMemory);
}

} // namespace vm
} // namespace darwin

#endif
