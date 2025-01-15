#ifdef __arm64__
#ifndef __VIRT_H_
#define __VIRT_H_

#include "bitops.h"

typedef struct HvfArm64State HvfArm64State;

/*
 * Round number down to multiple. Requires that d be a power of 2 (see
 * QEMU_ALIGN_UP for a safer but slower version on arbitrary
 * numbers); works even if d is a smaller type than n.
 */
#ifndef ROUND_DOWN
#define ROUND_DOWN(n, d) ((n) & -(0 ? (n) : (d)))
#endif

/*
 * Round number up to multiple. Requires that d be a power of 2 (see
 * QEMU_ALIGN_UP for a safer but slower version on arbitrary
 * numbers); works even if d is a smaller type than n.
 */

#define ROUND_UP(n, d) ROUND_DOWN((n) + (d)-1, (d))

#define DIV_ROUND_UP(n, d) (((n) + (d)-1) / (d))

typedef int64_t target_long;
typedef uint64_t target_ulong;

/* For M profile, some registers are banked secure vs non-secure;
 * these are represented as a 2-element array where the first element
 * is the non-secure copy and the second is the secure copy.
 * When the CPU does not have implement the security extension then
 * only the first element is used.
 * This means that the copy for the current security state can be
 * accessed via env->registerfield[env->v7m.secure] (whether the security
 * extension is implemented or not).
 */
enum {
    M_REG_NS = 0,
    M_REG_S = 1,
    M_REG_NUM_BANKS = 2,
};

/* ARM-specific interrupt pending bits.  */
#define CPU_INTERRUPT_FIQ CPU_INTERRUPT_TGT_EXT_1
#define CPU_INTERRUPT_VIRQ CPU_INTERRUPT_TGT_EXT_2
#define CPU_INTERRUPT_VFIQ CPU_INTERRUPT_TGT_EXT_3
#define CPU_INTERRUPT_VSERR CPU_INTERRUPT_TGT_INT_0

/* CPU state for each instance of a generic timer (in cp15 c14) */
typedef struct ARMGenericTimer {
    uint64_t cval; /* Timer CompareValue register */
    uint64_t ctl;  /* Timer Control register */
} ARMGenericTimer;

#define GTIMER_PHYS 0
#define GTIMER_VIRT 1
#define GTIMER_HYP 2
#define GTIMER_SEC 3
#define GTIMER_HYPVIRT 4
#define NUM_GTIMERS 5

#define ARM_MAX_VQ 16

typedef struct ARMVectorReg {
    uint64_t d[2 * ARM_MAX_VQ] __attribute__((aligned(16)));
    ;
} ARMVectorReg;

/* In AArch32 mode, predicate registers do not exist at all.  */
typedef struct ARMPredicateReg {
    uint64_t p[DIV_ROUND_UP(2 * ARM_MAX_VQ, 8)] __attribute__((aligned(16)));
} ARMPredicateReg;

/* In AArch32 mode, PAC keys do not exist at all.  */
typedef struct ARMPACKey {
    uint64_t lo, hi;
} ARMPACKey;

/* See the commentary above the TBFLAG field definitions.  */
typedef struct CPUARMTBFlags {
    uint32_t flags;
    target_ulong flags2;
} CPUARMTBFlags;

#define SYSREG_OP0_SHIFT 20
#define SYSREG_OP0_MASK 0x3
#define SYSREG_OP0(sysreg) ((sysreg >> SYSREG_OP0_SHIFT) & SYSREG_OP0_MASK)
#define SYSREG_OP1_SHIFT 14
#define SYSREG_OP1_MASK 0x7
#define SYSREG_OP1(sysreg) ((sysreg >> SYSREG_OP1_SHIFT) & SYSREG_OP1_MASK)
#define SYSREG_CRN_SHIFT 10
#define SYSREG_CRN_MASK 0xf
#define SYSREG_CRN(sysreg) ((sysreg >> SYSREG_CRN_SHIFT) & SYSREG_CRN_MASK)
#define SYSREG_CRM_SHIFT 1
#define SYSREG_CRM_MASK 0xf
#define SYSREG_CRM(sysreg) ((sysreg >> SYSREG_CRM_SHIFT) & SYSREG_CRM_MASK)
#define SYSREG_OP2_SHIFT 17
#define SYSREG_OP2_MASK 0x7
#define SYSREG_OP2(sysreg) ((sysreg >> SYSREG_OP2_SHIFT) & SYSREG_OP2_MASK)

#define SYSREG(op0, op1, crn, crm, op2)                                                            \
    ((op0 << SYSREG_OP0_SHIFT) | (op1 << SYSREG_OP1_SHIFT) | (crn << SYSREG_CRN_SHIFT) |           \
     (crm << SYSREG_CRM_SHIFT) | (op2 << SYSREG_OP2_SHIFT))

#define SYSREG_MASK                                                                                \
    SYSREG(SYSREG_OP0_MASK, SYSREG_OP1_MASK, SYSREG_CRN_MASK, SYSREG_CRM_MASK, SYSREG_OP2_MASK)
#define SYSREG_OSLAR_EL1 SYSREG(2, 0, 1, 0, 4)
#define SYSREG_OSLSR_EL1 SYSREG(2, 0, 1, 1, 4)
#define SYSREG_OSDLR_EL1 SYSREG(2, 0, 1, 3, 4)
#define SYSREG_CNTPCT_EL0 SYSREG(3, 3, 14, 0, 1)
#define SYSREG_PMCR_EL0 SYSREG(3, 3, 9, 12, 0)
#define SYSREG_PMUSERENR_EL0 SYSREG(3, 3, 9, 14, 0)
#define SYSREG_PMCNTENSET_EL0 SYSREG(3, 3, 9, 12, 1)
#define SYSREG_PMCNTENCLR_EL0 SYSREG(3, 3, 9, 12, 2)
#define SYSREG_PMINTENCLR_EL1 SYSREG(3, 0, 9, 14, 2)
#define SYSREG_PMOVSCLR_EL0 SYSREG(3, 3, 9, 12, 3)
#define SYSREG_PMSWINC_EL0 SYSREG(3, 3, 9, 12, 4)
#define SYSREG_PMSELR_EL0 SYSREG(3, 3, 9, 12, 5)
#define SYSREG_PMCEID0_EL0 SYSREG(3, 3, 9, 12, 6)
#define SYSREG_PMCEID1_EL0 SYSREG(3, 3, 9, 12, 7)
#define SYSREG_PMCCNTR_EL0 SYSREG(3, 3, 9, 13, 0)
#define SYSREG_PMCCFILTR_EL0 SYSREG(3, 3, 14, 15, 7)

#define SYSREG_ICC_AP0R0_EL1 SYSREG(3, 0, 12, 8, 4)
#define SYSREG_ICC_AP0R1_EL1 SYSREG(3, 0, 12, 8, 5)
#define SYSREG_ICC_AP0R2_EL1 SYSREG(3, 0, 12, 8, 6)
#define SYSREG_ICC_AP0R3_EL1 SYSREG(3, 0, 12, 8, 7)
#define SYSREG_ICC_AP1R0_EL1 SYSREG(3, 0, 12, 9, 0)
#define SYSREG_ICC_AP1R1_EL1 SYSREG(3, 0, 12, 9, 1)
#define SYSREG_ICC_AP1R2_EL1 SYSREG(3, 0, 12, 9, 2)
#define SYSREG_ICC_AP1R3_EL1 SYSREG(3, 0, 12, 9, 3)
#define SYSREG_ICC_ASGI1R_EL1 SYSREG(3, 0, 12, 11, 6)
#define SYSREG_ICC_BPR0_EL1 SYSREG(3, 0, 12, 8, 3)
#define SYSREG_ICC_BPR1_EL1 SYSREG(3, 0, 12, 12, 3)
#define SYSREG_ICC_CTLR_EL1 SYSREG(3, 0, 12, 12, 4)
#define SYSREG_ICC_DIR_EL1 SYSREG(3, 0, 12, 11, 1)
#define SYSREG_ICC_EOIR0_EL1 SYSREG(3, 0, 12, 8, 1)
#define SYSREG_ICC_EOIR1_EL1 SYSREG(3, 0, 12, 12, 1)
#define SYSREG_ICC_HPPIR0_EL1 SYSREG(3, 0, 12, 8, 2)
#define SYSREG_ICC_HPPIR1_EL1 SYSREG(3, 0, 12, 12, 2)
#define SYSREG_ICC_IAR0_EL1 SYSREG(3, 0, 12, 8, 0)
#define SYSREG_ICC_IAR1_EL1 SYSREG(3, 0, 12, 12, 0)
#define SYSREG_ICC_IGRPEN0_EL1 SYSREG(3, 0, 12, 12, 6)
#define SYSREG_ICC_IGRPEN1_EL1 SYSREG(3, 0, 12, 12, 7)
#define SYSREG_ICC_PMR_EL1 SYSREG(3, 0, 4, 6, 0)
#define SYSREG_ICC_RPR_EL1 SYSREG(3, 0, 12, 11, 3)
#define SYSREG_ICC_SGI0R_EL1 SYSREG(3, 0, 12, 11, 7)
#define SYSREG_ICC_SGI1R_EL1 SYSREG(3, 0, 12, 11, 5)
#define SYSREG_ICC_SRE_EL1 SYSREG(3, 0, 12, 12, 5)

#define SYSREG_MDSCR_EL1 SYSREG(2, 0, 0, 2, 2)
#define SYSREG_DBGBVR0_EL1 SYSREG(2, 0, 0, 0, 4)
#define SYSREG_DBGBCR0_EL1 SYSREG(2, 0, 0, 0, 5)
#define SYSREG_DBGWVR0_EL1 SYSREG(2, 0, 0, 0, 6)
#define SYSREG_DBGWCR0_EL1 SYSREG(2, 0, 0, 0, 7)
#define SYSREG_DBGBVR1_EL1 SYSREG(2, 0, 0, 1, 4)
#define SYSREG_DBGBCR1_EL1 SYSREG(2, 0, 0, 1, 5)
#define SYSREG_DBGWVR1_EL1 SYSREG(2, 0, 0, 1, 6)
#define SYSREG_DBGWCR1_EL1 SYSREG(2, 0, 0, 1, 7)
#define SYSREG_DBGBVR2_EL1 SYSREG(2, 0, 0, 2, 4)
#define SYSREG_DBGBCR2_EL1 SYSREG(2, 0, 0, 2, 5)
#define SYSREG_DBGWVR2_EL1 SYSREG(2, 0, 0, 2, 6)
#define SYSREG_DBGWCR2_EL1 SYSREG(2, 0, 0, 2, 7)
#define SYSREG_DBGBVR3_EL1 SYSREG(2, 0, 0, 3, 4)
#define SYSREG_DBGBCR3_EL1 SYSREG(2, 0, 0, 3, 5)
#define SYSREG_DBGWVR3_EL1 SYSREG(2, 0, 0, 3, 6)
#define SYSREG_DBGWCR3_EL1 SYSREG(2, 0, 0, 3, 7)
#define SYSREG_DBGBVR4_EL1 SYSREG(2, 0, 0, 4, 4)
#define SYSREG_DBGBCR4_EL1 SYSREG(2, 0, 0, 4, 5)
#define SYSREG_DBGWVR4_EL1 SYSREG(2, 0, 0, 4, 6)
#define SYSREG_DBGWCR4_EL1 SYSREG(2, 0, 0, 4, 7)
#define SYSREG_DBGBVR5_EL1 SYSREG(2, 0, 0, 5, 4)
#define SYSREG_DBGBCR5_EL1 SYSREG(2, 0, 0, 5, 5)
#define SYSREG_DBGWVR5_EL1 SYSREG(2, 0, 0, 5, 6)
#define SYSREG_DBGWCR5_EL1 SYSREG(2, 0, 0, 5, 7)
#define SYSREG_DBGBVR6_EL1 SYSREG(2, 0, 0, 6, 4)
#define SYSREG_DBGBCR6_EL1 SYSREG(2, 0, 0, 6, 5)
#define SYSREG_DBGWVR6_EL1 SYSREG(2, 0, 0, 6, 6)
#define SYSREG_DBGWCR6_EL1 SYSREG(2, 0, 0, 6, 7)
#define SYSREG_DBGBVR7_EL1 SYSREG(2, 0, 0, 7, 4)
#define SYSREG_DBGBCR7_EL1 SYSREG(2, 0, 0, 7, 5)
#define SYSREG_DBGWVR7_EL1 SYSREG(2, 0, 0, 7, 6)
#define SYSREG_DBGWCR7_EL1 SYSREG(2, 0, 0, 7, 7)
#define SYSREG_DBGBVR8_EL1 SYSREG(2, 0, 0, 8, 4)
#define SYSREG_DBGBCR8_EL1 SYSREG(2, 0, 0, 8, 5)
#define SYSREG_DBGWVR8_EL1 SYSREG(2, 0, 0, 8, 6)
#define SYSREG_DBGWCR8_EL1 SYSREG(2, 0, 0, 8, 7)
#define SYSREG_DBGBVR9_EL1 SYSREG(2, 0, 0, 9, 4)
#define SYSREG_DBGBCR9_EL1 SYSREG(2, 0, 0, 9, 5)
#define SYSREG_DBGWVR9_EL1 SYSREG(2, 0, 0, 9, 6)
#define SYSREG_DBGWCR9_EL1 SYSREG(2, 0, 0, 9, 7)
#define SYSREG_DBGBVR10_EL1 SYSREG(2, 0, 0, 10, 4)
#define SYSREG_DBGBCR10_EL1 SYSREG(2, 0, 0, 10, 5)
#define SYSREG_DBGWVR10_EL1 SYSREG(2, 0, 0, 10, 6)
#define SYSREG_DBGWCR10_EL1 SYSREG(2, 0, 0, 10, 7)
#define SYSREG_DBGBVR11_EL1 SYSREG(2, 0, 0, 11, 4)
#define SYSREG_DBGBCR11_EL1 SYSREG(2, 0, 0, 11, 5)
#define SYSREG_DBGWVR11_EL1 SYSREG(2, 0, 0, 11, 6)
#define SYSREG_DBGWCR11_EL1 SYSREG(2, 0, 0, 11, 7)
#define SYSREG_DBGBVR12_EL1 SYSREG(2, 0, 0, 12, 4)
#define SYSREG_DBGBCR12_EL1 SYSREG(2, 0, 0, 12, 5)
#define SYSREG_DBGWVR12_EL1 SYSREG(2, 0, 0, 12, 6)
#define SYSREG_DBGWCR12_EL1 SYSREG(2, 0, 0, 12, 7)
#define SYSREG_DBGBVR13_EL1 SYSREG(2, 0, 0, 13, 4)
#define SYSREG_DBGBCR13_EL1 SYSREG(2, 0, 0, 13, 5)
#define SYSREG_DBGWVR13_EL1 SYSREG(2, 0, 0, 13, 6)
#define SYSREG_DBGWCR13_EL1 SYSREG(2, 0, 0, 13, 7)
#define SYSREG_DBGBVR14_EL1 SYSREG(2, 0, 0, 14, 4)
#define SYSREG_DBGBCR14_EL1 SYSREG(2, 0, 0, 14, 5)
#define SYSREG_DBGWVR14_EL1 SYSREG(2, 0, 0, 14, 6)
#define SYSREG_DBGWCR14_EL1 SYSREG(2, 0, 0, 14, 7)
#define SYSREG_DBGBVR15_EL1 SYSREG(2, 0, 0, 15, 4)
#define SYSREG_DBGBCR15_EL1 SYSREG(2, 0, 0, 15, 5)
#define SYSREG_DBGWVR15_EL1 SYSREG(2, 0, 0, 15, 6)
#define SYSREG_DBGWCR15_EL1 SYSREG(2, 0, 0, 15, 7)

#define WFX_IS_WFE (1 << 0)

#define TMR_CTL_ENABLE (1 << 0)
#define TMR_CTL_IMASK (1 << 1)
#define TMR_CTL_ISTATUS (1 << 2)

/* Definitions for the PMU registers */
#define PMCRN_MASK 0xf800
#define PMCRN_SHIFT 11
#define PMCRLC 0x40
#define PMCRDP 0x20
#define PMCRX 0x10
#define PMCRD 0x8
#define PMCRC 0x4
#define PMCRP 0x2
#define PMCRE 0x1
/*
 * Mask of PMCR bits writable by guest (not including WO bits like C, P,
 * which can be written as 1 to trigger behaviour but which stay RAZ).
 */
#define PMCR_WRITABLE_MASK (PMCRLC | PMCRDP | PMCRX | PMCRD | PMCRE)

#define PMXEVTYPER_P 0x80000000
#define PMXEVTYPER_U 0x40000000
#define PMXEVTYPER_NSK 0x20000000
#define PMXEVTYPER_NSU 0x10000000
#define PMXEVTYPER_NSH 0x08000000
#define PMXEVTYPER_M 0x04000000
#define PMXEVTYPER_MT 0x02000000
#define PMXEVTYPER_EVTCOUNT 0x0000ffff
#define PMXEVTYPER_MASK                                                                            \
    (PMXEVTYPER_P | PMXEVTYPER_U | PMXEVTYPER_NSK | PMXEVTYPER_NSU | PMXEVTYPER_NSH |              \
     PMXEVTYPER_M | PMXEVTYPER_MT | PMXEVTYPER_EVTCOUNT)

#define PMCCFILTR 0xf8000000
#define PMCCFILTR_M PMXEVTYPER_M
#define PMCCFILTR_EL0 (PMCCFILTR | PMCCFILTR_M)

static inline uint32_t pmu_num_counters(HvfArm64State* env) {
    return (0x410b3000 & PMCRN_MASK) >> PMCRN_SHIFT;
}

/* Bits allowed to be set/cleared for PMCNTEN* and PMINTEN* */
static inline uint64_t pmu_counter_mask(HvfArm64State* env) {
    return (1 << 31) | ((1 << pmu_num_counters(env)) - 1);
}

/*
 * Software neural-network floating-point types.
 */
typedef uint16_t bfloat16;

/*
 * Software IEC/IEEE floating-point underflow tininess-detection mode.
 */

#define float_tininess_after_rounding false
#define float_tininess_before_rounding true

/*
 *Software IEC/IEEE floating-point rounding mode.
 */

typedef enum __attribute__((__packed__)) {
    float_round_nearest_even = 0,
    float_round_down = 1,
    float_round_up = 2,
    float_round_to_zero = 3,
    float_round_ties_away = 4,
    /* Not an IEEE rounding mode: round to closest odd, overflow to max */
    float_round_to_odd = 5,
    /* Not an IEEE rounding mode: round to closest odd, overflow to inf */
    float_round_to_odd_inf = 6,
} FloatRoundMode;

enum {
    float_flag_invalid = 0x0001,
    float_flag_divbyzero = 0x0002,
    float_flag_overflow = 0x0004,
    float_flag_underflow = 0x0008,
    float_flag_inexact = 0x0010,
    float_flag_input_denormal = 0x0020,
    float_flag_output_denormal = 0x0040,
    float_flag_invalid_isi = 0x0080,  /* inf - inf */
    float_flag_invalid_imz = 0x0100,  /* inf * 0 */
    float_flag_invalid_idi = 0x0200,  /* inf / inf */
    float_flag_invalid_zdz = 0x0400,  /* 0 / 0 */
    float_flag_invalid_sqrt = 0x0800, /* sqrt(-x) */
    float_flag_invalid_cvti = 0x1000, /* non-nan to integer */
    float_flag_invalid_snan = 0x2000, /* any operand was snan */
};

/*
 * Rounding precision for floatx80.
 */
typedef enum __attribute__((__packed__)) {
    floatx80_precision_x,
    floatx80_precision_d,
    floatx80_precision_s,
} FloatX80RoundPrec;

/*
 * Floating Point Status. Individual architectures may maintain
 * several versions of float_status for different functions. The
 * correct status for the operation is then passed by reference to
 * most of the softfloat functions.
 */

typedef struct float_status {
    uint16_t float_exception_flags;
    FloatRoundMode float_rounding_mode;
    FloatX80RoundPrec floatx80_rounding_precision;
    bool tininess_before_rounding;
    /* should denormalised results go to zero and set the inexact flag? */
    bool flush_to_zero;
    /* should denormalised inputs go to zero and set the input_denormal flag? */
    bool flush_inputs_to_zero;
    bool default_nan_mode;
    /*
     * The flags below are not used on all specializations and may
     * constant fold away (see snan_bit_is_one()/no_signalling_nans() in
     * softfloat-specialize.inc.c)
     */
    bool snan_bit_is_one;
    bool use_first_nan;
    bool no_signaling_nans;
} float_status;

typedef struct HvfArm64State {
    /* Regs for current mode.  */
    uint32_t regs[16];

    /* 32/64 switch only happens when taking and returning from
     * exceptions so the overlap semantics are taken care of then
     * instead of having a complicated union.
     */
    /* Regs for A64 mode.  */
    uint64_t xregs[32];
    uint64_t pc;
    /* PSTATE isn't an architectural register for ARMv8. However, it is
     * convenient for us to assemble the underlying state into a 32 bit format
     * identical to the architectural format used for the SPSR. (This is also
     * what the Linux kernel's 'pstate' field in signal handlers and KVM's
     * 'pstate' register are.) Of the PSTATE bits:
     *  NZCV are kept in the split out env->CF/VF/NF/ZF, (which have the same
     *    semantics as for AArch32, as described in the comments on each field)
     *  nRW (also known as M[4]) is kept, inverted, in env->aarch64
     *  DAIF (exception masks) are kept in env->daif
     *  BTYPE is kept in env->btype
     *  SM and ZA are kept in env->svcr
     *  all other bits are stored in their correct places in env->pstate
     */
    uint32_t pstate;
    bool aarch64; /* True if CPU is in aarch64 state; inverse of PSTATE.nRW */
    bool thumb;   /* True if CPU is in thumb mode; cpsr[5] */

    /* Cached TBFLAGS state.  See below for which bits are included.  */
    CPUARMTBFlags hflags;

    /* Frequently accessed CPSR bits are stored separately for efficiency.
       This contains all the other bits.  Use cpsr_{read,write} to access
       the whole CPSR.  */
    uint32_t uncached_cpsr;
    uint32_t spsr;

    /* Banked registers.  */
    uint64_t banked_spsr[8];
    uint32_t banked_r13[8];
    uint32_t banked_r14[8];

    /* These hold r8-r12.  */
    uint32_t usr_regs[5];
    uint32_t fiq_regs[5];

    /* cpsr flag cache for faster execution */
    uint32_t CF;            /* 0 or 1 */
    uint32_t VF;            /* V is the bit 31. All other bits are undefined */
    uint32_t NF;            /* N is bit 31. All other bits are undefined.  */
    uint32_t ZF;            /* Z set if zero.  */
    uint32_t QF;            /* 0 or 1 */
    uint32_t GE;            /* cpsr[19:16] */
    uint32_t condexec_bits; /* IT bits.  cpsr[15:10,26:25].  */
    uint32_t btype;         /* BTI branch type.  spsr[11:10].  */
    uint64_t daif;          /* exception masks, in the bits they are in PSTATE */
    uint64_t svcr;          /* PSTATE.{SM,ZA} in the bits they are in SVCR */

    uint64_t elr_el[4]; /* AArch64 exception link regs  */
    uint64_t sp_el[4];  /* AArch64 banked stack pointers */

    /* System control coprocessor (cp15) */
    struct {
        uint32_t c0_cpuid;
        union { /* Cache size selection */
            struct {
                uint64_t _unused_csselr0;
                uint64_t csselr_ns;
                uint64_t _unused_csselr1;
                uint64_t csselr_s;
            };
            uint64_t csselr_el[4];
        };
        union { /* System control register. */
            struct {
                uint64_t _unused_sctlr;
                uint64_t sctlr_ns;
                uint64_t hsctlr;
                uint64_t sctlr_s;
            };
            uint64_t sctlr_el[4];
        };
        uint64_t cpacr_el1;      /* Architectural feature access control register */
        uint64_t cptr_el[4];     /* ARMv8 feature trap registers */
        uint32_t c1_xscaleauxcr; /* XScale auxiliary control register.  */
        uint64_t sder;           /* Secure debug enable register. */
        uint32_t nsacr;          /* Non-secure access control register. */
        union {                  /* MMU translation table base 0. */
            struct {
                uint64_t _unused_ttbr0_0;
                uint64_t ttbr0_ns;
                uint64_t _unused_ttbr0_1;
                uint64_t ttbr0_s;
            };
            uint64_t ttbr0_el[4];
        };
        union { /* MMU translation table base 1. */
            struct {
                uint64_t _unused_ttbr1_0;
                uint64_t ttbr1_ns;
                uint64_t _unused_ttbr1_1;
                uint64_t ttbr1_s;
            };
            uint64_t ttbr1_el[4];
        };
        uint64_t vttbr_el2;  /* Virtualization Translation Table Base.  */
        uint64_t vsttbr_el2; /* Secure Virtualization Translation Table. */
        /* MMU translation table base control. */
        uint64_t tcr_el[4];
        uint64_t vtcr_el2;  /* Virtualization Translation Control.  */
        uint64_t vstcr_el2; /* Secure Virtualization Translation Control. */
        uint32_t c2_data;   /* MPU data cacheable bits.  */
        uint32_t c2_insn;   /* MPU instruction cacheable bits.  */
        union {             /* MMU domain access control register
                             * MPU write buffer control.
                             */
            struct {
                uint64_t dacr_ns;
                uint64_t dacr_s;
            };
            struct {
                uint64_t dacr32_el2;
            };
        };
        uint32_t pmsav5_data_ap; /* PMSAv5 MPU data access permissions */
        uint32_t pmsav5_insn_ap; /* PMSAv5 MPU insn access permissions */
        uint64_t hcr_el2;        /* Hypervisor configuration register */
        uint64_t hcrx_el2;       /* Extended Hypervisor configuration register */
        uint64_t scr_el3;        /* Secure configuration register.  */
        union {                  /* Fault status registers.  */
            struct {
                uint64_t ifsr_ns;
                uint64_t ifsr_s;
            };
            struct {
                uint64_t ifsr32_el2;
            };
        };
        union {
            struct {
                uint64_t _unused_dfsr;
                uint64_t dfsr_ns;
                uint64_t hsr;
                uint64_t dfsr_s;
            };
            uint64_t esr_el[4];
        };
        uint32_t c6_region[8]; /* MPU base/size registers.  */
        union {                /* Fault address registers. */
            struct {
                uint64_t _unused_far0;

                uint32_t dfar_ns;
                uint32_t ifar_ns;
                uint32_t dfar_s;
                uint32_t ifar_s;

                uint64_t _unused_far3;
            };
            uint64_t far_el[4];
        };
        uint64_t hpfar_el2;
        uint64_t hstr_el2;
        union { /* Translation result. */
            struct {
                uint64_t _unused_par_0;
                uint64_t par_ns;
                uint64_t _unused_par_1;
                uint64_t par_s;
            };
            uint64_t par_el[4];
        };

        uint32_t c9_insn; /* Cache lockdown registers.  */
        uint32_t c9_data;
        uint64_t c9_pmcr;      /* performance monitor control register */
        uint64_t c9_pmcnten;   /* perf monitor counter enables */
        uint64_t c9_pmovsr;    /* perf monitor overflow status */
        uint64_t c9_pmuserenr; /* perf monitor user enable */
        uint64_t c9_pmselr;    /* perf monitor counter selection register */
        uint64_t c9_pminten;   /* perf monitor interrupt enables */
        union {                /* Memory attribute redirection */
            struct {
                uint64_t _unused_mair_0;
                uint32_t mair0_ns;
                uint32_t mair1_ns;
                uint64_t _unused_mair_1;
                uint32_t mair0_s;
                uint32_t mair1_s;
            };
            uint64_t mair_el[4];
        };
        union { /* vector base address register */
            struct {
                uint64_t _unused_vbar;
                uint64_t vbar_ns;
                uint64_t hvbar;
                uint64_t vbar_s;
            };
            uint64_t vbar_el[4];
        };
        uint32_t mvbar; /* (monitor) vector base address register */
        uint64_t rvbar; /* rvbar sampled from rvbar property at reset */
        struct {        /* FCSE PID. */
            uint32_t fcseidr_ns;
            uint32_t fcseidr_s;
        };
        union { /* Context ID. */
            struct {
                uint64_t _unused_contextidr_0;
                uint64_t contextidr_ns;
                uint64_t _unused_contextidr_1;
                uint64_t contextidr_s;
            };
            uint64_t contextidr_el[4];
        };
        union { /* User RW Thread register. */
            struct {
                uint64_t tpidrurw_ns;
                uint64_t tpidrprw_ns;
                uint64_t htpidr;
                uint64_t _tpidr_el3;
            };
            uint64_t tpidr_el[4];
        };
        uint64_t tpidr2_el0;
        /* The secure banks of these registers don't map anywhere */
        uint64_t tpidrurw_s;
        uint64_t tpidrprw_s;
        uint64_t tpidruro_s;

        union { /* User RO Thread register. */
            uint64_t tpidruro_ns;
            uint64_t tpidrro_el[1];
        };
        uint64_t c14_cntfrq;  /* Counter Frequency register */
        uint64_t c14_cntkctl; /* Timer Control register */
        uint32_t cnthctl_el2; /* Counter/Timer Hyp Control register */
        uint64_t cntvoff_el2; /* Counter Virtual Offset register */
        ARMGenericTimer c14_timer[NUM_GTIMERS];
        uint32_t c15_cpar;                /* XScale Coprocessor Access Register */
        uint32_t c15_ticonfig;            /* TI925T configuration byte.  */
        uint32_t c15_i_max;               /* Maximum D-cache dirty line index.  */
        uint32_t c15_i_min;               /* Minimum D-cache dirty line index.  */
        uint32_t c15_threadid;            /* TI debugger thread-ID.  */
        uint32_t c15_config_base_address; /* SCU base address.  */
        uint32_t c15_diagnostic;          /* diagnostic register */
        uint32_t c15_power_diagnostic;
        uint32_t c15_power_control; /* power control */
        uint64_t dbgbvr[16];        /* breakpoint value registers */
        uint64_t dbgbcr[16];        /* breakpoint control registers */
        uint64_t dbgwvr[16];        /* watchpoint value registers */
        uint64_t dbgwcr[16];        /* watchpoint control registers */
        uint64_t mdscr_el1;
        uint64_t oslsr_el1; /* OS Lock Status */
        uint64_t osdlr_el1; /* OS DoubleLock status */
        uint64_t mdcr_el2;
        uint64_t mdcr_el3;
        /* Stores the architectural value of the counter *the last time it was
         * updated* by pmccntr_op_start. Accesses should always be surrounded
         * by pmccntr_op_start/pmccntr_op_finish to guarantee the latest
         * architecturally-correct value is being read/set.
         */
        uint64_t c15_ccnt;
        /* Stores the delta between the architectural value and the underlying
         * cycle count during normal operation. It is used to update c15_ccnt
         * to be the correct architectural value before accesses. During
         * accesses, c15_ccnt_delta contains the underlying count being used
         * for the access, after which it reverts to the delta value in
         * pmccntr_op_finish.
         */
        uint64_t c15_ccnt_delta;
        uint64_t c14_pmevcntr[31];
        uint64_t c14_pmevcntr_delta[31];
        uint64_t c14_pmevtyper[31];
        uint64_t pmccfiltr_el0; /* Performance Monitor Filter Register */
        uint64_t vpidr_el2;     /* Virtualization Processor ID Register */
        uint64_t vmpidr_el2;    /* Virtualization Multiprocessor ID Register */
        uint64_t tfsr_el[4];    /* tfsre0_el1 is index 0.  */
        uint64_t gcr_el1;
        uint64_t rgsr_el1;

        /* Minimal RAS registers */
        uint64_t disr_el1;
        uint64_t vdisr_el2;
        uint64_t vsesr_el2;

        /* Apple-specific registers */
        uint64_t vmsa_lock_el1;
        uint64_t apctl_el1;
        uint64_t apcfg_el1;
    } cp15;

    struct {
        uint64_t gxf_config_el[4];
        uint64_t gxf_enter_el[4];
        uint64_t gxf_status_el[4];
        uint64_t gxf_abort_el[4];
        uint64_t sp_gl[4];
        uint64_t tpidr_gl[4];
        uint64_t vbar_gl[4];
        uint64_t spsr_gl[4];
        uint64_t aspsr_gl[4];
        uint64_t esr_gl[4];
        uint64_t elr_gl[4];
        uint64_t far_gl[4];
    } gxf;

    struct {
        uint64_t sprr_el_br_el1[4][2];
        uint64_t sprr_config_el[4];
        uint64_t mprr_el_br_el1[4][2];
    } sprr;

    struct {
        /* M profile has up to 4 stack pointers:
         * a Main Stack Pointer and a Process Stack Pointer for each
         * of the Secure and Non-Secure states. (If the CPU doesn't support
         * the security extension then it has only two SPs.)
         * In QEMU we always store the currently active SP in regs[13],
         * and the non-active SP for the current security state in
         * v7m.other_sp. The stack pointers for the inactive security state
         * are stored in other_ss_msp and other_ss_psp.
         * switch_v7m_security_state() is responsible for rearranging them
         * when we change security state.
         */
        uint32_t other_sp;
        uint32_t other_ss_msp;
        uint32_t other_ss_psp;
        uint32_t vecbase[M_REG_NUM_BANKS];
        uint32_t basepri[M_REG_NUM_BANKS];
        uint32_t control[M_REG_NUM_BANKS];
        uint32_t ccr[M_REG_NUM_BANKS];      /* Configuration and Control */
        uint32_t cfsr[M_REG_NUM_BANKS];     /* Configurable Fault Status */
        uint32_t hfsr;                      /* HardFault Status */
        uint32_t dfsr;                      /* Debug Fault Status Register */
        uint32_t sfsr;                      /* Secure Fault Status Register */
        uint32_t mmfar[M_REG_NUM_BANKS];    /* MemManage Fault Address */
        uint32_t bfar;                      /* BusFault Address */
        uint32_t sfar;                      /* Secure Fault Address Register */
        unsigned mpu_ctrl[M_REG_NUM_BANKS]; /* MPU_CTRL */
        int exception;
        uint32_t primask[M_REG_NUM_BANKS];
        uint32_t faultmask[M_REG_NUM_BANKS];
        uint32_t aircr;  /* only holds r/w state if security extn implemented */
        uint32_t secure; /* Is CPU in Secure state? (not guest visible) */
        uint32_t csselr[M_REG_NUM_BANKS];
        uint32_t scr[M_REG_NUM_BANKS];
        uint32_t msplim[M_REG_NUM_BANKS];
        uint32_t psplim[M_REG_NUM_BANKS];
        uint32_t fpcar[M_REG_NUM_BANKS];
        uint32_t fpccr[M_REG_NUM_BANKS];
        uint32_t fpdscr[M_REG_NUM_BANKS];
        uint32_t cpacr[M_REG_NUM_BANKS];
        uint32_t nsacr;
        uint32_t ltpsize;
        uint32_t vpr;
    } v7m;

    /* Information associated with an exception about to be taken:
     * code which raises an exception must set cs->exception_index and
     * the relevant parts of this structure; the cpu_do_interrupt function
     * will then set the guest-visible registers as part of the exception
     * entry process.
     */
    struct {
        uint32_t syndrome;  /* AArch64 format syndrome register */
        uint32_t fsr;       /* AArch32 format fault status register info */
        uint64_t vaddress;  /* virtual addr associated with exception, if any */
        uint32_t target_el; /* EL the exception should be targeted for */
        /* If we implement EL2 we will also need to store information
         * about the intermediate physical address for stage 2 faults.
         */
    } exception;

    /* Information associated with an SError */
    struct {
        uint8_t pending;
        uint8_t has_esr;
        uint64_t esr;
    } serror;

    uint8_t ext_dabt_raised; /* Tracking/verifying injection of ext DABT */

    /* State of our input IRQ/FIQ/VIRQ/VFIQ lines */
    uint32_t irq_line_state;

    /* Thumb-2 EE state.  */
    uint32_t teecr;
    uint32_t teehbr;

    /* VFP coprocessor state.  */
    struct {
        ARMVectorReg zregs[32];

        /* Store FFR as pregs[16] to make it easier to treat as any other.  */
#define FFR_PRED_NUM 16
        ARMPredicateReg pregs[17];
        /* Scratch space for aa64 sve predicate temporary.  */
        ARMPredicateReg preg_tmp;

        /* We store these fpcsr fields separately for convenience.  */
        uint32_t qc[4] __attribute__((aligned(16)));
        int vec_len;
        int vec_stride;

        uint32_t xregs[16];

        /* Scratch space for aa32 neon expansion.  */
        uint32_t scratch[8];

        /* There are a number of distinct float control structures:
         *
         *  fp_status: is the "normal" fp status.
         *  fp_status_fp16: used for half-precision calculations
         *  standard_fp_status : the ARM "Standard FPSCR Value"
         *  standard_fp_status_fp16 : used for half-precision
         *       calculations with the ARM "Standard FPSCR Value"
         *
         * Half-precision operations are governed by a separate
         * flush-to-zero control bit in FPSCR:FZ16. We pass a separate
         * status structure to control this.
         *
         * The "Standard FPSCR", ie default-NaN, flush-to-zero,
         * round-to-nearest and is used by any operations (generally
         * Neon) which the architecture defines as controlled by the
         * standard FPSCR value rather than the FPSCR.
         *
         * The "standard FPSCR but for fp16 ops" is needed because
         * the "standard FPSCR" tracks the FPSCR.FZ16 bit rather than
         * using a fixed value for it.
         *
         * To avoid having to transfer exception bits around, we simply
         * say that the FPSCR cumulative exception flags are the logical
         * OR of the flags in the four fp statuses. This relies on the
         * only thing which needs to read the exception flags being
         * an explicit FPSCR read.
         */
        float_status fp_status;
        float_status fp_status_f16;
        float_status standard_fp_status;
        float_status standard_fp_status_f16;

        uint64_t zcr_el[4];  /* ZCR_EL[1-3] */
        uint64_t smcr_el[4]; /* SMCR_EL[1-3] */
    } vfp;
    uint64_t exclusive_addr;
    uint64_t exclusive_val;
    uint64_t exclusive_high;

    /* iwMMXt coprocessor state.  */
    struct {
        uint64_t regs[16];
        uint64_t val;

        uint32_t cregs[16];
    } iwmmxt;

    struct {
        ARMPACKey apia;
        ARMPACKey apib;
        ARMPACKey apda;
        ARMPACKey apdb;
        ARMPACKey apga;
        ARMPACKey kernel;
        ARMPACKey m;
    } keys;

    uint64_t scxtnum_el[4];

    /*
     * SME ZA storage -- 256 x 256 byte array, with bytes in host word order,
     * as we do with vfp.zregs[].  This corresponds to the architectural ZA
     * array, where ZA[N] is in the least-significant bytes of env->zarray[N].
     * When SVL is less than the architectural maximum, the accessible
     * storage is restricted, such that if the SVL is X bytes the guest can
     * see only the bottom X elements of zarray[], and only the least
     * significant X bytes of each element of the array. (In other words,
     * the observable part is always square.)
     *
     * The ZA storage can also be considered as a set of square tiles of
     * elements of different sizes. The mapping from tiles to the ZA array
     * is architecturally defined, such that for tiles of elements of esz
     * bytes, the Nth row (or "horizontal slice") of tile T is in
     * ZA[T + N * esz]. Note that this means that each tile is not contiguous
     * in the ZA storage, because its rows are striped through the ZA array.
     *
     * Because this is so large, keep this toward the end of the reset area,
     * to keep the offsets into the rest of the structure smaller.
     */
    ARMVectorReg zarray[ARM_MAX_VQ * 16];

    struct CPUBreakpoint* cpu_breakpoint[16];
    struct CPUWatchpoint* cpu_watchpoint[16];

    /* Fields up to this point are cleared by a CPU reset */
    struct {
    } end_reset_fields;

    /* Fields after this point are preserved across CPU reset. */

    /* Internal CPU feature flags.  */
    uint64_t features;

    /* PMSAv7 MPU */
    struct {
        uint32_t* drbar;
        uint32_t* drsr;
        uint32_t* dracr;
        uint32_t rnr[M_REG_NUM_BANKS];
    } pmsav7;

    /* PMSAv8 MPU */
    struct {
        /* The PMSAv8 implementation also shares some PMSAv7 config
         * and state:
         *  pmsav7.rnr (region number register)
         *  pmsav7_dregion (number of configured regions)
         */
        uint32_t* rbar[M_REG_NUM_BANKS];
        uint32_t* rlar[M_REG_NUM_BANKS];
        uint32_t mair0[M_REG_NUM_BANKS];
        uint32_t mair1[M_REG_NUM_BANKS];
    } pmsav8;

    /* v8M SAU */
    struct {
        uint32_t* rbar;
        uint32_t* rlar;
        uint32_t rnr;
        uint32_t ctrl;
    } sau;

    void* nvic;
    const struct arm_boot_info* boot_info;
    /* Store GICv3CPUState to access from this struct */
    void* gicv3state;

#ifdef TARGET_TAGGED_ADDRESSES
    /* Linux syscall tagged address support */
    bool tagged_addr_enable;
#endif
} HvfArm64State;

/* When looking up a coprocessor register we look for it
 * via an integer which encodes all of:
 *  coprocessor number
 *  Crn, Crm, opc1, opc2 fields
 *  32 or 64 bit register (ie is it accessed via MRC/MCR
 *    or via MRRC/MCRR?)
 *  non-secure/secure bank (AArch32 only)
 * We allow 4 bits for opc1 because MRRC/MCRR have a 4 bit field.
 * (In this case crn and opc2 should be zero.)
 * For AArch64, there is no 32/64 bit size distinction;
 * instead all registers have a 2 bit op0, 3 bit op1 and op2,
 * and 4 bit CRn and CRm. The encoding patterns are chosen
 * to be easy to convert to and from the KVM encodings, and also
 * so that the hashtable can contain both AArch32 and AArch64
 * registers (to allow for interprocessing where we might run
 * 32 bit code on a 64 bit core).
 */
/* This bit is private to our hashtable cpreg; in KVM register
 * IDs the AArch64/32 distinction is the KVM_REG_ARM/ARM64
 * in the upper bits of the 64 bit ID.
 */
#define CP_REG_AA64_SHIFT 28
#define CP_REG_AA64_MASK (1 << CP_REG_AA64_SHIFT)

/* To enable banking of coprocessor registers depending on ns-bit we
 * add a bit to distinguish between secure and non-secure cpregs in the
 * hashtable.
 */
#define CP_REG_NS_SHIFT 29
#define CP_REG_NS_MASK (1 << CP_REG_NS_SHIFT)

#define ENCODE_CP_REG(cp, is64, ns, crn, crm, opc1, opc2)                                          \
    ((ns) << CP_REG_NS_SHIFT | ((cp) << 16) | ((is64) << 15) | ((crn) << 11) | ((crm) << 7) |      \
     ((opc1) << 3) | (opc2))

#define ENCODE_AA64_CP_REG(cp, crn, crm, op0, op1, op2)                                            \
    (CP_REG_AA64_MASK | ((cp) << CP_REG_ARM_COPROC_SHIFT) |                                        \
     ((op0) << CP_REG_ARM64_SYSREG_OP0_SHIFT) | ((op1) << CP_REG_ARM64_SYSREG_OP1_SHIFT) |         \
     ((crn) << CP_REG_ARM64_SYSREG_CRN_SHIFT) | ((crm) << CP_REG_ARM64_SYSREG_CRM_SHIFT) |         \
     ((op2) << CP_REG_ARM64_SYSREG_OP2_SHIFT))

#define CP_REG_ARM64 0x6000000000000000ULL
#define CP_REG_ARM_COPROC_MASK 0x000000000FFF0000
#define CP_REG_ARM_COPROC_SHIFT 16
#define CP_REG_ARM64_SYSREG (0x0013 << CP_REG_ARM_COPROC_SHIFT)
#define CP_REG_ARM64_SYSREG_OP0_MASK 0x000000000000c000
#define CP_REG_ARM64_SYSREG_OP0_SHIFT 14
#define CP_REG_ARM64_SYSREG_OP1_MASK 0x0000000000003800
#define CP_REG_ARM64_SYSREG_OP1_SHIFT 11
#define CP_REG_ARM64_SYSREG_CRN_MASK 0x0000000000000780
#define CP_REG_ARM64_SYSREG_CRN_SHIFT 7
#define CP_REG_ARM64_SYSREG_CRM_MASK 0x0000000000000078
#define CP_REG_ARM64_SYSREG_CRM_SHIFT 3
#define CP_REG_ARM64_SYSREG_OP2_MASK 0x0000000000000007
#define CP_REG_ARM64_SYSREG_OP2_SHIFT 0

/* No kernel define but it's useful to QEMU */
#define CP_REG_ARM64_SYSREG_CP (CP_REG_ARM64_SYSREG >> CP_REG_ARM_COPROC_SHIFT)

#define HVF_SYSREG(crn, crm, op0, op1, op2)                                                        \
    ENCODE_AA64_CP_REG(CP_REG_ARM64_SYSREG_CP, crn, crm, op0, op1, op2)
#define PL1_WRITE_MASK 0x4

typedef struct HVFVTimer {
    /* Vtimer value during migration and paused state */
    uint64_t vtimer_val;
} HVFVTimer;

static HVFVTimer vtimer;

/* The instance init functions for implementation-specific subclasses
 * set these fields to specify the implementation-dependent values of
 * various constant registers and reset values of non-constant
 * registers.
 * Some of these might become QOM properties eventually.
 * Field names match the official register names as defined in the
 * ARMv7AR ARM Architecture Reference Manual. A reset_ prefix
 * is used for reset values of non-constant registers; no reset_
 * prefix means a constant register.
 * Some of these registers are split out into a substructure that
 * is shared with the translators to control the ISA.
 *
 * Note that if you add an ID register to the ARMISARegisters struct
 * you need to also update the 32-bit and 64-bit versions of the
 * kvm_arm_get_host_cpu_features() function to correctly populate the
 * field by reading the value from the KVM vCPU.
 */
struct ARMISARegisters {
    uint32_t id_isar0;
    uint32_t id_isar1;
    uint32_t id_isar2;
    uint32_t id_isar3;
    uint32_t id_isar4;
    uint32_t id_isar5;
    uint32_t id_isar6;
    uint32_t id_mmfr0;
    uint32_t id_mmfr1;
    uint32_t id_mmfr2;
    uint32_t id_mmfr3;
    uint32_t id_mmfr4;
    uint32_t id_pfr0;
    uint32_t id_pfr1;
    uint32_t id_pfr2;
    uint32_t mvfr0;
    uint32_t mvfr1;
    uint32_t mvfr2;
    uint32_t id_dfr0;
    uint32_t dbgdidr;
    uint32_t dbgdevid;
    uint32_t dbgdevid1;
    uint64_t id_aa64isar0;
    uint64_t id_aa64isar1;
    uint64_t id_aa64pfr0;
    uint64_t id_aa64pfr1;
    uint64_t id_aa64mmfr0;
    uint64_t id_aa64mmfr1;
    uint64_t id_aa64mmfr2;
    uint64_t id_aa64dfr0;
    uint64_t id_aa64dfr1;
    uint64_t id_aa64zfr0;
    uint64_t id_aa64smfr0;
    uint64_t reset_pmcr_el0;
};

typedef struct ARMHostCPUFeatures {
    ARMISARegisters isar;
    uint64_t features;
    uint64_t midr;
    uint32_t reset_sctlr;
    const char* dtb_compatible;
} ARMHostCPUFeatures;

static ARMHostCPUFeatures arm_host_cpu_features;

struct hvf_reg_match {
    int reg;
    uint64_t offset;
};

static const struct hvf_reg_match hvf_reg_match[] = {
    {HV_REG_X0, offsetof(HvfArm64State, xregs[0])},
    {HV_REG_X1, offsetof(HvfArm64State, xregs[1])},
    {HV_REG_X2, offsetof(HvfArm64State, xregs[2])},
    {HV_REG_X3, offsetof(HvfArm64State, xregs[3])},
    {HV_REG_X4, offsetof(HvfArm64State, xregs[4])},
    {HV_REG_X5, offsetof(HvfArm64State, xregs[5])},
    {HV_REG_X6, offsetof(HvfArm64State, xregs[6])},
    {HV_REG_X7, offsetof(HvfArm64State, xregs[7])},
    {HV_REG_X8, offsetof(HvfArm64State, xregs[8])},
    {HV_REG_X9, offsetof(HvfArm64State, xregs[9])},
    {HV_REG_X10, offsetof(HvfArm64State, xregs[10])},
    {HV_REG_X11, offsetof(HvfArm64State, xregs[11])},
    {HV_REG_X12, offsetof(HvfArm64State, xregs[12])},
    {HV_REG_X13, offsetof(HvfArm64State, xregs[13])},
    {HV_REG_X14, offsetof(HvfArm64State, xregs[14])},
    {HV_REG_X15, offsetof(HvfArm64State, xregs[15])},
    {HV_REG_X16, offsetof(HvfArm64State, xregs[16])},
    {HV_REG_X17, offsetof(HvfArm64State, xregs[17])},
    {HV_REG_X18, offsetof(HvfArm64State, xregs[18])},
    {HV_REG_X19, offsetof(HvfArm64State, xregs[19])},
    {HV_REG_X20, offsetof(HvfArm64State, xregs[20])},
    {HV_REG_X21, offsetof(HvfArm64State, xregs[21])},
    {HV_REG_X22, offsetof(HvfArm64State, xregs[22])},
    {HV_REG_X23, offsetof(HvfArm64State, xregs[23])},
    {HV_REG_X24, offsetof(HvfArm64State, xregs[24])},
    {HV_REG_X25, offsetof(HvfArm64State, xregs[25])},
    {HV_REG_X26, offsetof(HvfArm64State, xregs[26])},
    {HV_REG_X27, offsetof(HvfArm64State, xregs[27])},
    {HV_REG_X28, offsetof(HvfArm64State, xregs[28])},
    {HV_REG_X29, offsetof(HvfArm64State, xregs[29])},
    {HV_REG_X30, offsetof(HvfArm64State, xregs[30])},
    {HV_REG_PC, offsetof(HvfArm64State, pc)},
};

static const struct hvf_reg_match hvf_fpreg_match[] = {
    {HV_SIMD_FP_REG_Q0, offsetof(HvfArm64State, vfp.zregs[0])},
    {HV_SIMD_FP_REG_Q1, offsetof(HvfArm64State, vfp.zregs[1])},
    {HV_SIMD_FP_REG_Q2, offsetof(HvfArm64State, vfp.zregs[2])},
    {HV_SIMD_FP_REG_Q3, offsetof(HvfArm64State, vfp.zregs[3])},
    {HV_SIMD_FP_REG_Q4, offsetof(HvfArm64State, vfp.zregs[4])},
    {HV_SIMD_FP_REG_Q5, offsetof(HvfArm64State, vfp.zregs[5])},
    {HV_SIMD_FP_REG_Q6, offsetof(HvfArm64State, vfp.zregs[6])},
    {HV_SIMD_FP_REG_Q7, offsetof(HvfArm64State, vfp.zregs[7])},
    {HV_SIMD_FP_REG_Q8, offsetof(HvfArm64State, vfp.zregs[8])},
    {HV_SIMD_FP_REG_Q9, offsetof(HvfArm64State, vfp.zregs[9])},
    {HV_SIMD_FP_REG_Q10, offsetof(HvfArm64State, vfp.zregs[10])},
    {HV_SIMD_FP_REG_Q11, offsetof(HvfArm64State, vfp.zregs[11])},
    {HV_SIMD_FP_REG_Q12, offsetof(HvfArm64State, vfp.zregs[12])},
    {HV_SIMD_FP_REG_Q13, offsetof(HvfArm64State, vfp.zregs[13])},
    {HV_SIMD_FP_REG_Q14, offsetof(HvfArm64State, vfp.zregs[14])},
    {HV_SIMD_FP_REG_Q15, offsetof(HvfArm64State, vfp.zregs[15])},
    {HV_SIMD_FP_REG_Q16, offsetof(HvfArm64State, vfp.zregs[16])},
    {HV_SIMD_FP_REG_Q17, offsetof(HvfArm64State, vfp.zregs[17])},
    {HV_SIMD_FP_REG_Q18, offsetof(HvfArm64State, vfp.zregs[18])},
    {HV_SIMD_FP_REG_Q19, offsetof(HvfArm64State, vfp.zregs[19])},
    {HV_SIMD_FP_REG_Q20, offsetof(HvfArm64State, vfp.zregs[20])},
    {HV_SIMD_FP_REG_Q21, offsetof(HvfArm64State, vfp.zregs[21])},
    {HV_SIMD_FP_REG_Q22, offsetof(HvfArm64State, vfp.zregs[22])},
    {HV_SIMD_FP_REG_Q23, offsetof(HvfArm64State, vfp.zregs[23])},
    {HV_SIMD_FP_REG_Q24, offsetof(HvfArm64State, vfp.zregs[24])},
    {HV_SIMD_FP_REG_Q25, offsetof(HvfArm64State, vfp.zregs[25])},
    {HV_SIMD_FP_REG_Q26, offsetof(HvfArm64State, vfp.zregs[26])},
    {HV_SIMD_FP_REG_Q27, offsetof(HvfArm64State, vfp.zregs[27])},
    {HV_SIMD_FP_REG_Q28, offsetof(HvfArm64State, vfp.zregs[28])},
    {HV_SIMD_FP_REG_Q29, offsetof(HvfArm64State, vfp.zregs[29])},
    {HV_SIMD_FP_REG_Q30, offsetof(HvfArm64State, vfp.zregs[30])},
    {HV_SIMD_FP_REG_Q31, offsetof(HvfArm64State, vfp.zregs[31])},
};

struct hvf_sreg_match {
    int reg;
    uint32_t key;
    uint32_t cp_idx;
};

static struct hvf_sreg_match hvf_sreg_match[] = {
    {HV_SYS_REG_DBGBVR0_EL1, HVF_SYSREG(0, 0, 14, 0, 4)},
    {HV_SYS_REG_DBGBCR0_EL1, HVF_SYSREG(0, 0, 14, 0, 5)},
    {HV_SYS_REG_DBGWVR0_EL1, HVF_SYSREG(0, 0, 14, 0, 6)},
    {HV_SYS_REG_DBGWCR0_EL1, HVF_SYSREG(0, 0, 14, 0, 7)},

    {HV_SYS_REG_DBGBVR1_EL1, HVF_SYSREG(0, 1, 14, 0, 4)},
    {HV_SYS_REG_DBGBCR1_EL1, HVF_SYSREG(0, 1, 14, 0, 5)},
    {HV_SYS_REG_DBGWVR1_EL1, HVF_SYSREG(0, 1, 14, 0, 6)},
    {HV_SYS_REG_DBGWCR1_EL1, HVF_SYSREG(0, 1, 14, 0, 7)},

    {HV_SYS_REG_DBGBVR2_EL1, HVF_SYSREG(0, 2, 14, 0, 4)},
    {HV_SYS_REG_DBGBCR2_EL1, HVF_SYSREG(0, 2, 14, 0, 5)},
    {HV_SYS_REG_DBGWVR2_EL1, HVF_SYSREG(0, 2, 14, 0, 6)},
    {HV_SYS_REG_DBGWCR2_EL1, HVF_SYSREG(0, 2, 14, 0, 7)},

    {HV_SYS_REG_DBGBVR3_EL1, HVF_SYSREG(0, 3, 14, 0, 4)},
    {HV_SYS_REG_DBGBCR3_EL1, HVF_SYSREG(0, 3, 14, 0, 5)},
    {HV_SYS_REG_DBGWVR3_EL1, HVF_SYSREG(0, 3, 14, 0, 6)},
    {HV_SYS_REG_DBGWCR3_EL1, HVF_SYSREG(0, 3, 14, 0, 7)},

    {HV_SYS_REG_DBGBVR4_EL1, HVF_SYSREG(0, 4, 14, 0, 4)},
    {HV_SYS_REG_DBGBCR4_EL1, HVF_SYSREG(0, 4, 14, 0, 5)},
    {HV_SYS_REG_DBGWVR4_EL1, HVF_SYSREG(0, 4, 14, 0, 6)},
    {HV_SYS_REG_DBGWCR4_EL1, HVF_SYSREG(0, 4, 14, 0, 7)},

    {HV_SYS_REG_DBGBVR5_EL1, HVF_SYSREG(0, 5, 14, 0, 4)},
    {HV_SYS_REG_DBGBCR5_EL1, HVF_SYSREG(0, 5, 14, 0, 5)},
    {HV_SYS_REG_DBGWVR5_EL1, HVF_SYSREG(0, 5, 14, 0, 6)},
    {HV_SYS_REG_DBGWCR5_EL1, HVF_SYSREG(0, 5, 14, 0, 7)},

    {HV_SYS_REG_DBGBVR6_EL1, HVF_SYSREG(0, 6, 14, 0, 4)},
    {HV_SYS_REG_DBGBCR6_EL1, HVF_SYSREG(0, 6, 14, 0, 5)},
    {HV_SYS_REG_DBGWVR6_EL1, HVF_SYSREG(0, 6, 14, 0, 6)},
    {HV_SYS_REG_DBGWCR6_EL1, HVF_SYSREG(0, 6, 14, 0, 7)},

    {HV_SYS_REG_DBGBVR7_EL1, HVF_SYSREG(0, 7, 14, 0, 4)},
    {HV_SYS_REG_DBGBCR7_EL1, HVF_SYSREG(0, 7, 14, 0, 5)},
    {HV_SYS_REG_DBGWVR7_EL1, HVF_SYSREG(0, 7, 14, 0, 6)},
    {HV_SYS_REG_DBGWCR7_EL1, HVF_SYSREG(0, 7, 14, 0, 7)},

    {HV_SYS_REG_DBGBVR8_EL1, HVF_SYSREG(0, 8, 14, 0, 4)},
    {HV_SYS_REG_DBGBCR8_EL1, HVF_SYSREG(0, 8, 14, 0, 5)},
    {HV_SYS_REG_DBGWVR8_EL1, HVF_SYSREG(0, 8, 14, 0, 6)},
    {HV_SYS_REG_DBGWCR8_EL1, HVF_SYSREG(0, 8, 14, 0, 7)},

    {HV_SYS_REG_DBGBVR9_EL1, HVF_SYSREG(0, 9, 14, 0, 4)},
    {HV_SYS_REG_DBGBCR9_EL1, HVF_SYSREG(0, 9, 14, 0, 5)},
    {HV_SYS_REG_DBGWVR9_EL1, HVF_SYSREG(0, 9, 14, 0, 6)},
    {HV_SYS_REG_DBGWCR9_EL1, HVF_SYSREG(0, 9, 14, 0, 7)},

    {HV_SYS_REG_DBGBVR10_EL1, HVF_SYSREG(0, 10, 14, 0, 4)},
    {HV_SYS_REG_DBGBCR10_EL1, HVF_SYSREG(0, 10, 14, 0, 5)},
    {HV_SYS_REG_DBGWVR10_EL1, HVF_SYSREG(0, 10, 14, 0, 6)},
    {HV_SYS_REG_DBGWCR10_EL1, HVF_SYSREG(0, 10, 14, 0, 7)},

    {HV_SYS_REG_DBGBVR11_EL1, HVF_SYSREG(0, 11, 14, 0, 4)},
    {HV_SYS_REG_DBGBCR11_EL1, HVF_SYSREG(0, 11, 14, 0, 5)},
    {HV_SYS_REG_DBGWVR11_EL1, HVF_SYSREG(0, 11, 14, 0, 6)},
    {HV_SYS_REG_DBGWCR11_EL1, HVF_SYSREG(0, 11, 14, 0, 7)},

    {HV_SYS_REG_DBGBVR12_EL1, HVF_SYSREG(0, 12, 14, 0, 4)},
    {HV_SYS_REG_DBGBCR12_EL1, HVF_SYSREG(0, 12, 14, 0, 5)},
    {HV_SYS_REG_DBGWVR12_EL1, HVF_SYSREG(0, 12, 14, 0, 6)},
    {HV_SYS_REG_DBGWCR12_EL1, HVF_SYSREG(0, 12, 14, 0, 7)},

    {HV_SYS_REG_DBGBVR13_EL1, HVF_SYSREG(0, 13, 14, 0, 4)},
    {HV_SYS_REG_DBGBCR13_EL1, HVF_SYSREG(0, 13, 14, 0, 5)},
    {HV_SYS_REG_DBGWVR13_EL1, HVF_SYSREG(0, 13, 14, 0, 6)},
    {HV_SYS_REG_DBGWCR13_EL1, HVF_SYSREG(0, 13, 14, 0, 7)},

    {HV_SYS_REG_DBGBVR14_EL1, HVF_SYSREG(0, 14, 14, 0, 4)},
    {HV_SYS_REG_DBGBCR14_EL1, HVF_SYSREG(0, 14, 14, 0, 5)},
    {HV_SYS_REG_DBGWVR14_EL1, HVF_SYSREG(0, 14, 14, 0, 6)},
    {HV_SYS_REG_DBGWCR14_EL1, HVF_SYSREG(0, 14, 14, 0, 7)},

    {HV_SYS_REG_DBGBVR15_EL1, HVF_SYSREG(0, 15, 14, 0, 4)},
    {HV_SYS_REG_DBGBCR15_EL1, HVF_SYSREG(0, 15, 14, 0, 5)},
    {HV_SYS_REG_DBGWVR15_EL1, HVF_SYSREG(0, 15, 14, 0, 6)},
    {HV_SYS_REG_DBGWCR15_EL1, HVF_SYSREG(0, 15, 14, 0, 7)},

#ifdef SYNC_NO_RAW_REGS
    /*
     * The registers below are manually synced on init because they are
     * marked as NO_RAW. We still list them to make number space sync easier.
     */
    {HV_SYS_REG_MDCCINT_EL1, HVF_SYSREG(0, 2, 2, 0, 0)},
    {HV_SYS_REG_MIDR_EL1, HVF_SYSREG(0, 0, 3, 0, 0)},
    {HV_SYS_REG_MPIDR_EL1, HVF_SYSREG(0, 0, 3, 0, 5)},
    {HV_SYS_REG_ID_AA64PFR0_EL1, HVF_SYSREG(0, 4, 3, 0, 0)},
#endif
    {HV_SYS_REG_ID_AA64PFR1_EL1, HVF_SYSREG(0, 4, 3, 0, 2)},
    {HV_SYS_REG_ID_AA64DFR0_EL1, HVF_SYSREG(0, 5, 3, 0, 0)},
    {HV_SYS_REG_ID_AA64DFR1_EL1, HVF_SYSREG(0, 5, 3, 0, 1)},
    {HV_SYS_REG_ID_AA64ISAR0_EL1, HVF_SYSREG(0, 6, 3, 0, 0)},
    {HV_SYS_REG_ID_AA64ISAR1_EL1, HVF_SYSREG(0, 6, 3, 0, 1)},
#ifdef SYNC_NO_MMFR0
    /* We keep the hardware MMFR0 around. HW limits are there anyway */
    {HV_SYS_REG_ID_AA64MMFR0_EL1, HVF_SYSREG(0, 7, 3, 0, 0)},
#endif
    {HV_SYS_REG_ID_AA64MMFR1_EL1, HVF_SYSREG(0, 7, 3, 0, 1)},
    {HV_SYS_REG_ID_AA64MMFR2_EL1, HVF_SYSREG(0, 7, 3, 0, 2)},

    {HV_SYS_REG_MDSCR_EL1, HVF_SYSREG(0, 2, 2, 0, 2)},
    {HV_SYS_REG_SCTLR_EL1, HVF_SYSREG(1, 0, 3, 0, 0)},
    {HV_SYS_REG_CPACR_EL1, HVF_SYSREG(1, 0, 3, 0, 2)},
    {HV_SYS_REG_TTBR0_EL1, HVF_SYSREG(2, 0, 3, 0, 0)},
    {HV_SYS_REG_TTBR1_EL1, HVF_SYSREG(2, 0, 3, 0, 1)},
    {HV_SYS_REG_TCR_EL1, HVF_SYSREG(2, 0, 3, 0, 2)},

    {HV_SYS_REG_APIAKEYLO_EL1, HVF_SYSREG(2, 1, 3, 0, 0)},
    {HV_SYS_REG_APIAKEYHI_EL1, HVF_SYSREG(2, 1, 3, 0, 1)},
    {HV_SYS_REG_APIBKEYLO_EL1, HVF_SYSREG(2, 1, 3, 0, 2)},
    {HV_SYS_REG_APIBKEYHI_EL1, HVF_SYSREG(2, 1, 3, 0, 3)},
    {HV_SYS_REG_APDAKEYLO_EL1, HVF_SYSREG(2, 2, 3, 0, 0)},
    {HV_SYS_REG_APDAKEYHI_EL1, HVF_SYSREG(2, 2, 3, 0, 1)},
    {HV_SYS_REG_APDBKEYLO_EL1, HVF_SYSREG(2, 2, 3, 0, 2)},
    {HV_SYS_REG_APDBKEYHI_EL1, HVF_SYSREG(2, 2, 3, 0, 3)},
    {HV_SYS_REG_APGAKEYLO_EL1, HVF_SYSREG(2, 3, 3, 0, 0)},
    {HV_SYS_REG_APGAKEYHI_EL1, HVF_SYSREG(2, 3, 3, 0, 1)},

    {HV_SYS_REG_SPSR_EL1, HVF_SYSREG(4, 0, 3, 0, 0)},
    {HV_SYS_REG_ELR_EL1, HVF_SYSREG(4, 0, 3, 0, 1)},
    {HV_SYS_REG_SP_EL0, HVF_SYSREG(4, 1, 3, 0, 0)},
    {HV_SYS_REG_AFSR0_EL1, HVF_SYSREG(5, 1, 3, 0, 0)},
    {HV_SYS_REG_AFSR1_EL1, HVF_SYSREG(5, 1, 3, 0, 1)},
    {HV_SYS_REG_ESR_EL1, HVF_SYSREG(5, 2, 3, 0, 0)},
    {HV_SYS_REG_FAR_EL1, HVF_SYSREG(6, 0, 3, 0, 0)},
    {HV_SYS_REG_PAR_EL1, HVF_SYSREG(7, 4, 3, 0, 0)},
    {HV_SYS_REG_MAIR_EL1, HVF_SYSREG(10, 2, 3, 0, 0)},
    {HV_SYS_REG_AMAIR_EL1, HVF_SYSREG(10, 3, 3, 0, 0)},
    {HV_SYS_REG_VBAR_EL1, HVF_SYSREG(12, 0, 3, 0, 0)},
    {HV_SYS_REG_CONTEXTIDR_EL1, HVF_SYSREG(13, 0, 3, 0, 1)},
    {HV_SYS_REG_TPIDR_EL1, HVF_SYSREG(13, 0, 3, 0, 4)},
    {HV_SYS_REG_CNTKCTL_EL1, HVF_SYSREG(14, 1, 3, 0, 0)},
    {HV_SYS_REG_CSSELR_EL1, HVF_SYSREG(0, 0, 3, 2, 0)},
    {HV_SYS_REG_TPIDR_EL0, HVF_SYSREG(13, 0, 3, 3, 2)},
    {HV_SYS_REG_TPIDRRO_EL0, HVF_SYSREG(13, 0, 3, 3, 3)},
    {HV_SYS_REG_CNTV_CTL_EL0, HVF_SYSREG(14, 3, 3, 3, 1)},
    {HV_SYS_REG_CNTV_CVAL_EL0, HVF_SYSREG(14, 3, 3, 3, 2)},
    {HV_SYS_REG_SP_EL1, HVF_SYSREG(4, 1, 3, 4, 0)},
};

enum arm_cpu_mode {
    ARM_CPU_MODE_USR = 0x10,
    ARM_CPU_MODE_FIQ = 0x11,
    ARM_CPU_MODE_IRQ = 0x12,
    ARM_CPU_MODE_SVC = 0x13,
    ARM_CPU_MODE_MON = 0x16,
    ARM_CPU_MODE_ABT = 0x17,
    ARM_CPU_MODE_HYP = 0x1a,
    ARM_CPU_MODE_UND = 0x1b,
    ARM_CPU_MODE_SYS = 0x1f
};

/* FPCR, Floating Point Control Register
 * FPSR, Floating Poiht Status Register
 *
 * For A64 the FPSCR is split into two logically distinct registers,
 * FPCR and FPSR. However since they still use non-overlapping bits
 * we store the underlying state in fpscr and just mask on read/write.
 */
#define FPSR_MASK 0xf800009f
#define FPCR_MASK 0x07ff9f00

#define FPCR_IOE (1 << 8)         /* Invalid Operation exception trap enable */
#define FPCR_DZE (1 << 9)         /* Divide by Zero exception trap enable */
#define FPCR_OFE (1 << 10)        /* Overflow exception trap enable */
#define FPCR_UFE (1 << 11)        /* Underflow exception trap enable */
#define FPCR_IXE (1 << 12)        /* Inexact exception trap enable */
#define FPCR_IDE (1 << 15)        /* Input Denormal exception trap enable */
#define FPCR_FZ16 (1 << 19)       /* ARMv8.2+, FP16 flush-to-zero */
#define FPCR_RMODE_MASK (3 << 22) /* Rounding mode */
#define FPCR_FZ (1 << 24)         /* Flush-to-zero enable bit */
#define FPCR_DN (1 << 25)         /* Default NaN enable bit */
#define FPCR_AHP (1 << 26)        /* Alternative half-precision */
#define FPCR_QC (1 << 27)         /* Cumulative saturation bit */
#define FPCR_V (1 << 28)          /* FP overflow flag */
#define FPCR_C (1 << 29)          /* FP carry flag */
#define FPCR_Z (1 << 30)          /* FP zero flag */
#define FPCR_N (1 << 31)          /* FP negative flag */

#define FPCR_LTPSIZE_SHIFT 16 /* LTPSIZE, M-profile only */
#define FPCR_LTPSIZE_MASK (7 << FPCR_LTPSIZE_SHIFT)
#define FPCR_LTPSIZE_LENGTH 3

#define FPCR_NZCV_MASK (FPCR_N | FPCR_Z | FPCR_C | FPCR_V)
#define FPCR_NZCVQC_MASK (FPCR_NZCV_MASK | FPCR_QC)

/*
uint32_t vfp_get_fpscr(HvfArm64State *env)
{
    uint32_t i, fpscr;

    fpscr = env->vfp.xregs[ARM_VFP_FPSCR]
            | (env->vfp.vec_len << 16)
            | (env->vfp.vec_stride << 20);

    /*
     * M-profile LTPSIZE overlaps A-profile Stride; whichever of the
     * two is not applicable to this CPU will always be zero.
     */
/*
    fpscr |= env->v7m.ltpsize << 16;

    fpscr |= vfp_get_fpscr_from_host(env);

    i = env->vfp.qc[0] | env->vfp.qc[1] | env->vfp.qc[2] | env->vfp.qc[3];
    fpscr |= i ? FPCR_QC : 0;

    return fpscr;
}

static inline uint32_t vfp_get_fpsr(HvfArm64State *env)
{
    return vfp_get_fpscr(env) & FPSR_MASK;
}

static inline void vfp_set_fpsr(HvfArm64State *env, uint32_t val)
{
    uint32_t new_fpscr = (vfp_get_fpscr(env) & ~FPSR_MASK) | (val & FPSR_MASK);
    vfp_set_fpscr(env, new_fpscr);
}

uint32_t vfp_get_fpscr(HvfArm64State *env)
{
    uint32_t i, fpscr;

    fpscr = env->vfp.xregs[ARM_VFP_FPSCR]
            | (env->vfp.vec_len << 16)
            | (env->vfp.vec_stride << 20);

    /*
     * M-profile LTPSIZE overlaps A-profile Stride; whichever of the
     * two is not applicable to this CPU will always be zero.
     */
/*
    fpscr |= env->v7m.ltpsize << 16;

    i = env->vfp.qc[0] | env->vfp.qc[1] | env->vfp.qc[2] | env->vfp.qc[3];
    fpscr |= i ? FPCR_QC : 0;

    return fpscr;
}

static inline uint32_t vfp_get_fpcr(CPUARMState *env)
{
    return vfp_get_fpscr(env) & FPCR_MASK;
}

static inline void vfp_set_fpcr(CPUARMState *env, uint32_t val)
{
    uint32_t new_fpscr = (vfp_get_fpscr(env) & ~FPCR_MASK) | (val & FPCR_MASK);
    vfp_set_fpscr(env, new_fpscr);
}
*/

/* Bit definitions for ARMv8 SPSR (PSTATE) format.
 * Only these are valid when in AArch64 mode; in
 * AArch32 mode SPSRs are basically CPSR-format.
 */
#define PSTATE_SP (1U)
#define PSTATE_M (0xFU)
#define PSTATE_nRW (1U << 4)
#define PSTATE_F (1U << 6)
#define PSTATE_I (1U << 7)
#define PSTATE_A (1U << 8)
#define PSTATE_D (1U << 9)
#define PSTATE_BTYPE (3U << 10)
#define PSTATE_SSBS (1U << 12)
#define PSTATE_IL (1U << 20)
#define PSTATE_SS (1U << 21)
#define PSTATE_PAN (1U << 22)
#define PSTATE_UAO (1U << 23)
#define PSTATE_DIT (1U << 24)
#define PSTATE_TCO (1U << 25)
#define PSTATE_V (1U << 28)
#define PSTATE_C (1U << 29)
#define PSTATE_Z (1U << 30)
#define PSTATE_N (1U << 31)
#define PSTATE_NZCV (PSTATE_N | PSTATE_Z | PSTATE_C | PSTATE_V)
#define PSTATE_DAIF (PSTATE_D | PSTATE_A | PSTATE_I | PSTATE_F)
#define CACHED_PSTATE_BITS (PSTATE_NZCV | PSTATE_DAIF | PSTATE_BTYPE)
/* Mode values for AArch64 */
#define PSTATE_MODE_EL3h 13
#define PSTATE_MODE_EL3t 12
#define PSTATE_MODE_EL2h 9
#define PSTATE_MODE_EL2t 8
#define PSTATE_MODE_EL1h 5
#define PSTATE_MODE_EL1t 4
#define PSTATE_MODE_EL0t 0

#endif
#endif