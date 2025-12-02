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

#include "api_util.h"

extern "C" {
void push_registers_arm64();
void push_registers_arm64_end();

void set_argument_arm64();
void set_argument_arm64_end();

void check_breakpoint_arm64();
void check_breakpoint_arm64_end();

void breakpoint_arm64();
void breakpoint_arm64_end();

void pop_registers_arm64();
void pop_registers_arm64_end();
}

#define IS_OP_INS(x, op) ((bool (*)(uint32_t*))is_##x)(&op)

#define DEFINE_IS_MOV(Rn, Rt)                                                                      \
    bool is_mov_##Rn##Rt(mov_t* mov) {                                                             \
        return is_mov(mov) && mov->Rd == Rn && mov->Rm == Rt;                                      \
    }
#define DEFINE_IS_ZERO()                                                                           \
    bool is_zero(uint32_t* op) {                                                                   \
        return *op == 0x0;                                                                         \
    }

#define IS_ZERO() (bool (*)(uint32_t*)) is_zero
#define IS_INS(x) (bool (*)(uint32_t*)) is_##x
#define IS_MOV(Rd, Rm) (bool (*)(uint32_t*)) is_mov_##Rd##Rm

namespace arch {
namespace arm64 {
struct arm64_register_state {
    uint64_t x[29];
    uint64_t fp;
    uint64_t lr;
    uint64_t sp;
    uint64_t pc;
    uint64_t cpsr;
};

static constexpr size_t Breakpoint = sizeof(uint32_t);
static constexpr uint16_t BreakpointPrefix = 0b11010100001;

union Breakpoint MakeBreakpoint();

constexpr size_t BreakpointSize() {
    return Breakpoint;
}

union Breakpoint {
    struct PACKED Break {
        uint32_t z : 5, imm : 16, op : 11;
    } brk;
};

static constexpr size_t NormalBranch = sizeof(uint32_t);
static constexpr size_t IndirectBranch = sizeof(uint32_t);

static constexpr uint8_t NormalBranchPrefix = 0x05;
static constexpr uint32_t IndirectBranchPrefix = 0b1101011000011111000000;

union Branch MakeBranch(mach_vm_address_t to, mach_vm_address_t from);

constexpr size_t NormalBranchSize() {
    return NormalBranch;
}
constexpr size_t IndirectBranchSize() {
    return IndirectBranch;
}

union Branch {
    struct PACKED Br {
        uint32_t imm : 26, op : 5, mode : 1;
    } branch;

    uint32_t value;
};

static constexpr size_t CallFunction = sizeof(uint32_t);
static constexpr uint8_t CallFunctionPrefix = 0b00101;

union FunctionCall MakeCall(mach_vm_address_t to, mach_vm_address_t from);

constexpr size_t FunctionCallSize() {
    return CallFunction;
}

union FunctionCall {
    struct PACKED CallFunction {
        uint32_t imm : 26, op : 5, mode : 1;
    } c;

    uint32_t value;
};

typedef uint8_t aarch64_shift;

enum {
    AARCH64_SHIFT_LSL = 0,
    AARCH64_SHIFT_LSR = 1,
    AARCH64_SHIFT_ASR = 2,
    AARCH64_SHIFT_ROR = 3,
};

typedef uint8_t aarch64_extend;

enum {
    AARCH64_EXTEND_UXTB = 0,
    AARCH64_EXTEND_UXTH = 1,
    AARCH64_EXTEND_UXTW = 2,
    AARCH64_EXTEND_UXTX = 3,
    AARCH64_EXTEND_SXTB = 4,
    AARCH64_EXTEND_SXTH = 5,
    AARCH64_EXTEND_SXTW = 6,
    AARCH64_EXTEND_SXTX = 7,
    AARCH64_EXTEND_LSL = 8,
};

#define AARCH64_EXTEND_TYPE(ext) ((ext) & 0x7)

#define AARCH64_EXTEND_LEN(ext) ((ext) & 0x3)
#define AARCH64_EXTEND_SIGN(ext) (((ext) >> 2) & 1)
#define AARCH64_EXTEND_IS_LSL(ext) ((ext) & AARCH64_EXTEND_LSL)

#define AARCH64_INS_TYPE(ins, type) (((ins) & AARCH64_##type##_MASK) == AARCH64_##type##_BITS)

// ---- ADC, ADCS, SBC, SBCS ----
// ---- NGC, NGCS ----
#define AARCH64_ADC_CLASS_MASK 0x1fe0fc00
#define AARCH64_ADC_CLASS_BITS 0x1a000000

// ---- ADD extended register, ADDS extended register, SUB extended register, SUBS extended
//      register ----
// ---- CMN extended register, CMP extended register ----
#define AARCH64_ADD_XR_CLASS_MASK 0x1fe00000
#define AARCH64_ADD_XR_CLASS_BITS 0x0b200000

// ---- ADD immediate, ADDS immediate, SUB immediate, SUBS immediate ----
// ---- CMN immediate, CMP immediate, MOV to/from SP ----
#define AARCH64_ADD_IM_CLASS_MASK 0x1f000000
#define AARCH64_ADD_IM_CLASS_BITS 0x11000000

// ---- ADD shifted register, ADDS shifted register, SUB shifted register, SUBS shifted
//      register ----
// ---- CMN shifted register, CMP shifted register, NEG shifted register, NEGS shifted
//      register ----
#define AARCH64_ADD_SR_CLASS_MASK 0x1f200000
#define AARCH64_ADD_SR_CLASS_BITS 0x0b000000

// ---- AND immediate, ANDS immediate, EOR immediate, ORR immediate ----
// ---- MOV bitmask immediate, TST immediate ----
#define AARCH64_AND_IM_CLASS_MASK 0x5f800000
#define AARCH64_AND_IM_CLASS_BITS 0x12000000

// ---- AND shifted register, ANDS shifted register, BIC shifted register, BICS shifted register,
//      EON shifted register, EOR shifted register, ORN shifted register, ORR shifted register ----
// ---- MOV register, MVN, TST shifted register ----
#define AARCH64_AND_SR_CLASS_MASK 0x1f000000
#define AARCH64_AND_SR_CLASS_BITS 0x0a000000

// ---- LDNP, LDP post-index, LDP pre-index, LDP signed offset,
//      LDPSW post-index, LDPSW pre-index, LDPSW signed offset,
//      STNP, STP post-index, STP pre-index, STP signed offset  ----

#define AARCH64_LDP_CLASS_MASK 0x3e000000
#define AARCH64_LDP_CLASS_BITS 0x28000000

// ---- LDR immediate unsigned offset, LDRB immediate unsigned offset,
//      LDRH immediate unsigned offset, LDRSB immediate unsigned offset,
//      LDRSH immediate unsigned offset, LDRSW immediate unsigned offset,
//      STR immediate unsigned offset, STRB immediate unsigned offset,
//      STRH immediate unsigned offset ----

#define AARCH64_LDR_UI_CLASS_MASK 0x3f000000
#define AARCH64_LDR_UI_CLASS_BITS 0x39000000

// ---- LDR immediate post-index, LDR immediate pre-index, LDRB immediate post-index,
//      LDRB immediate pre-index, LDRH immediate post-index, LDRH immediate pre-index,
//      LDRSB immediate post-index, LDRSB immediate pre-index, LDRSH immediate post-index,
//      LDRSH immediate pre-index, LDRSW immediate post-index, LDRSW immediate pre-index,
//      STR immediate post-index, STR immediate pre-index, STRB immediate post-index,
//      STRB immediate pre-index, STRH immediate post-index, STRH immediate pre-index ----

#define AARCH64_LDR_IX_CLASS_MASK 0x3f200400
#define AARCH64_LDR_IX_CLASS_BITS 0x38000400

// ---- LDR register, LDRB register, LDRH register, LDRSB register, LDRSH register, LDRSW
// register,
//      STR register, STRB register, STRH register ----

#define AARCH64_LDR_R_CLASS_MASK 0x3f200c00
#define AARCH64_LDR_R_CLASS_BITS 0x38200800

// ---- LDR literal, LDRSW literal ----

#define AARCH64_LDR_LIT_CLASS_MASK 0x3f000000
#define AARCH64_LDR_LIT_CLASS_BITS 0x18000000

// ---- MOVK, MOVN, MOVZ ----
// ---- MOV inverted wide immediate, MOV wide immediate ----

#define AARCH64_MOV_CLASS_MASK 0x1f800000
#define AARCH64_MOV_CLASS_BITS 0x12800000

// ---- FADD (scalar), FSUB (scalar), FMUL (scalar), FDIV (scalar)
// ---- FABS (scalar), FCMP (scalar), FCSEL (scalar)

#define AARCH64_FP_SCALAR_CLASS_MASK 0xff200000
#define AARCH64_FP_SCALAR_CLASS_BITS 0x1e200000

#pragma pack(4)
typedef struct {
    uint32_t Rd : 5, Rn : 5, imms : 6, immr : 6, N : 1, op : 8, sf : 1;
} lsl_imm_t, lsr_imm_t;

typedef struct {
    uint32_t Rd : 5, Rn : 5, op2 : 6, Rm : 5, op : 10, sf : 1;
} lsl_reg_t, lsr_reg_t;

typedef struct {
    uint32_t Rd : 5, Rn : 5, imms : 6, immr : 6, N : 1, op : 8, sf : 1;
} asr_imm_t;

typedef struct {
    uint32_t Rd : 5, Rn : 5, op2 : 6, Rm : 5, op : 10, sf : 1;
} asr_reg_t;

typedef struct {
    uint32_t Rd : 5, Rn : 5, op2 : 6, Rm : 5, op1 : 10, sf : 1;
} adc_t, ngc_t, sbc_t;

typedef struct {
    uint32_t Rd : 5, Rn : 5, imm : 6, Rm : 5, z : 1, shift : 2, op : 7, sf : 1;
} neg_t;

typedef struct {
    uint32_t Rd : 5, immhi : 19, op2 : 5, immlo : 2, op1 : 1;
} adr_t;

typedef struct {
    uint32_t Rd : 5, Rn : 5, imm : 12, sh : 1, op : 8, sf : 1;
} add_imm_t, sub_imm_t;

typedef struct {
    uint32_t Rd : 5, Rn : 5, imm : 6, Rm : 5, op2 : 1, shift : 2, op1 : 7, sf : 1;
} add_reg_t, sub_reg_t;

typedef struct {
    uint32_t Rd : 5, Rn : 5, imm : 3, option : 3, Rm : 5, op : 10, sf : 1;
} add_ext_t, sub_ext_t;

typedef struct {
    uint32_t Rt : 5, Rn : 5, imm : 12, op2 : 8, sf : 1, op1 : 1;
} ldr_imm_uoff_t;

typedef struct {
    uint32_t Rt : 5, imm : 19, op2 : 6, sf : 1, op1 : 1;
} ldr_lit_t, ldrsw_lit_t;

typedef struct {
    uint32_t Rt : 5, Rn : 5, Rt2 : 5, imm : 7, op : 9, sf : 1;
} ldp_t, stp_t;

typedef struct {
    uint32_t Rt : 5, Rn : 5, Rt2 : 5, op3 : 1, Rs : 5, op2 : 9, sf : 1, op1 : 1;
} ldxr_t, stxr_t;

typedef struct {
    uint32_t Rt : 5, Rn : 5, op4 : 6, Rs : 5, op3 : 1, R : 1, A : 1, op2 : 6, sf : 1, op1 : 1;
} ldadd_t;

/*typedef struct
{
    uint32_t Rt     : 5,
             Rn     : 5,
             op3    : 2,
             S      : 1,
             opt    : 3,
             Rm     : 5,
             op2    : 9,
             sf     : 1,
             op1    : 1;
} str_reg_t;*/

typedef struct {
    uint32_t Rt : 5, Rn : 5, op3 : 2, imm : 9, op2 : 9, sf : 1, op1 : 1;
} str_imm_t;

typedef struct {
    uint32_t Rt : 5, Rn : 5, op3 : 2, imm : 9, op2 : 9, sf : 1, op1 : 1;
} ldr_imm_t;

typedef struct {
    uint32_t Rt : 5, Rn : 5, imm : 12, op2 : 8, sf : 1, op1 : 1;
} str_uoff_t;

typedef struct {
    uint32_t Rt : 5, Rn : 5, op3 : 2, imm : 9, op2 : 9, sf : 1, op1 : 1;
} ldur_t, stur_t;

typedef struct {
    uint32_t Rt : 5, Rn : 5, op2 : 2, imm : 9, op : 11;
} ldrb_imm_t, ldrh_imm_t, ldrsb_imm_t, ldrsh_imm_t, ldrsw_imm_t, strb_imm_t, strh_imm_t;

typedef struct {
    uint32_t Rt : 5, Rn : 5, imm : 12, op : 10;
} ldrb_imm_uoff_t, ldrh_imm_uoff_t, ldrsw_imm_uoff_t, strb_imm_uoff_t, strh_imm_uoff_t;

typedef struct {
    uint32_t Rt : 5, Rn : 5, imm : 12, sf : 1, op : 9;
} ldrsb_imm_uoff_t, ldrsh_imm_uoff_t;

typedef struct {
    uint32_t Rt : 5, Rn : 5, op2 : 2, S : 1, option : 3, Rm : 5, op : 9, size : 2;
} ldr_reg_t, ldrh_reg_t, ldrb_reg_t, ldrsb_reg_t, ldrsh_reg_t, ldrsw_reg_t, str_reg_t, strb_reg_t,
    strh_reg_t;

typedef struct {
    uint32_t Rt : 5, Rn : 5, imm : 12, op2 : 1, opc : 1, op1 : 6, size : 2;
} ldr_fp_uoff_t, str_fp_uoff_t;

typedef struct {
    uint32_t Rt : 5, Rn : 5, op3 : 2, imm : 9, op2 : 2, opc : 1, op1 : 6, size : 2;
} ldur_fp_t, stur_fp_t;

typedef struct {
    uint32_t Rt : 5, Rn : 5, Rt2 : 5, imm : 7, op : 8, opc : 2;
} ldp_fp_t, stp_fp_t;

typedef struct {
    uint32_t Rd : 5, Rn : 5, imm : 12, shift : 2, op : 7, sf : 1;
} cmp_imm_t, cmn_imm_t;

typedef struct {
    uint32_t Rd : 5, Rn : 5, imm : 6, Rm : 5, z : 1, shift : 2, op : 7, sf : 1;
} cmp_reg_t, cmn_reg_t;

typedef struct {
    uint32_t Rd : 5, Rn : 5, imm : 3, option : 3, Rm : 5, op : 10, sf : 1;
} cmp_ext_t, cmn_ext_t;

typedef struct {
    uint32_t op2 : 5, Rn : 5, op1 : 22;
} br_t;

typedef struct {
    uint32_t imm : 26, op : 5, mode : 1;
} bl_t, b_t;

typedef struct {
    uint32_t cond : 4, op2 : 1, imm : 19, op1 : 8;
} b_cond_t;

typedef struct {
    uint32_t Rm : 5, Rn : 5, M : 1, A : 1, op2 : 12, Z : 1, op : 7;
} blraa_t, blraaz_t, blrab_t, blrabz_t;

typedef struct {
    uint32_t Z : 5, imm : 16, op : 11;
} brk_t;

typedef struct {
    uint32_t Rt : 5, imm : 19, op : 7, sf : 1;
} cbz_t;

typedef struct {
    uint32_t Rt : 5, imm : 14, bit : 5, op : 7, sf : 1;
} tbz_t;

typedef struct {
    uint32_t Rd : 5, op2 : 11, Rm : 5, op1 : 10, sf : 1;
} mov_t;

typedef struct {
    uint32_t Rd : 5, imm : 16, hw : 2, op : 8, sf : 1;
} movz_t, movk_t, movn_t;

typedef struct {
    uint32_t Rd : 5, Rn : 5, imms : 6, immr : 6, N : 1, op : 8, sf : 1;
} movi_t;

typedef struct {
    uint32_t Rd : 5, Rn : 5, imms : 6, immr : 6, N : 1, op : 8, sf : 1;
} orr_t, eor_t;

typedef struct {
    uint32_t Rd : 5, Rn : 5, imm : 6, Rm : 5, N : 1, shift : 2, op : 7, sf : 1;
} orr_shift_t, orn_shift_t, eor_shift_t, eon_shift_t;

typedef struct {
    uint32_t Rd : 5, Rn : 5, imms : 6, immr : 6, N : 1, op : 8, sf : 1;
} and_imm_t, ands_imm_t, tst_imm_t;

typedef struct {
    uint32_t Rd : 5, Rn : 5, imm : 6, Rm : 5, N : 1, shift : 2, op : 7, sf : 1;
} and_shift_t, ands_shift_t, tst_shift_t;

typedef struct {
    uint32_t Rd : 5, Rn : 5, imm : 6, Rm : 5, N : 1, shift : 2, op : 7, sf : 1;
} mvn_t;

typedef struct {
    uint32_t Rd : 5, Rn : 5, imm : 6, Rm : 5, N : 1, shift : 2, op : 7, sf : 1;
} bic_t;

typedef struct {
    uint32_t Rd : 5, Rn : 5, Ra : 5, o0 : 1, Rm : 5, op2 : 2, U : 1, op1 : 8;
} umull_t;

typedef struct {
    uint32_t Rt : 5, op2 : 3, CRm : 4, CRn : 4, op1 : 3, op0 : 1, mrs : 12;
} mrs_t;

typedef struct {
    uint32_t msr3 : 5, op2 : 3, CRm : 4, msr2 : 4, op1 : 3, msr : 13;
} msr_imm_t;

typedef struct {
    uint32_t Rt : 5, op2 : 3, CRm : 4, CRn : 4, op1 : 3, o0 : 1, msr : 12;
} msr_reg_t;

typedef struct {
    uint32_t Rt : 5, Rn : 5, o2 : 1, W : 1, imm : 9, o1 : 1, S : 1, M : 1, op : 8;
} ldraa_t, ldrab_t;

typedef struct {
    uint32_t Rd : 5, Rn : 5, key : 1, data : 1, op2 : 1, Z : 1, op1 : 18;
} pac_t;

typedef struct {
    uint32_t op3 : 5, x : 1, key : 1, op2 : 2, C : 1, op1 : 22;
} pacsys_t;

typedef struct {
    uint32_t Rd : 5, Rn : 5, op2 : 6, Rm : 5, op1 : 11;
} pacga_t;

typedef struct {
    uint32_t Rd : 5, Rn : 5, op2 : 3, Z : 1, op : 18;
} pacda_t, pacdza_t, pacdb_t, pacdzb_t;

typedef struct {
    uint32_t Rd : 5, Rn : 5, op2 : 3, Z : 1, op : 18;
} pacia_t, paciza_t, pacib_t, pacizb_t;

typedef struct {
    uint32_t CRd : 5, op2 : 3, CRm : 4, op : 20;
} pacia1716_t, paciasp_t, paciaz_t, pacib1716_t, pacibsp_t, pacibz_t;

typedef struct {
    uint32_t Rm : 5, Rn : 5, M : 1, A : 1, op : 20;
} retaa_t, retab_t;

typedef struct {
    uint32_t Rd : 5, Rn : 5, D : 1, op : 21;
} xpacd_t, xpaci_t, xpaclri_t;

typedef struct {
    uint32_t Rd : 5, Rn : 5, op2 : 3, Z : 1, op : 18;
} autda_t, autdza_t;

typedef struct {
    uint32_t Rd : 5, Rn : 5, op2 : 3, Z : 1, op : 18;
} autdb_t, autdzb_t;

typedef struct {
    uint32_t Rd : 5, Rn : 5, op2 : 3, Z : 1, op : 18;
} autia_t, autiza_t, autib_t, autizb_t;

typedef struct {
    uint32_t CRd : 5, op2 : 3, CRm : 4, op : 20;
} autia1716_t, autiasp_t, autiaz_t, autib1716_t, autibsp_t, autibz_t;

typedef struct {
    uint32_t o : 5, op2 : 3, CRm : 4, op : 20;
} bti_t;

typedef struct {
    uint32_t Rd : 5, Rn : 5, op2 : 6, Rm : 5, o : 1, ftype : 2, op : 8;
} fadd_scalar_t, fsub_scalar_t, fmul_scalar_t, fdiv_scalar_t, fcmp_scalar_t, fabs_scalar_t,
    fcsel_scalar_t;

typedef struct {
    uint32_t Rd : 5, Rn : 5, op2 : 6, Rm : 5, op : 9, Q : 1, Z : 1;
} fadd_vector_t, fsub_vector_t, fmul_vector_t, fdiv_vector_t, fabs_vector_t;

typedef struct {
    uint32_t Rd : 5, Rn : 5, op2 : 6, opcode : 3, rmode : 2, o : 1, ftype : 2, op : 7, sf : 1;
} fmov_t, fcvtzs_scalar_t;

typedef struct {
    uint32_t Rd : 5, Rn : 5, op2 : 12, sz : 1, op : 7, Q : 1, Z : 1;
} fcvtzs_vector_t;

typedef struct {
    uint32_t Rd : 5, Rn : 5, op2 : 6, immb : 3, immh : 4, op : 7, Q : 1, Z : 1;
} fcvtzs_fixed_vector_t;

typedef struct {
    uint32_t Rd : 5, op2 : 8, imm : 8, o : 1, ftype : 2, op : 8;
} fmov_scalar_t;

typedef struct {
    uint32_t Rd : 5, h : 1, g : 1, f : 1, e : 1, d : 1, op2 : 6, c : 1, b : 1, a : 1, op : 11,
        Q : 1, Z : 1;
} fmov_vector_t;

typedef struct {
    uint32_t Rd : 5, Rn : 5, op2 : 12, ftype : 2, op : 8;
} fmov_reg_t;

typedef struct {
    uint32_t Rt : 5, Rn : 5, op2 : 2, imm : 9, opc : 3, op : 6, size : 2;
} str_simd_fp_imm_t, ldr_simd_fp_imm_t;

typedef struct {
    uint32_t Rt : 5, Rn : 5, imm : 12, opc : 2, op : 6, size : 2;
} str_simd_fp_imm_uoff_t, ldr_simd_fp_imm_uoff_t;

typedef struct {
    uint32_t Rt : 5, Rn : 5, op2 : 2, S : 1, option : 3, Rm : 5, opc : 3, op : 6, size : 2;
} str_simd_fp_reg_t, ldr_simd_fp_reg_t;

typedef struct {
    uint32_t Rt : 5, Rn : 5, Rt2 : 5, imm : 7, op : 8, opc : 2;
} stp_simd_fp_t, ldp_simd_fp_t;

typedef struct {
    uint32_t Rd : 5, Rn : 5, op2 : 6, Rm : 5, op : 8, Q : 1, Z : 1;
} and_vector_t, orr_vector_t, orn_vector_t, eor_vector_t, orr_vector_t, orn_vector_t, bic_vector_t,
    bif_vector_t, bit_vector_t, bsl_vector_t;

typedef struct {
    uint32_t Rd : 5, Rn : 5, imm : 6, Rm : 5, op : 11;
} xar_vector_t;

typedef struct {
    uint32_t op2 : 8, CRm : 4, op : 20;
} sb_t, isb_t, dsb_t, esb_t, dmb_t, csdb_t;

typedef struct {
    uint32_t Rd : 5, op : 27;
} wfit_t;

typedef struct {
    uint32_t Rt : 5, op2 : 3, CRm : 4, CRn : 4, op1 : 3, op : 13;
} sys_t, at_t, cfp_t, cpp_t, dc_t, dvp_t, ic_t, tlbi_t;

typedef struct {
    uint32_t op2 : 5, imm : 16, op : 11;
} svc_t, smc_t, hvc_t;

typedef uint32_t nop_t;
typedef uint32_t ret_t;
#pragma pack()

static inline bool is_lsl_imm(lsl_imm_t* lsl) {
    bool cond1 = (!lsl->sf && lsl->op == 0b10100110 && lsl->N == 0b0 && lsl->imms != 0b011111);
    bool cond2 = (lsl->sf && lsl->op == 0b10100110 && lsl->N == 0b1 && lsl->imms != 0b111111);

    return cond1 || cond2;
}

static inline bool is_lsr_imm(lsr_imm_t* lsr) {
    bool cond1 = (!lsr->sf && lsr->op == 0b10100110 && lsr->N == 0b0 && lsr->imms == 0b011111);
    bool cond2 = (lsr->sf && lsr->op == 0b10100110 && lsr->N == 0b1 && lsr->imms == 0b111111);

    return cond1 || cond2;
}

static inline bool is_asr_imm(asr_imm_t* asr) {
    return asr->op == 0b00100110 && ((!asr->sf && asr->N == 0b0 && asr->imms == 0b011111) ||
                                     (asr->sf && asr->N == 0b1 && asr->imms == 0b111111));
}

static inline bool is_asr_reg(asr_reg_t* asr) {
    return asr->op == 0b0011010110 && asr->op2 == 0b001010;
}

static inline bool is_lsl_reg(lsl_reg_t* lsl) {
    return lsl->op == 0b0011010110 && lsl->op2 == 0b001000;
}

static inline bool is_lsr_reg(lsr_reg_t* lsr) {
    return lsr->op == 0b0011010110 && lsr->op2 == 0b001001;
}

static inline bool is_adr(adr_t* adr) {
    return adr->op1 == 0 && adr->op2 == 0x10;
}

static inline bool is_adrp(adr_t* adrp) {
    return adrp->op1 == 1 && adrp->op2 == 0x10;
}

static inline int64_t get_adr_off(adr_t* adr) {
    size_t scale = adr->op1 ? 12 : 0;
    return (((int64_t)(adr->immlo | (adr->immhi << 2))) << (64 - 21)) >> (64 - 21 - scale);
}

static inline bool is_adc(adc_t* adc) {
    return adc->op1 == 0b0011010000 && adc->op2 == 0b000000;
}

static inline bool is_adcs(adc_t* adcs) {
    return adcs->op1 == 0b0111010000 && adcs->op2 == 0b000000;
}

static inline bool is_ngc(ngc_t* ngc) {
    return ngc->op1 == 0b1011010000 && ngc->op2 == 0b000000 && ngc->Rn == 0b11111;
}

static inline bool is_sbc(sbc_t* sbc) {
    return sbc->op1 == 0b1011010000 && sbc->op2 == 0b000000;
}

static inline bool is_sbcs(sbc_t* sbcs) {
    return sbcs->op1 == 0b1111010000 && sbcs->op2 == 0b000000;
}

static inline bool is_ngcs(ngc_t* ngcs) {
    return ngcs->op1 == 0b1111010000 && ngcs->op2 == 0b000000 && ngcs->Rn == 0b11111;
}

static inline bool is_neg(neg_t* neg) {
    return neg->op == 0b1101011 && neg->z == 0 && neg->Rn == 0b11111 && neg->Rd != 0b11111;
}

static inline bool is_add_imm(add_imm_t* add) {
    return add->op == 0b00100010;
}

static inline bool is_adds_imm(add_imm_t* adds) {
    return adds->op == 0b01100010;
}

static inline bool is_sub_imm(sub_imm_t* sub) {
    return sub->op == 0b10100010;
}

static inline bool is_subs_imm(sub_imm_t* subs) {
    return subs->op == 0b11100010;
}

static inline uint32_t get_add_sub_imm(add_imm_t* add) {
    return add->imm << ((add->sh) ? 12 : 0);
}

static inline bool is_add_reg(add_reg_t* add) {
    return add->op1 == 0b0001011 && add->op2 == 0;
}

static inline bool is_adds_reg(add_reg_t* adds) {
    return adds->op1 == 0b0101011 && adds->op2 == 0;
}

static inline bool is_sub_reg(sub_reg_t* sub) {
    return sub->op1 == 0b1001011 && sub->op2 == 0;
}

static inline bool is_subs_reg(sub_reg_t* subs) {
    return subs->op1 == 0b1101011 && subs->op2 == 0;
}

static inline bool is_add_ext(add_ext_t* add) {
    return add->op == 0b0001011001;
}

static inline bool is_adds_ext(add_ext_t* adds) {
    return adds->op == 0b0101011001;
}

static inline bool is_sub_ext(sub_ext_t* sub) {
    return sub->op == 0b1001011001;
}

static inline bool is_subs_ext(sub_ext_t* subs) {
    return subs->op == 0b1101011001;
}

static inline bool is_umull(umull_t* mul) {
    return mul->op1 == 0b10011011 && mul->U == 0b1 && mul->o0 == 0b0 && mul->Ra == 0b11111;
}

static inline bool is_ldr_imm_post(ldr_imm_t* ldr) {
    return ldr->op1 == 1 && ldr->op2 == 0b111000010 && ldr->op3 == 0b01;
}

static inline bool is_ldr_imm_pre(ldr_imm_t* ldr) {
    return ldr->op1 == 1 && ldr->op2 == 0b111000010 && ldr->op3 == 0b11;
}

static inline bool is_ldr_imm_uoff(ldr_imm_uoff_t* ldr) {
    return ldr->op1 == 1 && ldr->op2 == 0xe5;
}

static inline uint32_t get_ldr_imm_uoff(ldr_imm_uoff_t* ldr) {
    return ldr->imm << (2 + ldr->sf);
}

static inline bool is_ldr_lit(ldr_lit_t* ldr) {
    return ldr->op1 == 0 && ldr->op2 == 0x18;
}

static inline bool is_ldrsw_lit(ldrsw_lit_t* ldrsw) {
    return ldrsw->op1 == 0b1 && ldrsw->sf == 0 && ldrsw->op2 == 0b011000;
}

static inline int64_t get_ldr_lit_off(ldr_lit_t* ldr) {
    return (((int64_t)ldr->imm) << (64 - 19)) >> (64 - 21);
}

static inline bool is_ldr_reg(ldr_reg_t* ldr) {
    return (ldr->size & 0b10) == 0b10 && ldr->op == 0b111000011 && ldr->op2 == 0b10;
}

static inline bool is_ldrb_reg(ldrb_reg_t* ldrb) {
    return ldrb->size == 0b00 && ldrb->op == 0b111000011 && ldrb->op2 == 0b10;
}

static inline bool is_ldrh_reg(ldrh_reg_t* ldrh) {
    return ldrh->size == 0b01 && ldrh->op == 0b111000011 && ldrh->op2 == 0b10;
}

static inline bool is_ldrsb_reg(ldrsb_reg_t* ldrsb) {
    return ldrsb->size == 0b00 && (ldrsb->op == 0b111000101 || ldrsb->op == 0b111000111) &&
           ldrsb->op2 == 0b10;
}

static inline bool is_ldrsh_reg(ldrsh_reg_t* ldrsh) {
    return ldrsh->size == 0b01 && (ldrsh->op == 0b111000101 || ldrsh->op == 0b111000111) &&
           ldrsh->op2 == 0b10;
}

static inline bool is_ldrsw_reg(ldrsw_reg_t* ldrsw) {
    return ldrsw->size == 0b10 && ldrsw->op == 0b111000101 && ldrsw->op == 0b10;
}

static inline bool is_ldxr(ldxr_t* ldxr) {
    return ldxr->op1 == 1 && ldxr->op2 == 0x42 && ldxr->op3 == 0 && ldxr->Rs == 0x1f &&
           ldxr->Rt2 == 0x1f;
}

static inline bool is_stxr(stxr_t* stxr) {
    return stxr->op1 == 1 && stxr->op2 == 0x40 && stxr->op3 == 0 && stxr->Rt2 == 0x1f;
}

static inline bool is_ldadd(ldadd_t* ldadd) {
    return ldadd->op4 == 0 && ldadd->op3 == 1 && ldadd->op2 == 0x38 && ldadd->op1 == 1;
}

static inline bool is_ldnp(ldp_t* ldp) {
    return ldp->op == 0xa1;
}

static inline bool is_ldpsw_pre(ldp_t* ldp) {
    return ldp->op == 0x1a7;
}

static inline bool is_ldpsw_post(ldp_t* ldp) {
    return ldp->op == 0x1a3;
}

static inline bool is_ldpsw_soff(ldp_t* ldp) {
    return ldp->op == 0x1a5;
}

static inline bool is_ldp_pre(ldp_t* ldp) {
    return ldp->op == 0xa7;
}

static inline bool is_ldp_post(ldp_t* ldp) {
    return ldp->op == 0xa3;
}

static inline bool is_ldp_soff(ldp_t* ldp) {
    return ldp->op == 0xa5;
}

static inline bool is_stnp(stp_t* stp) {
    return stp->op == 0xa0;
}

static inline bool is_stp_pre(stp_t* stp) {
    return stp->op == 0xa6;
}

static inline bool is_stp_post(stp_t* stp) {
    return stp->op == 0xa2;
}

static inline bool is_stp_soff(stp_t* stp) {
    return stp->op == 0xa4;
}

static inline int64_t get_ldp_stp_off(ldp_t* ldp) {
    return ((int64_t)ldp->imm << (64 - 7)) >> (64 - 7 - (2 + ldp->sf));
}

static inline bool is_str_pre(str_imm_t* str) {
    return str->op1 == 1 && str->op2 == 0x1c0 && str->op3 == 0x3;
}

static inline bool is_str_post(str_imm_t* str) {
    return str->op1 == 1 && str->op2 == 0x1c0 && str->op3 == 0x1;
}

static inline int64_t get_str_imm(str_imm_t* str) {
    return ((int64_t)str->imm << (64 - 9)) >> (64 - 9 - (2 + str->sf));
}

static inline bool is_str_uoff(str_uoff_t* str) {
    return str->op1 == 1 && str->op2 == 0xe4;
}

static inline uint32_t get_str_uoff(str_uoff_t* str) {
    return str->imm << (2 + str->sf);
}

static inline bool is_str_reg(str_reg_t* str) {
    return (str->size == 0b10 || str->size == 0b11) && str->op == 0b111000001 && str->op2 == 0b10;
}

static inline bool is_strb_reg(strb_reg_t* strb) {
    return strb->size == 0b00 && strb->op == 0b111000001 && strb->op2 == 0b10;
}

static inline bool is_strh_reg(strh_reg_t* strh) {
    return strh->size == 0b01 && strh->op == 0b111000001 && strh->op2 == 0b10;
}

static inline bool is_stur(stur_t* stur) {
    return stur->op1 == 0b1 && stur->op2 == 0b111000000 && stur->op3 == 0b00;
}

static inline bool is_sturh(stur_t* sturh) {
    return sturh->op1 == 0b0 && sturh->sf == 0b1 && sturh->op2 == 0b111000000 && sturh->op3 == 0b00;
}

static inline bool is_sturb(stur_t* sturb) {
    return sturb->op1 == 0b0 && sturb->sf == 0b0 && sturb->op2 == 0b111000000 && sturb->op3 == 0b00;
}

static inline bool is_ldur(ldur_t* ldur) {
    return ldur->op1 == 0b1 && ldur->op2 == 0b111000010 && ldur->op3 == 0b0;
}

static inline bool is_ldurh(ldur_t* ldurh) {
    return ldurh->op1 == 0b0 && ldurh->sf == 0b1 && ldurh->op2 == 0b111000010 && ldurh->op3 == 0b00;
}

static inline bool is_ldurb(ldur_t* ldurb) {
    return ldurb->op1 == 0b0 && ldurb->sf == 0b0 && ldurb->op2 == 0b111000010 && ldurb->op3 == 0b00;
}

static inline int64_t get_ldur_off(ldur_t* ldur) {
    return (int64_t)ldur->imm;
}

static inline int64_t get_stur_off(stur_t* stur) {
    return (int64_t)stur->imm;
}

static inline bool is_ldrb_imm_pre(ldrb_imm_t* ldrb) {
    return ldrb->op == 0b00111000010 && ldrb->op2 == 0b11;
}

static inline bool is_ldrb_imm_post(ldrb_imm_t* ldrb) {
    return ldrb->op == 0b00111000010 && ldrb->op2 == 0b01;
}

static inline bool is_ldrb_imm_uoff(ldrb_imm_uoff_t* ldrb) {
    return ldrb->op == 0b0011100101;
}

static inline uint32_t get_ldrb_imm_uoff(ldrb_imm_uoff_t* ldrb) {
    return ldrb->imm;
}

static inline bool is_ldrh_imm_pre(ldrh_imm_t* ldrh) {
    return ldrh->op == 0b01111000010 && ldrh->op2 == 0b11;
}

static inline bool is_ldrh_imm_post(ldrh_imm_t* ldrh) {
    return ldrh->op == 0b01111000010 && ldrh->op2 == 0b01;
}

static inline bool is_ldrh_imm_uoff(ldrh_imm_uoff_t* ldrh) {
    return ldrh->op == 0b0111100101;
}

static inline uint32_t get_ldrh_imm_uoff(ldrh_imm_uoff_t* ldrh) {
    return ldrh->imm << 1;
}

static inline bool is_ldrsb_imm_pre(ldrsb_imm_t* ldrsb) {
    return (ldrsb->op & 0b11111111101) == 0b00111000100 && ldrsb->op2 == 0b11;
}

static inline bool is_ldrsb_imm_post(ldrsb_imm_t* ldrsb) {
    return (ldrsb->op & 0b11111111101) == 0b00111000100 && ldrsb->op2 == 0b01;
}

static inline bool is_ldrsb_imm_uoff(ldrsb_imm_uoff_t* ldrsb) {
    return ldrsb->op == 0b001110011;
}

static inline uint32_t get_ldrsb_imm_uoff(ldrsb_imm_uoff_t* ldrsb) {
    return ldrsb->imm;
}

static inline bool is_ldrsh_imm_pre(ldrsh_imm_t* ldrsh) {
    return ldrsh->op == 0b011110001 && ldrsh->op2 == 0b01;
}

static inline bool is_ldrsh_imm_post(ldrsh_imm_t* ldrsh) {
    return ldrsh->op == 0b011110001 && ldrsh->op2 == 0b11;
}

static inline bool is_ldrsh_imm_uoff(ldrsh_imm_uoff_t* ldrsh) {
    return ldrsh->op == 0b011110011;
}

static inline uint32_t get_ldrsh_imm_uoff(ldrsh_imm_uoff_t* ldrsh) {
    return ldrsh->imm << 1;
}

static inline bool is_ldrsw_imm_pre(ldrsw_imm_t* ldrsw) {
    return ldrsw->op == 0b10111000100 && ldrsw->op2 == 0b11;
}

static inline bool is_ldrsw_imm_post(ldrsw_imm_t* ldrsw) {
    return ldrsw->op == 0b10111000100 && ldrsw->op2 == 0b01;
}

static inline bool is_ldrsw_imm_uoff(ldrsw_imm_uoff_t* ldrsw) {
    return ldrsw->op == 0b1011100110;
}

static inline uint32_t get_ldrsw_imm_uoff(ldrsw_imm_uoff_t* ldrsw) {
    return ldrsw->imm << 2;
}

static inline bool is_strb_imm_pre(strb_imm_t* strb) {
    return strb->op == 0b00111000000 && strb->op2 == 0b11;
}

static inline bool is_strb_imm_post(strb_imm_t* strb) {
    return strb->op == 0b00111000000 && strb->op2 == 0b01;
}

static inline bool is_strb_imm_uoff(strb_imm_uoff_t* strb) {
    return strb->op == 0b0011100100;
}

static inline uint32_t get_strb_imm_uoff(strb_imm_uoff_t* strb) {
    return strb->imm;
}

static inline bool is_strh_imm_pre(strh_imm_t* strh) {
    return strh->op == 0b01111000000 && strh->op2 == 0b11;
}

static inline bool is_strh_imm_post(strh_imm_t* strh) {
    return strh->op == 0b01111000000 && strh->op2 == 0b01;
}

static inline bool is_strh_imm_uoff(strh_imm_uoff_t* strh) {
    return strh->op == 0b0111100100;
}

static inline uint32_t get_strh_imm_uoff(strh_imm_uoff_t* strh) {
    return strh->imm << 1;
}

static inline bool is_ldr_fp_uoff(ldr_fp_uoff_t* ldr) {
    return ldr->op1 == 0b111101 && ldr->op2 == 0b1;
}

static inline bool is_str_fp_uoff(str_fp_uoff_t* str) {
    return str->op1 == 0b111101 && str->op2 == 0b0;
}

static inline uint32_t get_fp_uoff_size(ldr_fp_uoff_t* ldr) {
    return (ldr->opc << 2) | ldr->size;
}

static inline uint32_t get_fp_uoff(ldr_fp_uoff_t* ldr) {
    return ldr->imm << get_fp_uoff_size(ldr);
}

static inline bool is_ldur_fp(ldur_fp_t* ldur) {
    return ldur->op1 == 0b111100 && ldur->op2 == 0b10 && ldur->op3 == 0b00;
}

static inline bool is_stur_fp(stur_fp_t* stur) {
    return stur->op1 == 0b111100 && stur->op2 == 0b00 && stur->op3 == 0b00;
}

static inline uint32_t get_ldur_stur_fp_size(stur_fp_t* ldur) {
    return (ldur->opc << 2) | ldur->size;
}

static inline int64_t get_ldur_stur_fp_off(stur_fp_t* ldur) {
    return (((int64_t)ldur->imm) << (64 - 9)) >> (64 - 9);
}

static inline bool is_ldp_fp_pre(ldp_fp_t* ldp) {
    return ldp->op == 0b10110111;
}

static inline bool is_ldp_fp_post(ldp_fp_t* ldp) {
    return ldp->op == 0b10110011;
}

static inline bool is_ldp_fp_uoff(ldp_fp_t* ldp) {
    return ldp->op == 0b10110101;
}

static inline bool is_stp_fp_pre(stp_fp_t* stp) {
    return stp->op == 0b10110110;
}

static inline bool is_stp_fp_post(stp_fp_t* stp) {
    return stp->op == 0b10110010;
}

static inline bool is_stp_fp_uoff(stp_fp_t* stp) {
    return stp->op == 0b10110100;
}

static inline int64_t get_ldp_stp_fp_off(ldp_fp_t* ldp) {
    return (((int64_t)ldp->imm) << (64 - 7)) >> (64 - 9 - ldp->opc);
}

static inline bool is_cmp_imm(cmp_imm_t* cmp) {
    return cmp->op == 0b1110001 && cmp->Rd == 0b11111;
}

static inline bool is_cmp_reg(cmp_reg_t* cmp) {
    return cmp->op == 0b1101011 && cmp->z == 0 && cmp->Rd == 0b11111;
}

static inline bool is_cmp_ext(cmp_ext_t* cmp) {
    return cmp->op == 0b1101011001 && cmp->Rd == 0b11111;
}

static inline bool is_cmn_imm(cmn_imm_t* cmn) {
    return cmn->op == 0b0110001 && cmn->Rd == 0b11111;
}

static inline bool is_cmn_reg(cmn_reg_t* cmn) {
    return cmn->op == 0b0101011 && cmn->z == 0 && cmn->Rd == 0b11111;
}

static inline bool is_cmn_ext(cmn_ext_t* cmn) {
    return cmn->op == 0b0101011001 && cmn->Rd == 0b11111;
}

static inline bool is_br(br_t* br) {
    return br->op1 == 0x3587c0 && br->op2 == 0;
}

static inline bool is_blr(br_t* br) {
    return br->op1 == 0x358fc0 && br->op2 == 0;
}

static inline bool is_bl(bl_t* bl) {
    return bl->op == 0x5 && bl->mode == 1;
}

static inline bool is_b(bl_t* b) {
    return b->op == 0x5 && b->mode == 0;
}

static inline bool is_blraa(blraa_t* blraa) {
    return blraa->op == 0b1101011 && blraa->op2 == 0b01111110000 && blraa->Z == 0b1 &&
           blraa->A == 0b1 && blraa->M == 0;
}

static inline bool is_blraaz(blraaz_t* blraaz) {
    return blraaz->op == 0b1101011 && blraaz->op2 == 0b001111110000 && blraaz->Z == 0b0 &&
           blraaz->A == 0b1 && blraaz->M == 0 && blraaz->Rm == 0b11111;
}

static inline bool is_blrab(blrab_t* blrab) {
    return blrab->op == 0b1101011 && blrab->op2 == 0b001111110000 && blrab->Z == 0b1 &&
           blrab->A == 0b1 && blrab->M == 0b1;
}

static inline bool is_blrabz(blrabz_t* blrabz) {
    return blrabz->op == 0b1101011 && blrabz->op2 == 0b001111110000 && blrabz->Z == 0b1 &&
           blrabz->A == 0b1 && blrabz->M == 0b1 && blrabz->Rm == 0b11111;
}

static inline bool is_b_cond(b_cond_t* b_cond) {
    return b_cond->op1 == 0b01010100 && b_cond->op2 == 0b0;
}

static inline int64_t get_bl_off(bl_t* bl) {
    return (((int64_t)bl->imm) << (64 - 26)) >> (64 - 26 - 2);
}

static inline bool is_brk(brk_t* brk) {
    return brk->op == 0b11010100001 && brk->Z == 0b00000;
}

static inline bool is_cbz(cbz_t* cbz) {
    return cbz->op == 0x34;
}

static inline bool is_cbnz(cbz_t* cbz) {
    return cbz->op == 0x35;
}

static inline int64_t get_cbz_off(cbz_t* cbz) {
    return (((int64_t)cbz->imm) << (64 - 19)) >> (64 - 19 - 2);
}

static inline bool is_tbz(tbz_t* tbz) {
    return tbz->op == 0x36;
}

static inline bool is_tbnz(tbz_t* tbz) {
    return tbz->op == 0x37;
}

static inline uint32_t get_tbz_bit(tbz_t* tbz) {
    return (tbz->sf << 5) | tbz->bit;
}

static inline int64_t get_tbz_off(tbz_t* tbz) {
    return (((int64_t)tbz->imm) << (64 - 14)) >> (64 - 19 - 2);
}

static inline bool is_mov(mov_t* mov) {
    return mov->op1 == 0x150 && mov->op2 == 0x1f;
}

static inline bool is_movz(movz_t* movz) {
    return movz->op == 0xa5;
}

static inline bool is_movk(movk_t* movk) {
    return movk->op == 0xe5;
}

static inline uint64_t get_movzk_imm(movz_t* movz) {
    return movz->imm << (movz->hw << 4);
}

static inline bool is_movn(movn_t* movn) {
    return movn->op == 0x25;
}

static inline int64_t get_movn_imm(movn_t* movn) {
    return ~get_movzk_imm(movn);
}

static inline bool is_movi(movi_t* movi) {
    return movi->op == 0b01100100 && movi->Rn == 0b11111;
}

static inline bool is_mrs(mrs_t* mrs) {
    return mrs->mrs == 0b110101010011;
}

static inline bool is_msr_imm(msr_imm_t* msr) {
    return msr->msr == 0b1101010100000 && msr->msr2 == 0b0100 && msr->msr3 == 0b11111;
}

static inline bool is_msr_reg(msr_reg_t* msr) {
    return msr->msr == 0b110101010001;
}

static inline bool is_ldraa(ldraa_t* ldraa) {
    return ldraa->op == 0b11111000 && ldraa->M == 0b0 && ldraa->o1 == 0b1 && ldraa->o2 == 0b1;
}

static inline bool is_ldrab(ldrab_t* ldrab) {
    return ldrab->op == 0b11111000 && ldrab->M == 0b1 && ldrab->o1 == 0b1 && ldrab->o2 == 0b1;
}

static inline bool is_pac(pac_t* pac) {
    return pac->op1 == 0x36b04 && pac->op2 == 0;
}

static inline bool is_pacda(pacda_t* pacda) {
    return pacda->op == 0b110110101100000100 && pacda->Z == 0b0 && pacda->op2 == 0b010;
}

static inline bool is_pacdza(pacdza_t* pacdza) {
    return pacdza->op == 0b110110101100000100 && pacdza->Z == 0b1 && pacdza->op2 == 0b1 &&
           pacdza->Rn == 0b11111;
}

static inline bool is_pacdb(pacdb_t* pacdb) {
    return pacdb->op == 0b110110101100000100 && pacdb->Z == 0b0 && pacdb->op2 == 0b011;
}

static inline bool is_pacdzb(pacdzb_t* pacdzb) {
    return pacdzb->op == 0b11011010110000100 && pacdzb->Z == 0b1 && pacdzb->op2 == 0b011 &&
           pacdzb->Rn == 0b11111;
}

static inline bool is_pacsys(pacsys_t* pacsys) {
    return pacsys->op1 == 0x3540c8 && pacsys->op2 == 0x2 && pacsys->op3 == 0x1f &&
           (pacsys->x == 0 || pacsys->C == 1);
}

static inline bool is_pacga(pacga_t* pacga) {
    return pacga->op1 == 0x4d6 && pacga->op2 == 0xc;
}

static inline bool is_pacia(pacia_t* pacia) {
    return pacia->op == 0b110110101100000100 && pacia->Z == 0b0 && pacia->op2 == 0b000;
}

static inline bool is_paciza(paciza_t* paciza) {
    return paciza->op == 0b110110101100000100 && paciza->Z == 0b1 && paciza->op2 == 0b000 &&
           paciza->Rn == 0b11111;
}

static inline bool is_pacia1716(pacia1716_t* pacia1716) {
    return pacia1716->op == 0b11010101000000110010 && pacia1716->op2 == 0b000 &&
           pacia1716->CRm == 0b0001 && pacia1716->CRd == 0b11111;
}

static inline bool is_paciasp(paciasp_t* paciasp) {
    return paciasp->op == 0b11010101000000110010 && paciasp->op2 == 0b001 &&
           paciasp->CRm == 0b0011 && paciasp->CRd == 0b11111;
}

static inline bool is_paciaz(paciaz_t* paciaz) {
    return paciaz->op == 0b110101010000001100010 && paciaz->op2 == 0b000 && paciaz->CRm == 0b0011 &&
           paciaz->CRd == 0b11111;
}

static inline bool is_pacib(pacib_t* pacib) {
    return pacib->op == 0b110110101100000100 && pacib->Z == 0b0 && pacib->op2 == 0b001;
}

static inline bool is_pacizb(pacizb_t* pacizb) {
    return pacizb->op == 0b110110101100000100 && pacizb->Z == 0b1 && pacizb->op2 == 0b001 &&
           pacizb->Rn == 0b11111;
}

static inline bool is_pacib1716(pacib1716_t* pacib1716) {
    return pacib1716->op == 0b11010101000000110010 && pacib1716->op2 == 0b010 &&
           pacib1716->CRm == 0b0001 && pacib1716->CRd == 0b11111;
}

static inline bool is_pacibsp(pacibsp_t* pacibsp) {
    return pacibsp->op == 0b11010101000000110010 && pacibsp->op2 == 0b011 &&
           pacibsp->CRm == 0b0011 && pacibsp->CRd == 0b11111;
}

static inline bool is_pacibz(pacibz_t* pacibz) {
    return pacibz->op == 0b110101010000001100010 && pacibz->op2 == 0b000 && pacibz->CRm == 0b0011 &&
           pacibz->CRd == 0b11111;
}

static inline bool is_xpacd(xpacd_t* xpacd) {
    return xpacd->op == 0b110110101100000101000 && xpacd->D == 0b1 && xpacd->Rn == 0b11111;
}

static inline bool is_xpaci(xpaci_t* xpaci) {
    return xpaci->op == 0b110110101100000101000 && xpaci->D == 0b0 && xpaci->Rn == 0b11111;
}

static inline bool is_xpaclri(xpaclri_t* xpaclri) {
    return *((uint32_t*)xpaclri) == 0xd50320ff;
}

static inline bool is_autda(autda_t* autda) {
    return autda->op == 0b110110101100000100 && autda->Z == 0b0 && autda->op2 == 0b110;
}

static inline bool is_autdza(autdza_t* autdza) {
    return autdza->op == 0b110110101100000100 && autdza->Z == 0b1 && autdza->op2 == 0b110 &&
           autdza->Rn == 0b11111;
}

static inline bool is_autdb(autdb_t* autdb) {
    return autdb->op == 0b110110101100000100 && autdb->Z == 0b0 && autdb->op2 == 0b111;
}

static inline bool is_autdzb(autdzb_t* autdzb) {
    return autdzb->op == 0b110110101100000100 && autdzb->Z == 0b1 && autdzb->op2 == 0b111 &&
           autdzb->Rn == 0b11111;
}

static inline bool is_autia(autia_t* autia) {
    return autia->op == 0b110110101100000100 && autia->op2 == 0b100 && autia->Z == 0b0;
}

static inline bool is_autiza(autiza_t* autiza) {
    return autiza->op == 0b110110101100000100 && autiza->op2 == 0b100 && autiza->Z == 0b1 &&
           autiza->Rn == 0b11111;
}

static inline bool is_autiaz(autiaz_t* autiaz) {
    return autiaz->op == 0b11010101000000110010 && autiaz->CRm == 0b0011 && autiaz->op2 == 0b100 &&
           autiaz->CRd == 0b11111;
}

static inline bool is_autia1716(autia1716_t* autiza1716) {
    return autiza1716->op == 0b11010101000000110010 && autiza1716->CRm == 0001 &&
           autiza1716->op2 == 0b100 && autiza1716->CRd == 0b11111;
}

static inline bool is_autiasp(autiasp_t* autiasp) {
    return autiasp->op == 0b11010101000000110010 && autiasp->CRm == 0b0011 &&
           autiasp->op2 == 0b101 && autiasp->CRd == 0b11111;
}

static inline bool is_autib(autib_t* autib) {
    return autib->op == 0b110110101100000100 && autib->Z == 0b0 && autib->op2 == 0b101;
}

static inline bool is_autizb(autizb_t* autizb) {
    return autizb->op == 0b110110101100000100 && autizb->Z == 0b1 && autizb->op2 == 0b101 &&
           autizb->Rn == 0b11111;
}

static inline bool is_autib1716(autib1716_t* autib1716) {
    return autib1716->op == 0b11010101000000110010 && autib1716->CRm == 0b0001 &&
           autib1716->op2 == 0b110 && autib1716->CRd == 0b11111;
}

static inline bool is_autibsp(autibsp_t* autibsp) {
    return autibsp->op == 0b11010101000000110010 && autibsp->CRm == 0b0011 &&
           autibsp->op2 == 0b111 && autibsp->CRd == 0b11111;
}

static inline bool is_autibz(autibz_t* autibz) {
    return autibz->op == 0b11010101000000110010 && autibz->CRm == 0b0011 && autibz->op2 == 0b110 &&
           autibz->CRd == 0b11111;
}

static inline bool is_aut(pac_t* pac) {
    return pac->op1 == 0x36b04 && pac->op2 == 1;
}

static inline bool is_autsys(pacsys_t* pacsys) {
    return pacsys->op1 == 0x3540c8 && pacsys->op2 == 0x3 && pacsys->op3 == 0x1f &&
           (pacsys->x == 0 || pacsys->C == 1);
}

static inline bool is_bti(bti_t* bti) {
    return bti->op == 0b11010101000000110010 && bti->CRm == 0b0100 && (bti->op2 & 0b001) == 0b0 &&
           bti->o == 0b11111;
}

static inline bool is_nop(nop_t* nop) {
    return *nop == 0xd503201f;
}

static inline bool is_ret(ret_t* ret) {
    ret_t r = *ret;
    return r == 0xd65f03c0;
}

static inline bool is_retaa(retaa_t* retaa) {
    return retaa->op == 0b11010110010111110000 && retaa->Rm == 0b11111 && retaa->Rn == 0b11111 &&
           retaa->M == 0 && retaa->A == 1;
}

static inline bool is_retab(retab_t* retab) {
    return retab->op == 0b11010110010111110000 && retab->Rm == 0b11111 && retab->Rn == 0b11111 &&
           retab->M == 1 && retab->A == 1;
}

static inline bool is_and_imm(and_imm_t* and_) {
    return and_->op == 0b00100100;
}

static inline bool is_and_shift(and_shift_t* and_) {
    return and_->op == 0b0001010 && and_->N == 0;
}

static inline bool is_ands_imm(ands_imm_t* ands) {
    return ands->op == 0b11100100;
}

static inline bool is_ands_shift(ands_shift_t* ands) {
    return ands->op == 0b1101010 && ands->N == 0;
}

static inline bool is_tst_imm(tst_imm_t* tst) {
    return tst->op == 0b11100100 && tst->Rd == 0b11111;
}

static inline bool is_tst_shift(tst_shift_t* tst) {
    return tst->op == 0b1101010 && tst->N == 0 && tst->Rd == 0b11111;
}

static inline bool is_orr(orr_t* orr) {
    return orr->op == 0x64;
}

static inline bool is_eor(eor_t* eor) {
    return eor->op == 0xa4;
}

static inline bool is_orr_shift(orr_shift_t* orr) {
    return orr->op == 0b0101010 && orr->N == 0;
}

static inline bool is_orn_shift(orn_shift_t* orn) {
    return orn->op == 0b0101010 && orn->N == 1;
}

static inline bool is_eor_shift(eor_shift_t* eor) {
    return eor->op == 0b1001010 && eor->N == 0;
}

static inline bool is_eon_shift(eon_shift_t* eon) {
    return eon->op == 0b1001010 && eon->N == 1;
}

static inline bool is_mvn(mvn_t* mvn) {
    return mvn->op == 0b0101010 && mvn->N == 1 && mvn->Rd == 0b11111;
}

static inline bool is_bic(bic_t* bic) {
    return bic->op == 0b0001010 && bic->N == 1;
}

static inline bool is_bics(bic_t* bic) {
    return bic->op == 0b1101010 && bic->N == 1;
}

static inline bool is_fadd_scalar(fadd_scalar_t* fadd) {
    return fadd->op == 0b00011110 && fadd->o == 0b1 && fadd->op2 == 0b001010;
}

static inline bool is_fsub_scalar(fsub_scalar_t* fsub) {
    return fsub->op == 0b00011110 && fsub->o == 0b1 && fsub->op2 == 0b001110;
}

static inline bool is_fmul_scalar(fmul_scalar_t* fmul) {
    return fmul->op == 0b00011110 && fmul->o == 0b1 && fmul->op2 == 0b000010;
}

static inline bool is_fdiv_scalar(fdiv_scalar_t* fdiv) {
    return fdiv->op == 0b00011110 && fdiv->o == 0b1 && fdiv->op2 == 0b000110;
}

static inline bool is_fcmp_scalar(fcmp_scalar_t* fcmp) {
    return fcmp->op == 0b00011110 && fcmp->o == 0b1 && fcmp->op2 == 0b001000 &&
           (fcmp->Rd & 0b111) == 0b000;
}

static inline bool is_fabs_scalar(fabs_scalar_t* fabs) {
    return fabs->op == 0b00011110 && fabs->o == 0b1 && fabs->Rm == 0b00000 && fabs->op2 == 0b110000;
}

static inline bool is_fcsel_scalar(fcsel_scalar_t* fcsel) {
    return fcsel->op == 0b00011110 && fcsel->o == 0b1 && (fcsel->op2 & 0b11) == 0b11;
}

static inline bool is_fadd_vector(fadd_vector_t* fadd) {
    return fadd->Z == 0b0 && (fadd->op & 0b111111100) == 0b00111000 &&
           (fadd->op2 == 0b000101 || fadd->op2 == 0b110101);
}

static inline bool is_fsub_vector(fsub_vector_t* fsub) {
    return fsub->Z == 0b0 && (fsub->op & 0b111111100) == 0b001110100 &&
           (fsub->op2 == 0b000101 || fsub->op2 == 0b110101);
}

static inline bool is_fmul_vector(fmul_vector_t* fmul) {
    return fmul->Z == 0b0 && (fmul->op & 0b111111100) == 0b101110000 &&
           (fmul->op2 == 0b000111 || fmul->op2 == 0b110111);
}

static inline bool is_fdiv_vector(fdiv_vector_t* fdiv) {
    return fdiv->Z == 0b0 && (fdiv->op & 0b111111100) == 0b101110000 &&
           (fdiv->op2 == 0b001111 || fdiv->op2 == 0b111111);
}

static inline bool is_fmov(fmov_t* fmov) {
    return fmov->op == 0b0011110 && fmov->o == 0b1 && fmov->op2 == 0b000000;
}

static inline bool is_fmov_reg(fmov_reg_t* fmov) {
    return fmov->op == 0b00011110 && fmov->op2 == 0b100000010000;
}

static inline bool is_fmov_scalar(fmov_scalar_t* fmov) {
    return fmov->op == 0b00011110 && fmov->o == 0b1 && fmov->op2 == 0b10000000;
}

static inline bool is_fmov_vector(fmov_vector_t* fmov) {
    return fmov->Z == 0b0 && fmov->op == 0b0011110000 && fmov->op2 == 0b111111;
}

static inline bool is_fcvtzs_scalar(fcvtzs_scalar_t* fcvtzs) {
    return fcvtzs->op == 0b0011110 && fcvtzs->o == 0b1 && fcvtzs->rmode == 0b11 &&
           fcvtzs->opcode == 0b000 && fcvtzs->op2 == 0b000000;
}

static inline bool is_fcvtzs_fixed_scalar(fcvtzs_scalar_t* fcvtzs) {
    return fcvtzs->op == 0b0011110 && fcvtzs->o == 0b0 && fcvtzs->rmode == 0b11 &&
           fcvtzs->opcode == 0b000;
}

static inline bool is_str_simd_fp_imm_pre(str_simd_fp_imm_t* str) {
    return str->op == 0b111100 && (str->opc & 0b011) == 0b000 && str->op2 == 0b11;
}

static inline bool is_str_simd_fp_imm_post(str_simd_fp_imm_t* str) {
    return str->op == 0b111100 && (str->opc & 0b011) == 0b000 && str->op2 == 0b01;
}

static inline bool is_str_simd_fp_imm_uoff(str_simd_fp_imm_uoff_t* str) {
    return str->op == 0b111101 && (str->opc & 0b1) == 0b0;
}

static inline bool is_str_simd_fp_reg(str_simd_fp_reg_t* str) {
    return str->op == 0b111100 && (str->opc & 0b011) == 0b001 && str->op2 == 0b11;
}

static inline bool is_stp_simd_fp_pre(stp_simd_fp_t* stp) {
    return stp->op == 0b10110110;
}

static inline bool is_stp_simd_fp_soff(stp_simd_fp_t* stp) {
    return stp->op == 0b10110100;
}

static inline bool is_stp_simd_fp_post(stp_simd_fp_t* stp) {
    return stp->op == 0b10110010;
}

static inline bool is_ldr_simd_fp_imm_pre(ldr_simd_fp_imm_t* ldr) {
    return ldr->op == 0b111100 && (ldr->opc & 0b011) == 0b010 && ldr->op2 == 0b01;
}

static inline bool is_ldr_simd_fp_imm_post(ldr_simd_fp_imm_t* ldr) {
    return ldr->op == 0b111100 && (ldr->opc & 0b011) == 0b010 && ldr->op2 == 0b01;
}

static inline bool is_ldr_simd_fp_imm_uoff(ldr_simd_fp_imm_uoff_t* ldr) {
    return ldr->op == 0b111101 && (ldr->opc & 0b1) == 0b1;
}

static inline bool is_ldr_simd_fp_reg(ldr_simd_fp_reg_t* ldr) {
    return ldr->op == 0b111100 && (ldr->opc & 0b011) == 0b11 && ldr->op2 == 0b10;
}

static inline bool is_ldp_simd_fp_pre(ldp_simd_fp_t* ldp) {
    return ldp->op == 0b10110111;
}

static inline bool is_ldp_simd_fp_soff(ldp_simd_fp_t* ldp) {
    return ldp->op == 0b10110101;
}

static inline bool is_ldp_simd_fp_post(ldp_simd_fp_t* ldp) {
    return ldp->op == 0b10110011;
}

static inline bool is_and_vector(and_vector_t* and_) {
    return and_->Z == 0b0 && and_->op == 0b001110001 && and_->op2 == 0b000111;
}

static inline bool is_eor_vector(eor_vector_t* eor) {
    return eor->Z == 0b0 && eor->op == 0b101110001 && eor->op2 == 0b000111;
}

static inline bool is_orr_vector(orr_vector_t* orr) {
    return orr->Z == 0b0 && orr->op == 0b001110101 && orr->op2 == 0b000111;
}

static inline bool is_orn_vector(orn_vector_t* orn) {
    return orn->Z == 0b0 && orn->op == 0b001110111 && orn->op2 == 0b000111;
}

static inline bool is_bic_vector(bic_vector_t* bic) {
    return bic->Z == 0b0 && bic->op == 0b001110011 && bic->op2 == 0b000111;
}

static inline bool is_bit_vector(bit_vector_t* bit) {
    return bit->Z == 0b0 && bit->op == 0b101110101 && bit->op2 == 0b000111;
}

static inline bool is_bif_vector(bif_vector_t* bif) {
    return bif->Z == 0b0 && bif->op == 0b101110111 && bif->op2 == 0b000111;
}

static inline bool is_bsl_vector(bsl_vector_t* bsl) {
    return bsl->Z == 0b0 && bsl->op == 0b101110011 && bsl->op2 == 0b000111;
}

static inline bool is_xar_vector(xar_vector_t* xar) {
    return xar->op == 0b11001110100;
}

static inline bool is_fcvtzs_vector(fcvtzs_vector_t* fcvtzs) {
    bool cond1 = fcvtzs->Z == 0b0 && fcvtzs->Q == 0b1 && fcvtzs->op == 0b0111101 &&
                 fcvtzs->sz == 0b1 && fcvtzs->op2 == 0b111001101110;
    bool cond2 = fcvtzs->Z == 0b0 && fcvtzs->Q == 0b1 && fcvtzs->op == 0b0111101 &&
                 fcvtzs->op2 == 0b100001101110;
    bool cond3 = fcvtzs->Z == 0b0 && fcvtzs->op == 0b0011101 && fcvtzs->sz == 0b1 &&
                 fcvtzs->op2 == 0b1111001101110;
    bool cond4 = fcvtzs->Z == 0b0 && fcvtzs->op == 0b0011101 && fcvtzs->op2 == 0b100001101110;

    return cond1 || cond2 || cond3 || cond4;
}

static inline bool is_fcvtzs_fixed_vector(fcvtzs_fixed_vector_t* fcvtzs) {
    return ((fcvtzs->Q == 0b1 && fcvtzs->op == 0b0111110) || fcvtzs->op == 0b0011110) &&
           fcvtzs->immh != 0b0000 && fcvtzs->op2 == 0b111111;
}

static inline bool is_dmb(dmb_t* dmb) {
    return dmb->op == 0b11010101000000110011 && dmb->op2 == 0b10111111;
}

static inline bool is_dsb(dsb_t* dsb) {
    return dsb->op == 0b11010101000000110011 && dsb->op2 == 0b10011111 && dsb->CRm != 0x00;
}

static inline bool is_isb(isb_t* isb) {
    return isb->op == 0b11010101000000110011 && isb->op2 == 0b11011111;
}

static inline bool is_esb(esb_t* esb) {
    return esb->op == 0b11010101000000110010 && esb->CRm == 0b0010 && esb->op2 == 0b00011111;
}

static inline bool is_sb(sb_t* sb) {
    return sb->op == 0b11010101000000110011 && sb->op2 == 0b11111111 && sb->CRm == 0b0000;
}

static inline bool is_csdb(csdb_t* csdb) {
    return csdb->op == 0b11010101000000110010 && csdb->CRm == 0b0010 && csdb->op2 == 0b10011111;
}

typedef uint32_t wfi_t;

static inline bool is_wfi(wfi_t* wfi) {
    return *(uint32_t*)wfi == 0xd503207f;
}

static inline bool is_wfit(wfit_t* wfit) {
    return wfit->op == 0x6a81881;
}

static inline bool is_sys(sys_t* sys) {
    return sys->op == 0b1101010100001;
}

static inline bool is_tlbi(tlbi_t* tlbi) {
    return tlbi->op == 0b1101010100001 && tlbi->CRn == 0b1000;
}

static inline bool is_svc(svc_t* svc) {
    return svc->op == 0b11010100000 && svc->op2 == 0b00001;
}

static inline bool is_hvc(hvc_t* hvc) {
    return hvc->op == 0b11010100000 && hvc->op2 == 0b00010;
}

static inline bool is_smc(smc_t* smc) {
    return smc->op == 0b11010100000 & smc->op2 == 0b00011;
}

}; // namespace arm64
} // namespace arch
