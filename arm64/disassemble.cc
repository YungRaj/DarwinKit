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

#include <arm64/isa_arm64.h>

#include "disassemble.h"
#include "macho.h"

using namespace arch::arm64;
using namespace arch::arm64::disassembler;

extern "C" {
static inline int hibit_pos(uintmax_t x) {
    uint32_t msb = -1;

    while (x > 0) {
        x >>= 1;
        msb += 1;
    }
    return msb;
}

// logical shift right
#define lsr(x, shift) ((x) >> (shift))

// logical shift left
#define lsl(x, shift, width) (((x) << (shift)) & (((uint64_t)2 << ((width) - 1)) - 1))

// rotate right
#define ror(x, shift, width)                                                                       \
    ({                                                                                             \
        __typeof__(x) _x = (x);                                                                    \
        uint32_t _shift = (shift);                                                                 \
        uint32_t _width = (width);                                                                 \
        uint32_t _s = _shift % _width;                                                             \
        __typeof__(x) _lsl = lsl(_x, _width - _s, _width);                                         \
        __typeof__(x) _lsr = lsr(_x, _s);                                                          \
        _lsl | _lsr;                                                                               \
    })

static inline uint64_t ones(uint32_t n) {
    uint32_t bits = sizeof(uint64_t) * 8;
    return (n == bits ? (uint64_t)(-1) : ((uint64_t)1 << n) - 1);
}

static inline uint64_t lobits(uint64_t x, unsigned n) {
    return (x & ones(n));
}

#define test(x, n) testbit(x, n)

uint64_t replicate(uint64_t x, unsigned m, unsigned n) {
    uint64_t r = 0;
    for (unsigned c = n / m; c > 0; c--) {
        r = (r << m) | x;
    }
    return r;
}

char* shift(aarch64_shift s) {
    switch (s) {
    case AARCH64_SHIFT_LSL:
        return "LSL";
    case AARCH64_SHIFT_LSR:
        return "LSR";
    case AARCH64_SHIFT_ASR:
        return "ASR";
    case AARCH64_SHIFT_ROR:
        return "ROR";
    }
    return "???";
}

char* ext(aarch64_extend e) {
    switch (e) {
    case AARCH64_EXTEND_UXTB:
        return "UXTB";
    case AARCH64_EXTEND_UXTH:
        return "UXTH";
    case AARCH64_EXTEND_UXTW:
        return "UXTW";
    case AARCH64_EXTEND_UXTX:
        return "UXTX";
    case AARCH64_EXTEND_SXTB:
        return "SXTB";
    case AARCH64_EXTEND_SXTH:
        return "SXTH";
    case AARCH64_EXTEND_SXTW:
        return "SXTW";
    case AARCH64_EXTEND_SXTX:
        return "SXTX";
    default:
        return shift(AARCH64_SHIFT_LSL);
    };
}

char* reg(uint8_t reg, uint8_t sf) {
    if (sf) {
        switch (reg) {
        case 0:
            return "X0";
        case 1:
            return "X1";
        case 2:
            return "X2";
        case 3:
            return "X3";
        case 4:
            return "X4";
        case 5:
            return "X5";
        case 6:
            return "X6";
        case 7:
            return "X7";
        case 8:
            return "X8";
        case 9:
            return "X9";
        case 10:
            return "X10";
        case 11:
            return "X11";
        case 12:
            return "X12";
        case 13:
            return "X13";
        case 14:
            return "X14";
        case 15:
            return "X15";
        case 16:
            return "X16";
        case 17:
            return "X17";
        case 18:
            return "X18";
        case 19:
            return "X19";
        case 20:
            return "X20";
        case 21:
            return "X21";
        case 22:
            return "X22";
        case 23:
            return "X23";
        case 24:
            return "X24";
        case 25:
            return "X25";
        case 26:
            return "X26";
        case 27:
            return "X27";
        case 28:
            return "X28";
        case 29:
            return "X29";
        case 30:
            return "X30";
        case 31:
            return "SP";
        }
    } else {
        switch (reg) {
        case 0:
            return "W0";
        case 1:
            return "W1";
        case 2:
            return "W2";
        case 3:
            return "W3";
        case 4:
            return "W4";
        case 5:
            return "W5";
        case 6:
            return "W6";
        case 7:
            return "W7";
        case 8:
            return "W8";
        case 9:
            return "W9";
        case 10:
            return "W10";
        case 11:
            return "W11";
        case 12:
            return "W12";
        case 13:
            return "W13";
        case 14:
            return "W14";
        case 15:
            return "W15";
        case 16:
            return "W16";
        case 17:
            return "W17";
        case 18:
            return "W18";
        case 19:
            return "W19";
        case 20:
            return "W20";
        case 21:
            return "W21";
        case 22:
            return "W22";
        case 23:
            return "W23";
        case 24:
            return "W24";
        case 25:
            return "W25";
        case 26:
            return "W26";
        case 27:
            return "W27";
        case 28:
            return "W28";
        case 29:
            return "W29";
        case 30:
            return "W30";
        case 31:
            return "WSP";
        }
    }

    return "???";
}

char* condition(uint8_t c) {
    char* cond = nullptr;
    switch (c & 0b01111) {
    case 0b0000:
        cond = "EQ";
        break;
    case 0b0001:
        cond = "NE";
        break;
    case 0b0010:
        cond = "CS";
        break;
    case 0b0011:
        cond = "CC";
        break;
    case 0b0100:
        cond = "MI";
        break;
    case 0b0101:
        cond = "PL";
        break;
    case 0b0110:
        cond = "VS";
        break;
    case 0b0111:
        cond = "VC";
        break;
    case 0b1000:
        cond = "HI";
        break;
    case 0b1001:
        cond = "LS";
        break;
    case 0b1010:
        cond = "GE";
        break;
    case 0b1011:
        cond = "LT";
        break;
    case 0b1100:
        cond = "GT";
        break;
    case 0b1101:
        cond = "LE";
        break;
    case 0b1110:
    case 0b1111:
        cond = "AL";
        break;
    }

    return cond;
}

char* tlbi_op(uint8_t op1, uint8_t CRm, uint8_t op2) {
    if (op1 == 0b000) {
        if (CRm == 0b001) {
            if (op2 == 0b000) {
                return "VMALLE1OS";
            }
            if (op2 == 0b001) {
                return "VAE1OS";
            }
            if (op2 == 0b010) {
                return "ASIDE1OS";
            }
            if (op2 == 0b011) {
                return "VAAE1OS";
            }
            if (op2 == 0b101) {
                return "VALE1OS";
            }
            if (op2 == 0b111) {
                return "VAALE1OS";
            } else {
                return "???";
            }
        } else if (CRm == 0b0010) {
            if (op2 == 0b001) {
                return "RVAE1IS";
            }
            if (op2 == 0b011) {
                return "RVAAE1IS";
            }
            if (op2 == 0b101) {
                return "RVALE1IS";
            }
            if (op2 == 0b111) {
                return "RVAALE1IS";
            } else {
                return "???";
            }
        } else if (CRm == 0b0011) {
            if (op2 == 0b000) {
                return "VMALLE1IS";
            }
            if (op2 == 0b001) {
                return "VAE1IS";
            }
            if (op2 == 0b010) {
                return "ASIDE1IS";
            }
            if (op2 == 0b011) {
                return "VAAE1IS";
            }
            if (op2 == 0b101) {
                return "VALE1IS";
            }
            if (op2 == 0b111) {
                return "VAALE1IS";
            } else {
                return "???";
            }
        } else if (CRm == 0b0101) {
            if (op2 == 0b001) {
                return "RVAE1OS";
            }
            if (op2 == 0b011) {
                return "RVAAE1OS";
            }
            if (op2 == 0b101) {
                return "RVALE1OS";
            }
            if (op2 == 0b111) {
                return "RVAALE1OS";
            } else {
                return "???";
            }
        } else if (CRm == 0b0110) {
            if (op2 == 0b001) {
                return "RVAE1";
            }
            if (op2 == 0b011) {
                return "RVAAE1";
            }
            if (op2 == 0b101) {
                return "RVALE1";
            }
            if (op2 == 0b111) {
                return "RVAALE1";
            } else {
                return "???";
            }
        } else if (CRm == 0b0111) {
            if (op2 == 0b000) {
                return "VMALLE1";
            }
            if (op2 == 0b001) {
                return "VAE1";
            }
            if (op2 == 0b010) {
                return "ASIDE1";
            }
            if (op2 == 0b011) {
                return "VAAE1";
            }
            if (op2 == 0b101) {
                return "VALE1";
            }
            if (op2 == 0b111) {
                return "VAALE1";
            } else {
                return "???";
            }
        }
    } else if (op1 == 0b100) {
        if (CRm == 0b0000) {
            if (op2 == 0b001) {
                return "IPAS2E1IS";
            } else if (op2 == 0b010) {
                return "RIPAS2E1IS";
            } else if (op2 == 0b101) {
                return "IPAS2LE1IS";
            } else if (op2 == 0b110) {
                return "RIPAS2LE1IS";
            } else {
                return "???";
            }
        } else if (CRm == 0b0001) {
            if (op2 == 0b000) {
                return "ALLE2OS";
            } else if (op2 == 0b001) {
                return "ALLE2OS";
            } else if (op2 == 0b100) {
                return "ALLE1OS";
            } else if (op2 == 0b101) {
                return "VALE2OS";
            } else if (op2 == 0b110) {
                return "VMALLS12E1OS";
            } else {
                return "???";
            }
        } else if (CRm == 0b0010) {
            if (op2 == 0b001) {
                return "RVAE2IS";
            } else if (op2 == 0b101) {
                return "RVALE2IS";
            } else {
                return "???";
            }
        } else if (CRm == 0b0011) {
            if (op2 == 0b000) {
                return "ALLE2IS";
            } else if (op2 == 0b001) {
                return "VAE2IS";
            } else if (op2 == 0b100) {
                return "ALLE1IS";
            } else if (op2 == 0b101) {
                return "VALE2IS";
            } else if (op2 == 0b110) {
                return "VMALLS12E1IS";
            } else {
                return "???";
            }
        } else if (CRm == 0b100) {
            if (op2 == 0b000) {
                return "IPAS2E1OS";
            } else if (op2 == 0b001) {
                return "IPAS2E1";
            } else if (op2 == 0b010) {
                return "RIPAS2E1";
            } else if (op2 == 0b011) {
                return "RIPAS2E1OS";
            } else if (op2 == 0b100) {
                return "IPAS2LE1OS";
            } else if (op2 == 0b101) {
                return "IPAS2LE1";
            } else if (op2 == 0b110) {
                return "RIPAS2LE1";
            } else if (op2 == 0b111) {
                return "RIPAS2LE1OS";
            } else {
                return "???";
            }
        } else if (CRm == 0b0101) {
            if (op2 == 0b001) {
                return "RVAE2OS";
            } else if (op2 == 0b101) {
                return "RVALE2OS";
            } else {
                return "???";
            }
        } else if (CRm == 0b0110) {
            if (op2 == 0b001) {
                return "RVAE2";
            } else if (op2 == 0b101) {
                return "RVALE2";
            } else {
                return "???";
            }
        } else if (CRm == 0b0111) {
            if (op2 == 0b000) {
                return "ALLE2";
            } else if (op2 == 0b001) {
                return "VAE2";
            } else if (op2 == 0b100) {
                return "ALLE1";
            } else if (op2 == 0b101) {
                return "VALE2";
            } else if (op2 == 0b110) {
                return "VMALLS12E1";
            } else {
                return "???";
            }
        }
    } else if (op1 == 0b110) {
        if (CRm == 0b0001) {
            if (op2 == 0b000) {
                return "ALLE3OS";
            } else if (op2 == 0b001) {
                return "VAE3OS";
            } else if (op2 == 0b101) {
                return "VALE3OS";
            } else {
                return "???";
            }
        } else if (CRm == 0b0010) {
            if (op2 == 0b001) {
                return "RVAE3IS";
            } else if (op2 == 0b101) {
                return "RVALE3IS";
            } else {
                return "???";
            }
        } else if (CRm == 0b0011) {
            if (op2 == 0b000) {
                return "ALLE3IS";
            } else if (op2 == 0b001) {
                return "VAE3IS";
            } else if (op2 == 0b101) {
                return "VALE3IS";
            } else {
                return "???";
            }
        } else if (CRm == 0b0101) {
            if (op2 == 0b001) {
                return "RVAE3OS";
            } else if (op2 == 0b101) {
                return "RVALE3OS";
            } else {
                return "???";
            }
        } else if (CRm == 0b0110) {
            if (op2 == 0b001) {
                return "RVAE3";
            } else if (op2 == 0b101) {
                return "RVALE3";
            } else {
                return "???";
            }
        } else if (CRm == 0b0111) {
            if (op2 == 0b000) {
                return "ALLE3";
            } else if (op2 == 0b001) {
                return "VAE3";
            } else if (op2 == 0b101) {
                return "VALE3";
            } else {
                return "???";
            }
        }
    }
    return "???";
}
}

bool decode_bit_masks(unsigned sf, uint8_t N, uint8_t imms, uint8_t immr, uint8_t immediate,
                      uint64_t* wmask, uint64_t* tmask) {
    int len = hibit_pos((N << 6) | lobits(~imms, 6));
    if (len < 1) {
        return false;
    }
    uint8_t levels = ones(len);
    if (immediate != 0 && (imms & levels) == levels) {
        return false;
    }
    uint8_t S = imms & levels;
    uint8_t R = immr & levels;
    int8_t diff = S - R;
    uint8_t esize = 1 << len;
    uint8_t d = lobits(diff, len - 1);
    uint64_t welem = ones(S + 1);
    uint64_t telem = ones(d + 1);
    *wmask = replicate(ror(welem, R, esize), esize, (sf ? 64 : 32));
    *tmask = replicate(telem, esize, (sf ? 64 : 32));
    return true;
}

bool disassemble_arith(MachO* macho, uint64_t pc, uint32_t op) {
    char* name = nullptr;
    if (AARCH64_INS_TYPE(op, ADC_CLASS)) {
        adc_t adc = *(adc_t*)&op;
        if (IS_OP_INS(adc, op)) {
            name = "ADC";
        } else if (IS_OP_INS(adcs, op)) {
            name = "ADCS";
        } else if (IS_OP_INS(ngc, op)) {
            name = "NGC";
        } else if (IS_OP_INS(ngcs, op)) {
            name = "NGCS";
        } else if (IS_OP_INS(sbc, op)) {
            name = "SBC";
        } else if (IS_OP_INS(sbcs, op)) {
            name = "SBCS";
        }
        if (name) {
            printf("0x%016llx\t%-7s %s, %s, %s", pc, name, reg(adc.Rd, adc.sf), reg(adc.Rn, adc.sf),
                   reg(adc.Rm, adc.sf));
            return true;
        }
    }

    if (AARCH64_INS_TYPE(op, ADD_XR_CLASS)) {
        add_ext_t add = *(add_ext_t*)&op;
        if (IS_OP_INS(cmp_ext, op)) {
            name = "CMP";
        } else if (IS_OP_INS(cmn_ext, op)) {
            name = "CMN";
        }
        if (name) {
            cmp_ext_t cmp = *(cmp_ext_t*)&op;
            printf("0x%016llx\t%-7s %s, %s, %s", pc, name, reg(cmp.Rd, cmp.sf), reg(cmp.Rn, cmp.sf),
                   reg(cmp.Rm, cmp.sf));
            return true;
        }
        if (IS_OP_INS(add_ext, op)) {
            name = "ADD";
        } else if (IS_OP_INS(adds_ext, op)) {
            name = "ADDS";
        } else if (IS_OP_INS(sub_ext, op)) {
            name = "SUB";
        } else if (IS_OP_INS(subs_ext, op)) {
            name = "SUBS";
        }
        if (name) {
            printf("0x%016llx\t%-7s %s, %s, %s", pc, name, reg(add.Rd, add.sf), reg(add.Rn, add.sf),
                   reg(add.Rm, add.sf));
            if (add.imm > 0 || !AARCH64_EXTEND_IS_LSL(add.option)) {
                printf(", %s", ext(add.option));
            }
            if (add.imm > 0) {
                printf(" #%u", add.imm);
            }
            return true;
        }
    }

    if (AARCH64_INS_TYPE(op, ADD_IM_CLASS)) {
        add_imm_t add = *(add_imm_t*)&op;
        if (IS_OP_INS(add_imm, op) && !add.imm && !add.sh &&
            (add.Rn == 0b11111 || add.Rd == 0b11111)) {
            printf("0x%016llx\t%-7s %s %s", pc, "MOV", reg(add.Rd, add.sf), reg(add.Rn, add.sf));
            return true;
        }
        if (IS_OP_INS(cmp_imm, op)) {
            name = "CMP";
        } else if (IS_OP_INS(cmn_imm, op)) {
            name = "CMN";
        }
        if (name) {
            cmp_imm_t cmp = *(cmp_imm_t*)&op;
            printf("0x%016llx\t%-7s %s, #0x%x", pc, "CMP", reg(cmp.Rn, cmp.sf), cmp.imm);
            return true;
        }
        if (IS_OP_INS(add_imm, op)) {
            name = "ADD";
        } else if (IS_OP_INS(adds_imm, op)) {
            name = "ADDS";
        } else if (IS_OP_INS(sub_imm, op)) {
            name = "SUB";
        } else if (IS_OP_INS(subs_imm, op)) {
            name = "SUBS";
        }
        if (name) {
            printf("0x%016llx\t%-7s %s, %s, #0x%x", pc, name, reg(add.Rd, add.sf),
                   reg(add.Rn, add.sf), add.imm);
            if (add.sh > 0) {
                printf(", %s #%u", shift(AARCH64_SHIFT_LSL), add.sh ? 12 : 0);
            }
            return true;
        }
    }

    if (AARCH64_INS_TYPE(op, ADD_SR_CLASS)) {
        add_reg_t add = *(add_reg_t*)&op;
        if (IS_OP_INS(cmp_reg, op)) {
            name = "CMP";
        } else if (IS_OP_INS(cmn_reg, op)) {
            name = "CMN";
        } else if (IS_OP_INS(neg, op)) {
            name = "NEG";
        }
        if (name) {
            cmp_reg_t cmp = *(cmp_reg_t*)&op;
            printf("0x%016llx\t%-7s %s, %s", pc, name, reg(cmp.Rn, cmp.sf), reg(cmp.Rm, cmp.sf));
            if (cmp.imm) {
                printf(", %s #%u", shift(cmp.shift), cmp.imm);
            }
            return true;
        }
        if (IS_OP_INS(add_reg, op)) {
            name = "ADD";
        } else if (IS_OP_INS(adds_reg, op)) {
            name = "ADDS";
        } else if (IS_OP_INS(sub_reg, op)) {
            name = "SUB";
        } else if (IS_OP_INS(subs_reg, op)) {
            name = "SUBS";
        }
        if (name) {
            printf("0x%016llx\t%-7s %s, %s, %s", pc, name, reg(add.Rd, add.sf), reg(add.Rn, add.sf),
                   reg(add.Rm, add.sf));
            if (add.imm) {
                printf(", %s #%u", shift(add.shift), add.imm);
            }
            return true;
        }
    }

    if (IS_OP_INS(asr_imm, op)) {
        asr_imm_t asr = *(asr_imm_t*)&op;
        printf("0x%016llx\t%-7s %s, %s, #%u", pc, "ASR", reg(asr.Rd, asr.sf), reg(asr.Rn, asr.sf),
               asr.immr);
        return true;
    } else if (IS_OP_INS(asr_reg, op)) {
        asr_reg_t asr = *(asr_reg_t*)&op;
        printf("0x%016llx\t%-7s %s, %s, %s", pc, "ASR", reg(asr.Rd, asr.sf), reg(asr.Rn, asr.sf),
               reg(asr.Rm, asr.sf));
        return true;
    }
    return false;
}

bool disassemble_logic(MachO* macho, uint64_t pc, uint32_t op) {
    char* name = nullptr;
    if (AARCH64_INS_TYPE(op, AND_IM_CLASS)) {
        and_imm_t and_imm = *(and_imm_t*)&op;
        uint64_t wmask, tmask, imm;
        if (!decode_bit_masks(and_imm.sf, and_imm.N, and_imm.imms, and_imm.immr, 1, &wmask,
                              &tmask)) {
            return false;
        }
        imm = lobits(wmask, (and_imm.sf ? 64 : 32));
        if (IS_OP_INS(movi, op)) {
            movi_t movi = *(movi_t*)&op;
            printf("0x%016llx\t%-7s %s #0x%llx", pc, "MOV", reg(movi.Rd, movi.sf), imm);
            return true;
        }
        if (IS_OP_INS(tst_imm, op)) {
            tst_imm_t tst = *(tst_imm_t*)&op;
            printf("0x%016llx\t%-7s %s, #0x%llx", pc, "TST", reg(tst.Rn, tst.sf), imm);
            return true;
        }
        if (IS_OP_INS(orr, op)) {
            name = "ORR";
        } else if (IS_OP_INS(eor, op)) {
            name = "EOR";
        } else if (IS_OP_INS(and_imm, op)) {
            name = "AND";
        }
        if (name) {
            printf("0x%016llx\t%-7s %s, %s, #0x%llx", pc, name, reg(and_imm.Rd, and_imm.sf),
                   reg(and_imm.Rn, and_imm.sf), imm);
            return true;
        }
    }
    if (IS_OP_INS(ands_imm, op)) {
        name = "ANDS";
    }
    if (name) {
        and_imm_t and_imm = *(and_imm_t*)&op;
        uint64_t wmask, tmask, imm;
        if (!decode_bit_masks(and_imm.sf, and_imm.N, and_imm.imms, and_imm.immr, 1, &wmask,
                              &tmask)) {
            return false;
        }
        imm = lobits(wmask, (and_imm.sf ? 64 : 32));
        printf("0x%016llx\t%-7s %s, %s, #0x%llx", pc, name, reg(and_imm.Rd, and_imm.sf),
               reg(and_imm.Rn, and_imm.sf), imm);
        return true;
    }

    if (AARCH64_INS_TYPE(op, AND_SR_CLASS)) {
        and_shift_t and_s = *(and_shift_t*)&op;
        if (IS_OP_INS(mvn, op)) {
            name = "MVN";
        } else if (IS_OP_INS(mov, op)) {
            name = "MOV";
        }
        if (name) {
            mov_t mov = *(mov_t*)&op;
            printf("0x%016llx\t%-7s %s, %s", pc, name, reg(mov.Rd, mov.sf), reg(mov.Rm, mov.sf));
            return true;
        }
        if (IS_OP_INS(tst_shift, op)) {
            tst_shift_t tst = *(tst_shift_t*)&op;
            printf("0x%016llx\t%-7s %s %s", pc, name, reg(tst.Rn, tst.sf), reg(tst.Rm, tst.sf));
            return true;
        }

        if (IS_OP_INS(orr_shift, op)) {
            name = "ORR";
        } else if (IS_OP_INS(orn_shift, op)) {
            name = "ORN";
        } else if (IS_OP_INS(eor_shift, op)) {
            name = "EOR";
        } else if (IS_OP_INS(eon_shift, op)) {
            name = "EON";
        } else if (IS_OP_INS(bic, op)) {
            name = "BIC";
        } else if (IS_OP_INS(and_shift, op)) {
            name = "AND";
        } else if (IS_OP_INS(bics, op)) {
            name = "BICS";
        }
        if (name) {
            printf("0x%016llx\t%-7s %s, %s, %s", pc, name, reg(and_s.Rd, and_s.sf),
                   reg(and_s.Rn, and_s.sf), reg(and_s.Rm, and_s.sf));
            if (and_s.imm > 0) {
                printf(", %s #%d", shift(and_s.shift), and_s.imm);
            }
            return true;
        }
    }

    if (IS_OP_INS(ands_shift, op)) {
        name = "ANDS";
    }
    if (name) {
        and_shift_t and_s = *(and_shift_t*)&op;
        printf("0x%016llx\t%-7s %s, %s, %s", pc, name, reg(and_s.Rd, and_s.sf),
               reg(and_s.Rn, and_s.sf), reg(and_s.Rm, and_s.sf));
        if (and_s.imm > 0) {
            printf(", %s #%d", shift(and_s.shift), and_s.imm);
        }
        return true;
    }
    if (IS_OP_INS(lsl_imm, op) || IS_OP_INS(lsl_reg, op)) {
        name = "LSL";
    } else if (IS_OP_INS(lsr_imm, op) || IS_OP_INS(lsr_reg, op)) {
        name = "LSR";
    }
    if (name) {
        if (IS_OP_INS(lsl_imm, op) || IS_OP_INS(lsr_imm, op)) {
            lsl_imm_t lsl = *(lsl_imm_t*)&op;
            uint32_t sub = lsl.sf ? 64 : 32;
            uint32_t shift = strcmp(name, "LSL") == 0 ? (sub - lsl.immr) : lsl.immr;
            printf("0x%016llx\t%-7s %s, %s, #%u", pc, name, reg(lsl.Rd, lsl.sf),
                   reg(lsl.Rn, lsl.sf), shift);
            return true;
        } else if (IS_OP_INS(lsl_reg, op) || IS_OP_INS(lsr_reg, op)) {
            lsl_reg_t lsl = *(lsl_reg_t*)&op;
            printf("0x%016llx\t%-7s %s, %s, %s", pc, name, reg(lsl.Rd, lsl.sf), reg(lsl.Rn, lsl.sf),
                   reg(lsl.Rm, lsl.sf));
            return true;
        }
    }
    return false;
}

bool disassemble_memory(MachO* macho, uint64_t pc, uint32_t op) {
    char* name = nullptr;
    if (AARCH64_INS_TYPE(op, LDP_CLASS)) {
        ldp_t ldp = *(ldp_t*)&op;
        int64_t imm;
        bool sign = (ldp.imm & 0b1000000);
        if (sign) {
            imm = ((int64_t)(ldp.imm & 0b111111)) << (2 + ldp.sf);
            for (int i = 6 + 2 + ldp.sf; i < 64; i++) {
                imm |= (1UL << i);
            }
            imm *= -1;
        } else {
            imm = ldp.imm << (2 + ldp.sf);
        }
        if (IS_OP_INS(ldpsw_pre, op) || IS_OP_INS(ldpsw_post, op) || IS_OP_INS(ldpsw_soff, op)) {
            name = "LDPSW";
        } else if (IS_OP_INS(ldnp, op)) {
            name = "LDNP";
        } else if (IS_OP_INS(ldp_pre, op) || IS_OP_INS(ldp_post, op) || IS_OP_INS(ldp_soff, op)) {
            name = "LDP";
        } else if (IS_OP_INS(stnp, op)) {
            name = "STNP";
        } else if (IS_OP_INS(stp_pre, op) || IS_OP_INS(stp_post, op) || IS_OP_INS(stp_soff, op)) {
            name = "STP";
        }
        if (IS_OP_INS(ldpsw_soff, op) || IS_OP_INS(ldp_soff, op) || IS_OP_INS(stp_soff, op)) {
            if (!imm) {
                printf("0x%016llx\t%-7s %s, %s, [%s]", pc, name, reg(ldp.Rt, ldp.sf),
                       reg(ldp.Rt2, ldp.sf), reg(ldp.Rn, ldp.sf));
            } else {
                printf("0x%016llx\t%-7s %s, %s, [%s, #%s0x%llx]", pc, name, reg(ldp.Rt, ldp.sf),
                       reg(ldp.Rt2, ldp.sf), reg(ldp.Rn, ldp.sf), sign ? "-" : "", imm);
            }
            return true;
        }
        if (IS_OP_INS(ldpsw_post, op) || IS_OP_INS(ldp_post, op) || IS_OP_INS(stp_post, op)) {
            printf("0x%016llx\t%-7s %s, %s, [%s], #0x%s%llx", pc, name, reg(ldp.Rt, ldp.sf),
                   reg(ldp.Rt2, ldp.sf), reg(ldp.Rn, ldp.sf), sign ? "-" : "", imm);
            return true;
        }
        if (IS_OP_INS(ldpsw_pre, op) || IS_OP_INS(ldp_pre, op) || IS_OP_INS(stp_pre, op)) {
            printf("0x%016llx\t%-7s %s, %s, [%s, #%s0x%llx]!", pc, name, reg(ldp.Rt, ldp.sf),
                   reg(ldp.Rt2, ldp.sf), reg(ldp.Rn, ldp.sf), sign ? "-" : "", imm);
            return true;
        }
    }
    if (AARCH64_INS_TYPE(op, LDR_UI_CLASS) || AARCH64_INS_TYPE(op, LDR_IX_CLASS)) {
        ldr_imm_t ldr = *(ldr_imm_t*)&op;
        if (IS_OP_INS(ldr_imm_pre, op) || IS_OP_INS(ldr_imm_post, op) ||
            IS_OP_INS(ldr_imm_uoff, op)) {
            name = "LDR";
        } else if (IS_OP_INS(str_pre, op) || IS_OP_INS(str_post, op) || IS_OP_INS(str_uoff, op)) {
            name = "STR";
        } else if (IS_OP_INS(ldrb_imm_pre, op) || IS_OP_INS(ldrb_imm_post, op) ||
                   IS_OP_INS(ldrb_imm_uoff, op)) {
            name = "LDRB";
        } else if (IS_OP_INS(ldrh_imm_pre, op) || IS_OP_INS(ldrh_imm_post, op) ||
                   IS_OP_INS(ldrh_imm_uoff, op)) {
            name = "LDRH";
        } else if (IS_OP_INS(strb_imm_pre, op) || IS_OP_INS(strb_imm_post, op) ||
                   IS_OP_INS(strb_imm_uoff, op)) {
            name = "STRB";
        } else if (IS_OP_INS(strh_imm_pre, op) || IS_OP_INS(strh_imm_post, op) ||
                   IS_OP_INS(strh_imm_uoff, op)) {
            name = "STRH";
        } else if (IS_OP_INS(ldrsb_imm_pre, op) || IS_OP_INS(ldrsb_imm_post, op) ||
                   IS_OP_INS(ldrsb_imm_uoff, op)) {
            name = "LDRSB";
        } else if (IS_OP_INS(ldrsh_imm_pre, op) || IS_OP_INS(ldrsh_imm_post, op) ||
                   IS_OP_INS(ldrsh_imm_uoff, op)) {
            name = "LDRSH";
        } else if (IS_OP_INS(ldrsw_imm_pre, op) || IS_OP_INS(ldrsw_imm_post, op) ||
                   IS_OP_INS(ldrsw_imm_uoff, op)) {
            name = "LDRSW";
        }
        if (AARCH64_INS_TYPE(op, LDR_UI_CLASS)) {
            ldr_imm_uoff_t ldr_uoff = *(ldr_imm_uoff_t*)&op;
            if (ldr_uoff.imm == 0) {
                printf("0x%016llx\t%-7s %s, [%s]", pc, name, reg(ldr_uoff.Rt, ldr_uoff.sf),
                       reg(ldr_uoff.Rn, ldr_uoff.sf));
                return true;
            }
            printf("0x%016llx\t%-7s %s, [%s, #0x%x]", pc, name, reg(ldr_uoff.Rt, ldr_uoff.sf),
                   reg(ldr_uoff.Rn, ldr_uoff.sf), ldr_uoff.imm << (2 + ldr_uoff.sf));
            return true;
        } else if (AARCH64_INS_TYPE(op, LDR_IX_CLASS)) {
            bool sign = (ldr.imm & 0b100000000) > 0;
            int64_t imm = (ldr.imm & 0b11111111);
            if (sign) {
                for (int i = 8; i < 64; i++) {
                    imm |= (1UL << i);
                }
                imm *= -1;
            }
            if (ldr.imm == 0) {
                printf("0x%016llx\t%-7s %s, [%s]", pc, name, reg(ldr.Rt, ldr.sf),
                       reg(ldr.Rn, ldr.sf));
                return true;
            }
            if (IS_OP_INS(ldr_imm_pre, op) || IS_OP_INS(str_pre, op) ||
                IS_OP_INS(ldrb_imm_pre, op) || IS_OP_INS(ldrh_imm_pre, op) ||
                IS_OP_INS(strb_imm_pre, op) || IS_OP_INS(strh_imm_pre, op) ||
                IS_OP_INS(ldrsb_imm_pre, op) || IS_OP_INS(ldrsh_imm_pre, op) ||
                IS_OP_INS(ldrsw_imm_pre, op)) {
                printf("0x%016llx\t%-7s %s, [%s, #%s0x%llx]!", pc, name, reg(ldr.Rt, ldr.sf),
                       reg(ldr.Rn, ldr.sf), sign ? "-" : "", imm);
                return true;
            }
            if (IS_OP_INS(ldr_imm_post, op) || IS_OP_INS(str_post, op) ||
                IS_OP_INS(ldrb_imm_post, op) || IS_OP_INS(ldrh_imm_post, op) ||
                IS_OP_INS(strb_imm_post, op) || IS_OP_INS(strh_imm_post, op) ||
                IS_OP_INS(ldrsb_imm_post, op) || IS_OP_INS(ldrsh_imm_post, op) ||
                IS_OP_INS(ldrsw_imm_post, op)) {
                printf("0x%016llx\t%-7s %s, [%s], #%s0x%llx", pc, name, reg(ldr.Rt, ldr.sf),
                       reg(ldr.Rn, ldr.sf), sign ? "-" : "", imm);
                return true;
            }
        }
    }

    if (AARCH64_INS_TYPE(op, LDR_R_CLASS)) {
        ldr_reg_t ldr = *(ldr_reg_t*)&op;
        uint8_t sf = true;
        uint8_t option = ldr.option;
        if (option == AARCH64_EXTEND_UXTX) {
            option |= AARCH64_EXTEND_LSL;
        }
        if (IS_OP_INS(ldr_reg, op)) {
            name = "LDR";
            sf = ldr.size == 0b11 ? true : false;
        } else if (IS_OP_INS(str_reg, op)) {
            name = "STR";
            sf = ldr.size == 0b11 ? true : false;
        } else if (IS_OP_INS(ldrb_reg, op)) {
            name = "LDRB";
            sf = false;
        } else if (IS_OP_INS(ldrh_reg, op)) {
            name = "LDRH";
            sf = false;
        } else if (IS_OP_INS(ldrsb_reg, op)) {
            name = "LDRSB";
            sf = (ldr.op & 0b10) == 0b10 ? false : true;
        } else if (IS_OP_INS(ldrsh_reg, op)) {
            name = "LDRSH";
            sf = false;
        } else if (IS_OP_INS(ldrsw_reg, op)) {
            name = "LDRSW";
            sf = false;
        } else if (IS_OP_INS(strb_reg, op))
            name = "STRB";
        else if (IS_OP_INS(strh_reg, op)) {
            name = "STRH";
        }
        if (!(ldr.S * ldr.size)) {
            if (AARCH64_EXTEND_IS_LSL(option)) {
                printf("0x%016llx\t%-7s %s, [%s, %s]", pc, name, reg(ldr.Rt, sf), reg(ldr.Rn, true),
                       reg(ldr.Rm, sf));
            } else {
                printf("0x%016llx\t%-7s %s, [%s, %s, %s]", pc, name, reg(ldr.Rt, sf),
                       reg(ldr.Rn, true), reg(ldr.Rm, sf), ext(option));
            }
        } else {
            printf("0x%016llx\t%-7s %s, [%s, %s, %s #%u]", pc, name, reg(ldr.Rt, sf),
                   reg(ldr.Rn, true), reg(ldr.Rm, sf), ext(option), (ldr.S * ldr.size));
        }
        return true;
    }

    if (IS_OP_INS(stur, op)) {
        name = "STUR";
    } else if (IS_OP_INS(sturh, op)) {
        name = "STURH";
    } else if (IS_OP_INS(sturb, op)) {
        name = "STURB";
    } else if (IS_OP_INS(ldur, op)) {
        name = "LDUR";
    } else if (IS_OP_INS(ldurh, op)) {
        name = "LDURH";
    } else if (IS_OP_INS(ldurb, op)) {
        name = "LDURB";
    }
    if (name) {
        ldur_t ldur = *(ldur_t*)&op;
        bool sign = (ldur.imm & 0b100000000) > 0;
        int64_t imm = (ldur.imm & 0b11111111);
        if (sign) {
            for (int i = 8; i < 64; i++) {
                imm |= (1UL << i);
            }
            imm *= -1;
        }
        uint8_t sf = ldur.op1 ? ldur.sf : 0;
        if (imm == 0) {
            printf("0x%016llx\t%-7s %s, [%s]", pc, name, reg(ldur.Rt, sf), reg(ldur.Rn, sf));
            return true;
        }
        printf("0x%016llx\t%-7s %s, [%s, #%s0x%llx]", pc, name, reg(ldur.Rt, sf), reg(ldur.Rn, sf),
               sign ? "-" : "", imm);
        return true;
    }

    if (AARCH64_INS_TYPE(op, LDR_LIT_CLASS)) {
        ldr_lit_t ldr = *(ldr_lit_t*)&op;
        if (IS_OP_INS(ldrsw_lit, op)) {
            name = "LDRSW";
        } else if (IS_OP_INS(ldr_lit, op)) {
            name = "LDR";
        }
        printf("0x%016llx\t%-7s %s, #0x%x", pc, name, reg(ldr.Rt, true), ldr.imm);
        return true;
    }
    return false;
}

bool disassemble_movknz(MachO* macho, uint64_t pc, uint32_t op) {
    char* name = nullptr;
    if (!AARCH64_INS_TYPE(op, MOV_CLASS)) {
        return false;
    }
    movz_t mov = *(movz_t*)&op;
    uint8_t sf = mov.sf;
    uint64_t mov_imm;
    uint8_t sh = 16 * mov.hw;
    uint32_t imm = mov.imm;
    if (IS_OP_INS(movk, op)) {
        name = "MOVK";
    } else if (IS_OP_INS(movn, op)) {
        if (mov.hw == 0b00 && mov.imm) {
            mov_imm = ~((uint64_t)imm << sh);
            goto mov;
        }
        name = "MOVN";
    } else if (IS_OP_INS(movz, op)) {
        if (mov.hw == 0b00 && mov.imm) {
            mov_imm = imm << sh;
            goto mov;
        }
        name = "MOVZ";
    }
    if (sh) {
        printf("0x%016llx\t%-7s %s, #0x%x, %s #%u", pc, name, reg(mov.Rd, sf), mov.imm,
               shift(AARCH64_SHIFT_LSL), sh);
    } else {
        printf("0x%016llx\t%-7s %s, #0x%x", pc, name, reg(mov.Rd, sf), mov.imm);
    }
    return true;
mov:
    printf("0x%016llx\t%-7s %s, #0x%llx", pc, "MOV", reg(mov.Rd, sf), mov_imm);
    return true;
}

bool disassemble_adr_b(MachO* macho, uint64_t pc, uint32_t op) {
    char* name;
    if (IS_OP_INS(adr, op)) {
        adr_t adr = *(adr_t*)&op;
        signed addr = adr.immlo | (adr.immhi << 2);
        printf("0x%016llx\t%-7s X%u, #0x%x", pc, "ADR", adr.Rd, addr);
        return true;
    } else if (IS_OP_INS(adrp, op)) {
        adr_t adrp = *(adr_t*)&op;
        printf("0x%016llx\t%-7s X%u, #0x%llx", pc, "ADRP", adrp.Rd,
               (pc & ~0xFFF) + ((((adrp.immhi << 2) | adrp.immlo)) << 12));
        return true;
    } else if (IS_OP_INS(b, op)) {
        b_t b = *(b_t*)&op;
        int64_t imm = b.imm << 2;
        if (imm & 0x2000000) {
            imm |= 0xf << 28;
        }
        printf("0x%016llx\t%-7s #0x%llx", pc, "B", pc + imm);
        return true;
    } else if (IS_OP_INS(bl, op)) {
        bl_t bl = *(bl_t*)&op;
        int64_t imm = bl.imm << 2;
        if (bl.imm & 0x2000000) {
            imm |= 0xf << 28;
        }
        printf("0x%016llx\t%-7s #0x%llx", pc, "BL", pc + imm);
        return true;
    } else if (IS_OP_INS(br, op)) {
        br_t br = *(br_t*)&op;
        printf("0x%016llx\t%-7s X%u", pc, "BR", br.Rn);
        return true;
    } else if (IS_OP_INS(blr, op)) {
        br_t blr = *(br_t*)&op;
        printf("0x%016llx\t%-7s X%u", pc, "BLR", blr.Rn);
        return true;
    } else if (IS_OP_INS(cbz, op)) {
        cbz_t cbz = *(cbz_t*)&op;
        uint8_t sf = cbz.sf;
        int64_t imm = cbz.imm << 2;
        uint64_t address = pc + imm;
        printf("0x%016llx\t%-7s %s, #0x%llx", pc, "CBZ", reg(cbz.Rt, cbz.sf), address);
        return true;
    } else if (IS_OP_INS(cbnz, op)) {
        cbz_t cbnz = *(cbz_t*)&op;
        uint8_t sf = cbnz.sf;
        int64_t imm = cbnz.imm << 2;
        uint64_t address = pc + imm;
        printf("0x%016llx\t%-7s %s, #0x%llx", pc, "CBNZ", reg(cbnz.Rt, cbnz.sf), address);
        return true;
    } else if (IS_OP_INS(tbz, op)) {
        tbz_t tbz = *(tbz_t*)&tbz;
        uint8_t sf = tbz.sf;
        uint64_t address = pc + ((int64_t)tbz.imm << 2);
        uint32_t bit = tbz.bit;
        printf("0x%016llx\t%-7s %s, #%u, #0x%llx", pc, "TBZ", reg(tbz.Rt, sf), bit, address);
        return true;
    } else if (IS_OP_INS(tbnz, op)) {
        tbz_t tbnz = *(tbz_t*)&op;
        uint8_t sf = tbnz.sf;
        uint64_t address = pc + ((int64_t)tbnz.imm << 2);
        uint32_t bit = tbnz.bit;
        printf("0x%016llx\t%-7s %s, #%u, #0x%llx", pc, "TBNZ", reg(tbnz.Rt, sf), bit, address);
        return true;
    } else if (IS_OP_INS(b_cond, op)) {
        b_cond_t b_cond = *(b_cond_t*)&op;
        int64_t imm = b_cond.imm << 2;
        uint64_t address = pc + imm;
        char* cond = condition(b_cond.cond);
        name = "B";
        if (name && cond) {
            uint32_t len = strlen(name) + strlen(cond) + 2;
            char* mnem = new char[len];
            strncpy(mnem, name, strlen(name));
            mnem[strlen(name)] = '.';
            strncpy(mnem + strlen(name) + 1, cond, strlen(cond));
            mnem[len - 1] = '\0';
            printf("0x%016llx\t%-7s #0x%llx", pc, mnem, address);
            delete[] mnem;
        }
        return true;
    } else if (IS_OP_INS(blraa, op)) {
        blraa_t blraa = *(blraa_t*)&op;
        printf("0x%016llx\t%-7s X%u X%u", pc, "BLRAA", blraa.Rn, blraa.Rm);
        return true;
    } else if (IS_OP_INS(blraaz, op)) {
        blraaz_t blraaz = *(blraaz_t*)&op;
        printf("0x%016llx\t%-7s X%u", pc, "BLRAAZ", blraaz.Rn);
        return true;
    } else if (IS_OP_INS(blrab, op)) {
        blrab_t blrab = *(blrab_t*)&op;
        printf("0x%016llx\t%-7s X%u X%u", pc, "BLRAB", blrab.Rn, blrab.Rm);
        return true;
    } else if (IS_OP_INS(blrabz, op)) {
        blrabz_t blrabz = *(blrabz_t*)&op;
        printf("0x%016llx\t%-7s X%u", pc, "BLRAZ", blrabz.Rn);
        return true;
    } else if (IS_OP_INS(ret, op)) {
        printf("0x%016llx\t%-7s", pc, "RET");
        return true;
    } else if (IS_OP_INS(retaa, op)) {
        printf("0x%016llx\t%-7s", pc, "RETAA");
        return true;
    } else if (IS_OP_INS(retab, op)) {
        printf("0x%016llx\t%-7s", pc, "RETAB");
        return true;
    }
    return false;
}

bool disassemble_pac(MachO* macho, uint64_t pc, uint32_t op) {
    char* name = nullptr;
    if (IS_OP_INS(xpaclri, op)) {
        printf("XPACLRI");
        return true;
    }

    if (IS_OP_INS(xpacd, op)) {
        name = "XPACD";
    } else if (IS_OP_INS(xpaci, op)) {
        name = "XPACI";
    } else if (IS_OP_INS(autdza, op)) {
        name = "AUTDZA";
    } else if (IS_OP_INS(autdzb, op)) {
        name = "AUTDZB";
    } else if (IS_OP_INS(autiza, op)) {
        name = "AUTIZA";
    } else if (IS_OP_INS(autizb, op)) {
        name = "AUTIZB";
    } else if (IS_OP_INS(pacdza, op)) {
        name = "PACDZA";
    } else if (IS_OP_INS(pacdzb, op)) {
        name = "PACDZB";
    } else if (IS_OP_INS(paciza, op)) {
        name = "PACIZA";
    } else if (IS_OP_INS(pacizb, op)) {
        name = "PACIZB";
    }
    if (name) {
        xpacd_t xpacd = *(xpacd_t*)&op;
        printf("0x%016llx\t%-7s X%u", pc, name, xpacd.Rd);
        return true;
    }

    if (IS_OP_INS(autda, op)) {
        name = "AUTDA";
    } else if (IS_OP_INS(autdb, op)) {
        name = "AUTDB";
    } else if (IS_OP_INS(autia, op)) {
        name = "AUTIA";
    } else if (IS_OP_INS(autib, op)) {
        name = "AUTIB";
    } else if (IS_OP_INS(pacda, op)) {
        name = "PACDA";
    } else if (IS_OP_INS(pacdb, op)) {
        name = "PACDB";
    } else if (IS_OP_INS(pacia, op)) {
        name = "PACIA";
    } else if (IS_OP_INS(pacib, op)) {
        name = "PACIB";
    }
    if (name) {
        autda_t autda = *(autda_t*)&op;
        printf("0x%016llx\t%-7s X%u, X%u", pc, name, autda.Rd, autda.Rn);
        return true;
    }

    if (IS_OP_INS(autia1716, op)) {
        name = "AUTIA1716";
    } else if (IS_OP_INS(autib1716, op)) {
        name = "AUTIB1716";
    } else if (IS_OP_INS(autiasp, op)) {
        name = "AUTIASP";
    } else if (IS_OP_INS(autibsp, op)) {
        name = "AUTIBSP";
    } else if (IS_OP_INS(autiaz, op)) {
        name = "AUTIAZ";
    } else if (IS_OP_INS(autibz, op)) {
        name = "AUTIBZ";
    } else if (IS_OP_INS(pacia1716, op)) {
        name = "PACIA1716";
    } else if (IS_OP_INS(paciasp, op)) {
        name = "PACIASP";
    } else if (IS_OP_INS(paciaz, op)) {
        name = "PACIAZ";
    } else if (IS_OP_INS(pacib1716, op)) {
        name = "PACIB1716";
    } else if (IS_OP_INS(pacibsp, op)) {
        name = "PACIBSP";
    } else if (IS_OP_INS(pacibz, op)) {
        name = "PACIBZ";
    }
    if (name) {
        printf("0x%016llx\t%-7s", pc, name);

        return true;
    }

    if (IS_OP_INS(ldraa, op)) {
        name = "LDRAA";
    } else if (IS_OP_INS(ldrab, op)) {
        name = "LDRAB";
    }
    if (name) {
        ldraa_t ldraa = *(ldraa_t*)&op;
        int64_t imm;
        bool sign = (ldraa.imm & 0b100000000);
        if (sign) {
            imm = ((int64_t)(ldraa.imm & 0b11111111)) << 3;
            for (int i = 8 + 3; i < 64; i++) {
                imm |= (1UL << i);
            }
            imm *= -1;
        } else {
            imm = ldraa.imm << 3;
        }
        if (ldraa.W) {
            printf("0x%016llx\t%-7s %s, [%s , #%s0x%llx]!", pc, name, reg(ldraa.Rt, true),
                   reg(ldraa.Rn, true), sign ? "-" : "", imm);
        } else {
            printf("0x%016llx\t%-7s %s, [%s , #%s0x%llx]", pc, name, reg(ldraa.Rt, true),
                   reg(ldraa.Rn, true), sign ? "-" : "", imm);
        }
        return true;
    }

    if (IS_OP_INS(bti, op)) {
        bti_t bti = *(bti_t*)&op;
        uint8_t op = (bti.op & 0b110) >> 1;
        char* targets = "";
        if (op == 0b00) {
            targets = "(omitted)";
        } else if (op == 0b01) {
            targets = "c";
        } else if (op == 0b10) {
            targets = "j";
        } else if (op == 0b11) {
            targets = "jc";
        }
        printf("0x%016llx\t%-7s %s", pc, name, targets);
        return true;
    }
    return false;
}

bool disassemble_sys(MachO* macho, uint64_t pc, uint32_t op) {
    char* name = nullptr;
    if (IS_OP_INS(wfi, op)) {
        name = "WFI";
    } else if (IS_OP_INS(sb, op)) {
        name = "SB";
    } else if (IS_OP_INS(isb, op)) {
        name = "ISB";
    } else if (IS_OP_INS(dsb, op)) {
        name = "DSB";
    } else if (IS_OP_INS(esb, op)) {
        name = "ESB";
    } else if (IS_OP_INS(dmb, op)) {
        name = "DMB";
    } else if (IS_OP_INS(csdb, op)) {
        name = "CSDB";
    }
    if (name) {
        sb_t sb = *(sb_t*)&op;
        printf("0x%016llx\t%-7s", pc, name);
        return true;
    }

    if (IS_OP_INS(wfit, op)) {
        wfit_t wfit = *(wfit_t*)&op;
        printf("0x%016llx\t%-7s %s", pc, "WFIT", reg(wfit.Rd, true));
    }
    if (IS_OP_INS(brk, op)) {
        brk_t brk = *(brk_t*)&op;
        printf("0x%016llx\t%-7s #0x%x", pc, "BRK", brk.imm);
        return true;
    } else if (IS_OP_INS(msr_imm, op)) {
        msr_imm_t msr = *(msr_imm_t*)&op;
        printf("0x%016llx\t%-7s #%u, #%u", pc, "MSR", msr.op2, msr.CRm);
        return true;
    } else if (IS_OP_INS(msr_reg, op)) {
        msr_reg_t msr = *(msr_reg_t*)&op;
        printf("0x%016llx\t%-7s #%u, c%u, c%u, #%u, X%u", pc, "MSR", msr.op1, msr.CRm, msr.CRn,
               msr.op2, msr.Rt);
        return true;
    } else if (IS_OP_INS(mrs, op)) {
        mrs_t mrs = *(mrs_t*)&op;
        printf("0x%016llx\t%-7s X%u, #%u, c%u, c%u, #%u", pc, "MRS", mrs.Rt, mrs.op1, mrs.CRm,
               mrs.CRn, mrs.op2);
        return true;
    } else if (IS_OP_INS(sys, op)) {
        sys_t sys = *(sys_t*)&op;
        if (sys.CRn == 0b1000) {
            tlbi_t tlbi = *(tlbi_t*)&op;
            printf("0x%016llx\t%-7s %s, X%u", pc, "TLBI", tlbi_op(tlbi.op1, tlbi.CRm, tlbi.op2),
                   tlbi.Rt);
            return true;
        }
        printf("0x%016llx\t%-7s #%u, c%u, c%u, #%u, X%u", pc, "SYS", sys.op2, sys.CRn, sys.CRm,
               sys.op2, sys.Rt);
        return true;
    }

    if (IS_OP_INS(svc, op)) {
        name = "SVC";
    } else if (IS_OP_INS(smc, op)) {
        name = "SMC";
    } else if (IS_OP_INS(hvc, op)) {
        name = "HVC";
    }
    if (name) {
        svc_t svc = *(svc_t*)&op;
        printf("0x%016llx\t%-7s #0x%x", pc, name, svc.imm);
        return true;
    }
    return false;
}

bool disassemble_fp_simd(MachO* macho, uint64_t pc, uint32_t op) {
    char* name = nullptr;
    if (AARCH64_INS_TYPE(op, FP_SCALAR_CLASS)) {
        fadd_scalar_t fadd = *(fadd_scalar_t*)&op;
        char* precision = nullptr;
        if (IS_OP_INS(fadd_scalar, op)) {
            name = "FADD";
        } else if (IS_OP_INS(fsub_scalar, op)) {
            name = "FSUB";
        } else if (IS_OP_INS(fmul_scalar, op)) {
            name = "FMUL";
        } else if (IS_OP_INS(fdiv_scalar, op)) {
            name = "FDIV";
        } else if (IS_OP_INS(fabs_scalar, op)) {
            name = "FABS";
        } else if (IS_OP_INS(fcmp_scalar, op)) {
            name = "FCMP";
        } else if (IS_OP_INS(fcsel_scalar, op)) {
            name = "FCSEL";
        } else if (IS_OP_INS(fmov_scalar, op)) {
            fmov_scalar_t fmov = *(fmov_scalar_t*)&op;
            if (fadd.ftype == 0b11) {
                precision = "H";
            } else if (fadd.ftype == 0b00) {
                precision = "S";
            } else if (fadd.ftype == 0b01) {
                precision = "D";
            }
            name = "FMOV";
            float imm;
            uint32_t x = 0;
            bool sign = (fmov.imm & 0b10000000);
            if (sign) {
                x |= (1U << 31);
            }
            x |= ((((uint32_t)fmov.imm & 0b01110000) >> 4) << 23);
            x |= (((uint32_t)fmov.imm & 0b00001111) << 19);
            bool b = fmov.imm & 0b01000000;
            x &= ~(1UL << 30);
            x |= (!b) << 30;
            for (int i = 29; i >= 25; i--) {
                x &= ~(1UL << i);
                x |= b << i;
            }
            memcpy(&imm, &x, sizeof(float));
            printf("0x%016llx\t%-7s %s%u, #%f", pc, name, precision, fmov.Rd, imm);
            return true;
        }

        if (fadd.ftype == 0b11) {
            precision = "H";
        } else if (fadd.ftype == 0b00) {
            precision = "S";
        } else if (fadd.ftype == 0b01) {
            precision = "D";
        }
        if (name && precision) {
            printf("0x%016llx\t%-7s %s%u, %s%u, %s%u", pc, name, precision, fadd.Rd, precision,
                   fadd.Rn, precision, fadd.Rm);
            if (IS_OP_INS(fcsel_scalar, op)) {
                printf(", %s", condition(fadd.op2 & 0b111100));
            }
            return true;
        }
    }

    if (IS_OP_INS(fcvtzs_scalar, op) || IS_OP_INS(fcvtzs_fixed_scalar, op)) {
        name = "FCVTZS";
    }
    if (name) {
        fcvtzs_scalar_t fcvtzs = *(fcvtzs_scalar_t*)&op;
        char* precision = nullptr;
        if (fcvtzs.ftype == 0b11) {
            precision = "H";
        } else if (fcvtzs.ftype == 0b00) {
            precision = "S";
        } else if (fcvtzs.ftype == 0b01) {
            precision = "D";
        }
        if (precision) {
            printf("0x%016llx\t%-7s %s, %s%u", pc, name, reg(fcvtzs.Rd, fcvtzs.sf), precision,
                   fcvtzs.Rn);
            if (IS_OP_INS(fcvtzs_fixed_scalar, op)) {
                printf(", #%u", (64 - fcvtzs.op2));
            }
            return true;
        }
    }

    if (IS_OP_INS(fmov_reg, op)) {
        name = "FMOV";
    }
    if (name) {
        fmov_reg_t fmov = *(fmov_reg_t*)&op;
        char* precision = nullptr;
        if (fmov.ftype == 0b11) {
            precision = "H";
        } else if (fmov.ftype == 0b00) {
            precision = "S";
        } else if (fmov.ftype == 0b01) {
            precision = "D";
        }
        if (precision) {
            printf("0x%016llx\t%-7s %s%u %s%u", pc, name, precision, fmov.Rd, precision, fmov.Rn);
            return true;
        }
    }

    if (IS_OP_INS(fmov, op)) {
        name = "FMOV";
    }
    if (name) {
        fmov_t fmov = *(fmov_t*)&op;
        uint8_t sf = fmov.sf;
        uint8_t ftype = fmov.ftype;
        uint8_t rmode = fmov.rmode;
        uint8_t opcode = fmov.opcode;
        if (!sf && ftype == 0b11 && rmode == 0b00 && opcode == 0b110) {
            printf("0x%016llx\t%-7s W%u, H%u", pc, name, fmov.Rd, fmov.Rn);
        } else if (sf && ftype == 0b11 && rmode == 0b00 && opcode == 0b110) {
            printf("0x%016llx\t%-7s X%u, H%u", pc, name, fmov.Rd, fmov.Rn);
        } else if (!sf && ftype == 0b11 && rmode == 0b00 && opcode == 0b110) {
            printf("0x%016llx\t%-7s J%u, W%u", pc, name, fmov.Rd, fmov.Rn);
        } else if (!sf && ftype == 0b00 && rmode == 0b00 && opcode == 0b111) {
            printf("0x%016llx\t%-7s S%u, W%u", pc, name, fmov.Rd, fmov.Rn);
        } else if (!sf && ftype == 0b00 && rmode == 0b00 && opcode == 0b110) {
            printf("0x%016llx\t%-7s W%u, H%u", pc, name, fmov.Rd, fmov.Rn);
        } else if (sf && ftype == 0b11 && rmode == 0b00 && opcode == 0b111) {
            printf("0x%016llx\t%-7s H%u, X%u", pc, name, fmov.Rd, fmov.Rn);
        } else if (sf && ftype == 0b01 && rmode == 0b00 && opcode == 0b11) {
            printf("0x%016llx\t%-7s D%u, X%u", pc, name, fmov.Rd, fmov.Rn);
        } else if (sf && ftype == 0b10 && rmode == 0b01 && opcode == 0b111) {
            printf("0x%016llx\t%-7s V%u.D[1], H%u", pc, name, fmov.Rd, fmov.Rn);
        } else if (sf && ftype == 0b01 && rmode == 0b00 && opcode == 0b110) {
            printf("0x%016llx\t%-7s X%u, D%u", pc, name, fmov.Rd, fmov.Rn);
        } else if (sf && ftype == 0b10 && rmode == 0b01 && opcode == 0b110) {
            printf("0x%016llx\t%-7s X%u, V%u.D[1]", pc, name, fmov.Rd, fmov.Rn);
        } else {
            return false;
        }
        return true;
    }

    if (IS_OP_INS(fadd_vector, op)) {
        name = "FADD";
    } else if (IS_OP_INS(fsub_vector, op)) {
        name = "FSUB";
    }
    if (name) {
        fadd_vector_t fadd = *(fadd_vector_t*)&op;
        char* vec = nullptr;
        if (fadd.op2 == 0b000101) {
            if (fadd.Q == 0b0) {
                vec = "4H";
            } else if (fadd.Q == 0b1) {
                vec = "8H";
            }
            if (vec) {
                printf("0x%016llx\t%-7s V%u.%s, V%u.%s, V%u.%s", pc, name, fadd.Rd, vec, fadd.Rn,
                       vec, fadd.Rm, vec);
                return true;
            }
        }
        if (fadd.op2 == 0b110101) {
            uint8_t sz = (fadd.op & 0b10) >> 1;
            uint8_t Q = fadd.Q;
            if (sz == 0b0 && Q == 0b0) {
                vec = "2S";
            } else if (sz == 0b0 && Q == 0b1) {
                vec = "4S";
            } else if (sz == 0b1 && Q == 0b0) {
                vec = "RESERVED";
            } else if (sz == 0b1 && Q == 0b1) {
                vec = "2D";
            }
            if (vec) {
                printf("0x%016llx\t%-7s V%u.%s, V%u.%s, V%u.%s", pc, name, fadd.Rd, vec, fadd.Rn,
                       vec, fadd.Rm, vec);
                return true;
            }
        }
    }

    if (IS_OP_INS(fmul_vector, op)) {
        name = "FMUL";
    } else if (IS_OP_INS(fdiv_vector, op)) {
        name = "FDIV";
    }
    if (name) {
        fmul_vector_t fmul = *(fmul_vector_t*)&op;
        char* vec = nullptr;
        if (fmul.op2 == 0b000111) {
            if (fmul.Q == 0b0) {
                vec = "4H";
            } else if (fmul.Q == 0b1) {
                vec = "8H";
            }
            if (vec) {
                printf("0x%016llx\t%-7s V%u.%s, V%u.%s, V%u.%s", pc, name, fmul.Rd, vec, fmul.Rn,
                       vec, fmul.Rm, vec);
                return true;
            }
        }
        if (fmul.op2 == 0b110111) {
            uint8_t sz = (fmul.op & 0b10) >> 1;
            uint8_t Q = fmul.Q;
            if (sz == 0b0 && Q == 0b0) {
                vec = "2S";
            } else if (sz == 0b0 && Q == 0b1) {
                vec = "4S";
            } else if (sz == 0b1 && Q == 0b0) {
                vec = "RESERVED";
            } else if (sz == 0b1 && Q == 0b1) {
                vec = "2D";
            }
            if (vec) {
                printf("0x%016llx\t%-7s V%u.%s, V%u.%s, V%u.%s", pc, name, fmul.Rd, vec, fmul.Rn,
                       vec, fmul.Rm, vec);
                return true;
            }
        }
    }

    if (IS_OP_INS(fcvtzs_vector, op)) {
        fcvtzs_vector_t fcvtzs = *(fcvtzs_vector_t*)&op;
        name = "FCVTZS";
        bool scalar_fp16 = fcvtzs.Z == 0b0 && fcvtzs.Q == 0b1 && fcvtzs.op == 0b0111101 &&
                           fcvtzs.sz == 0b1 && fcvtzs.op2 == 0b111001101110;
        bool scalar_fp32_fp64 = fcvtzs.Z == 0b0 && fcvtzs.Q == 0b1 && fcvtzs.op == 0b0111101 &&
                                fcvtzs.op2 == 0b100001101110;
        bool vector_fp16 = fcvtzs.Z == 0b0 && fcvtzs.op == 0b0011101 && fcvtzs.sz == 0b1 &&
                           fcvtzs.op2 == 0b1111001101110;
        bool vector_fp32_fp64 =
            fcvtzs.Z == 0b0 && fcvtzs.op == 0b0011101 && fcvtzs.op2 == 0b100001101110;
        if (scalar_fp16) {
            printf("0x%016llx\t%-7s H%u, H%u", pc, name, fcvtzs.Rd, fcvtzs.Rn);
            return true;
        } else if (scalar_fp32_fp64) {
            printf("0x%016llx\t%-7s V%u, V%u", pc, name, fcvtzs.Rd, fcvtzs.Rn);
            return true;
        } else if (vector_fp16) {
            uint8_t Q = fcvtzs.Q;
            char* vector = nullptr;
            if (Q == 0b0) {
                vector = "4H";
            } else if (Q == 0b1) {
                vector = "8H";
            }
            printf("0x%016llx\t%-7s V%u.%s, V%u.%s", pc, name, fcvtzs.Rd, vector, fcvtzs.Rn,
                   vector);
            return true;
        } else if (vector_fp32_fp64) {
            uint8_t Q = fcvtzs.Q;
            uint8_t sz = fcvtzs.sz;
            char* vector = nullptr;
            if (sz == 0b0 && Q == 0b0) {
                vector = "2S";
            } else if (sz == 0b0 && Q == 0b1) {
                vector = "4S";
            } else if (sz == 0b1 && Q == 0b0) {
                vector = "RESERVED";
            } else if (sz == 0b1 && Q == 0b1) {
                vector = "2D";
            }
            printf("0x%016llx\t%-7s V%u.%s, V%u.%s", pc, name, fcvtzs.Rd, vector, fcvtzs.Rn,
                   vector);
            return true;
        }
    }

    if (IS_OP_INS(fcvtzs_fixed_vector, op)) {
        fcvtzs_fixed_vector_t fcvtzs = *(fcvtzs_fixed_vector_t*)&op;
        bool scalar = (fcvtzs.Q == 0b1 && fcvtzs.op == 0b0111110);
        bool vector = fcvtzs.op == 0b0011110;
        uint64_t fbits = (fcvtzs.immh << 3) | fcvtzs.immb;
        name = "FCVTZS";
        char* V = nullptr;
        char* T = nullptr;
        if ((fcvtzs.immh & 0b1110) == 0b0010) {
            V = "H";
        } else if ((fcvtzs.immh & 0b1100) == 0b0100) {
            V = "S";
        } else if ((fcvtzs.immh & 0b1000) == 0b1000) {
            V = "D";
        }
        if (scalar) {
            printf("0x%016llx\t%-7s %s%u, %s%u, #%llu", pc, name, V, fcvtzs.Rd, V, fcvtzs.Rn,
                   fbits);
            return true;
        }
        if ((fcvtzs.immh & 0b1111) == 0b0001) {
            T = "RESERVED";
        } else if ((fcvtzs.immh & 0b1110) == 0b0010) {
            if (fcvtzs.Q == 0b0) {
                T = "4H";
            } else if (fcvtzs.Q == 0b1) {
                T = "8H";
            }
        } else if ((fcvtzs.immh & 0b1100) == 0b0100) {
            if (fcvtzs.Q == 0b0) {
                T = "2S";
            } else if (fcvtzs.Q == 0b1) {
                T = "4S";
            }
        } else if ((fcvtzs.immh & 0b1000) == 0b1000) {
            if (fcvtzs.Q == 0b0) {
                T = "RESERVED";
            } else if (fcvtzs.Q == 0b1) {
                T = "2D";
            }
        }
        if (vector) {
            printf("0x%016llx\t%-7s V%u.%s, V%u.%s, #%llu", pc, name, fcvtzs.Rd, T, fcvtzs.Rn, T,
                   fbits);
            return true;
        }
    }
    if (IS_OP_INS(str_simd_fp_imm_pre, op) || IS_OP_INS(str_simd_fp_imm_post, op)) {
        name = "STR";
    } else if (IS_OP_INS(ldr_simd_fp_imm_pre, op) || IS_OP_INS(ldr_simd_fp_imm_post, op)) {
        name = "LDR";
    }
    if (name) {
        str_simd_fp_imm_t str = *(str_simd_fp_imm_t*)&op;
        int64_t imm;
        uint8_t size = str.size;
        uint8_t opc = (str.opc & 0b100) >> 2;
        char* vector = nullptr;
        if (size == 0b00 && opc == 0b00) {
            vector = "B";
        } else if (size == 0b01 && opc == 0b0) {
            vector = "H";
        } else if (size == 0b10 && opc == 0b0) {
            vector = "S";
        } else if (size == 0b11 && opc == 0b0) {
            vector = "D";
        } else if (size == 0b00 && opc == 0b1) {
            vector = "Q";
        }
        bool sign = (str.imm & 0b100000000);
        if (sign) {
            imm = 0x1UL << 63;
            imm |= ((int64_t)str.imm & 0b11111111);
            for (int i = 8; i < 64; i++) {
                imm |= (1UL << i);
            }
            imm *= -1;
        } else {
            imm = str.imm;
        }
        if (IS_OP_INS(str_simd_fp_imm_pre, op) || IS_OP_INS(ldr_simd_fp_imm_pre, op)) {
            printf("0x%016llx\t%-7s %s%u, [%s, #%s0x%llx]!", pc, name, vector, str.Rt,
                   reg(str.Rn, true), sign ? "-" : "", imm);
            return true;
        } else if (IS_OP_INS(str_simd_fp_imm_post, op) || IS_OP_INS(ldr_simd_fp_imm_post, op)) {
            printf("0x%016llx\t%-7s %s%u, [%s], #%s0x%llx", pc, name, vector, str.Rt,
                   reg(str.Rn, true), sign ? "-" : "", imm);
            return true;
        }
    }

    if (IS_OP_INS(str_simd_fp_imm_uoff, op)) {
        name = "STR";
    } else if (IS_OP_INS(ldr_simd_fp_imm_uoff, op)) {
        name = "LDR";
    }
    if (name) {
        str_simd_fp_imm_uoff_t str = *(str_simd_fp_imm_uoff_t*)&op;
        uint64_t imm = str.imm;
        uint8_t size = str.size;
        uint8_t opc = (str.opc & 0b100) >> 2;
        char* vector = nullptr;
        name = "STR";
        if (size == 0b00 && opc == 0b0) {
            vector = "B";
        } else if (size == 0b01 && opc == 0b0) {
            vector = "H";
            imm <<= 1;
        } else if (size == 0b10 && opc == 0b0) {
            vector = "S";
            imm <<= 2;
        } else if (size == 0b11 && opc == 0b0) {
            vector = "D";
            imm <<= 3;
        } else if (size == 0b00 && opc == 0b1) {
            vector = "Q";
            imm <<= 4;
        }
        printf("0x%016llx\t%-7s %s%u, [%s, #0x%llx]", pc, name, vector, str.Rt, reg(str.Rn, true),
               imm);
        return true;
    }
    if (IS_OP_INS(str_simd_fp_reg, op)) {
        name = "STR";
    } else if (IS_OP_INS(ldr_simd_fp_reg, op)) {
        name = "LDR";
    }
    if (name) {
        str_simd_fp_reg_t str = *(str_simd_fp_reg_t*)&op;
        uint8_t option = str.option;
        uint8_t size = str.size;
        uint8_t opc = (str.opc & 0b100) >> 2;
        uint8_t S = str.S;
        char* vector = nullptr;
        uint8_t amount = 0;
        if (size == 0b00 && opc == 0b0) {
            vector = "B";
        } else if (size == 0b01 && opc == 0b0) {
            vector = "H";
            amount = S == 0b1 ? 1 : 0;
        } else if (size == 0b10 && opc == 0b0) {
            vector = "S";
            amount = S == 0b1 ? 2 : 0;
        } else if (size == 0b11 && opc == 0b0) {
            vector = "D";
            amount = S == 0b1 ? 3 : 0;
        } else if (size == 0b00 && opc == 0b1) {
            vector = "Q";
            amount = S == 0b1 ? 4 : 0;
        }
        printf("0x%016llx\t%-7s %s%u, [%s, %s, %s %u]", pc, name, vector, str.Rt, reg(str.Rn, true),
               reg(str.Rm, true), ext(option), amount);
        return true;
    }

    if (IS_OP_INS(stp_simd_fp_pre, op) || IS_OP_INS(stp_simd_fp_post, op) ||
        IS_OP_INS(stp_simd_fp_soff, op)) {
        name = "STP";
    } else if (IS_OP_INS(ldp_simd_fp_pre, op) || IS_OP_INS(ldp_simd_fp_post, op) ||
               IS_OP_INS(ldp_simd_fp_soff, op)) {
        name = "LDP";
    }
    if (name) {
        stp_simd_fp_t stp = *(stp_simd_fp_t*)&op;
        bool sign = stp.imm & 0b1000000;
        uint8_t opc = stp.opc;
        int64_t imm = ((int64_t)stp.imm & 0b111111) << (2 + opc);
        char* fp = nullptr;
        if (sign) {
            imm |= ((int64_t)stp.imm & 0b11111111);
            for (int i = 8; i < 64; i++) {
                imm |= (1UL << i);
            }
            imm *= -1;
        } else {
            imm = stp.imm;
        }
        if (opc == 0b00) {
            fp = "S";
            imm *= 4;
        } else if (opc == 0b01) {
            fp = "D";
            imm *= 8;
        } else if (opc == 0b10) {
            fp = "Q";
            imm *= 16;
        }
        if (IS_OP_INS(stp_simd_fp_pre, op) || IS_OP_INS(ldp_simd_fp_pre, op)) {
            printf("0x%016llx\t%-7s %s%u, %s%u, [%s, #%s0x%llx]!", pc, name, fp, stp.Rt, fp,
                   stp.Rt2, reg(stp.Rn, true), sign ? "-" : "", imm);
            return true;
        } else if (IS_OP_INS(stp_simd_fp_soff, op) || IS_OP_INS(ldp_simd_fp_soff, op)) {
            printf("0x%016llx\t%-7s %s%u, %s%u, [%s, #%s0x%llx]", pc, name, fp, stp.Rt, fp, stp.Rt2,
                   reg(stp.Rn, true), sign ? "-" : "", imm);
            return true;
        } else if (IS_OP_INS(stp_simd_fp_post, op) || IS_OP_INS(ldp_simd_fp_post, op)) {
            printf("0x%016llx\t%-7s %s%u, %s%u, [%s], #%s0x%llx", pc, name, fp, stp.Rt, fp, stp.Rt2,
                   reg(stp.Rn, true), sign ? "-" : "", imm);
            return true;
        }
    }

    if (IS_OP_INS(and_vector, op)) {
        name = "AND";
    } else if (IS_OP_INS(eor_vector, op)) {
        name = "EOR";
    } else if (IS_OP_INS(orr_vector, op)) {
        name = "ORR";
    } else if (IS_OP_INS(orn_vector, op)) {
        name = "ORN";
    } else if (IS_OP_INS(bic_vector, op)) {
        name = "BIC";
    } else if (IS_OP_INS(bit_vector, op)) {
        name = "BIT";
    } else if (IS_OP_INS(bif_vector, op)) {
        name = "BIF";
    } else if (IS_OP_INS(bsl_vector, op)) {
        name = "BSL";
    }
    if (name) {
        and_vector_t and_v = *(and_vector_t*)&op;
        char* vector = "nullptr";
        if (and_v.Q == 0b0) {
            vector = "8B";
        } else if (and_v.Q == 0b1) {
            vector = "16B";
        }
        printf("0x%016llx\t%-7s V%u.%s, V%u.%s, V%u.%s", pc, name, and_v.Rd, vector, and_v.Rn,
               vector, and_v.Rm, vector);
        return true;
    }
    if (IS_OP_INS(xar_vector, op)) {
        xar_vector_t xar = *(xar_vector_t*)&op;
        printf("0x%016llx\t%-7s V%u,2D, V%u.2D, V%u.2D", pc, "XAR", xar.Rd, xar.Rn, xar.Rm);
        return true;
    }
    return false;
}

namespace arch {
namespace arm64 {
namespace disassembler {
bool Disassemble(MachO* macho, uint64_t pc, uint32_t op) {
    if (disassemble_arith(macho, pc, op)) {
        return true;
    } else if (disassemble_logic(macho, pc, op)) {
        return true;
    } else if (disassemble_movknz(macho, pc, op)) {
        return true;
    } else if (disassemble_memory(macho, pc, op)) {
        return true;
    } else if (disassemble_adr_b(macho, pc, op)) {
        return true;
    } else if (disassemble_pac(macho, pc, op)) {
        return true;
    } else if (disassemble_sys(macho, pc, op)) {
        return true;
    } else if (disassemble_fp_simd(macho, pc, op)) {
        return true;
    } else if (is_nop(&op)) {
        printf("0x%016llx\t%-7s", pc, "NOP");
        return true;
    }
    return false;
}

void Disassemble(MachO* macho, mach_vm_address_t start, uint64_t* length) {
    mach_vm_address_t current = start;
    mach_vm_address_t end = start + *length;
    if (*length) {
        while (current < end) {
            uint32_t op = *reinterpret_cast<uint32_t*>(macho->GetBufferAddress(current));
            bool ok = arch::arm64::disassembler::Disassemble(macho, current, op);
            if (ok) {
                printf("\n");
            }
            current += sizeof(uint32_t);
        }
    } else {
        uint32_t op = *(uint32_t*)macho->GetBufferAddress(current);
        while (!is_ret(&op)) {
            op = *reinterpret_cast<uint32_t*>(macho->GetBufferAddress(current));
            bool ok = arch::arm64::disassembler::Disassemble(macho, current, op);
            if (ok) {
                printf("\n");
            }
            current += sizeof(uint32_t);
        }
    }
}
} // namespace disassembler
} // namespace arm64
} // namespace arch
