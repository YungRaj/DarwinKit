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

#include "assemble.h"
#include "macho.h"

#include "strparse.h"

using namespace arch::arm64;
using namespace arch::arm64::assembler;

uint32_t n_digits(uint64_t val, uint8_t digit) {
    bool loop = false;
    int nbit = 63;
    uint32_t max = 0;
    uint32_t digits = 0;
    while (nbit >= 0) {
        uint8_t bit = (val & (1UL << nbit)) >> nbit;
        if (bit == digit) {
            digits++;
            if (nbit == 0) {
                nbit = 64;
                loop = true;
            }
        } else {
            if (digits > max) {
                max = digits;
            } if (loop) {
                break;
            }
            digits = 0;
        }
        nbit--;
    }
    return max;
}

uint32_t n_rotate(uint64_t val, uint32_t ones, uint32_t zeroes) {
    int nbit = 63;
    uint32_t nones = 0;
    uint32_t nzeroes = 0;
    bool found = false;
    while (!found && nbit >= 0) {
        uint8_t bit = (val & (1UL << nbit)) >> nbit;
        if (bit == 0) {
            nzeroes++;
        } else {
            found = true;
            break;
        }
        nbit--;
    }
    found = false;
    while (!found && nbit >= 0) {
        uint8_t bit = (val & (1UL << nbit)) >> nbit;
        if (bit) {
            nones++;
        } else {
            found = true;
            break;
        }
        nbit--;
    }
    return nones + nzeroes;
}

bool encode_bit_masks(uint64_t imm, uint8_t* imms, uint8_t* immr, uint8_t* N) {
    uint32_t ones = n_digits(imm, 1);
    uint32_t zeroes = n_digits(imm, 0);
    uint32_t rotate = n_rotate(imm, ones, zeroes);
    uint32_t digits = ones + zeroes;
    *N = 0;
    if (digits == 64) {
        *N = 0b1;
        *imms = ones - 1;
    } else if (digits == 32) {
        *imms = (ones - 1) & 0b11111;
    } else if (digits == 16) {
        *imms = 0b100000 | ((ones - 1) & 0b1111);
    } else if (digits == 8) {
        *imms = 0b110000 | ((ones - 1) & 0b111);
    } else if (digits == 4) {
        *imms = 0b111000 | ((ones - 1) & 0b11);
    } else if (digits == 2) {
        *imms = 0b111100 | ((ones - 1) & 0b1);
    } else {
        return false;
    }
    *immr = rotate;
    return true;
}

uint8_t get_reg(char* operand) {
    uint8_t reg;
    char* op = operand;
    if (strcmp(op, "SP") == 0) {
        return 0x1F;
    } else if (strcmp(op, "WSP") == 0) {
        return 0x1F;
    }
    while (*op < '0' || *op > '9') {
        op++;
    }
    reg = strtoul(op, nullptr, 10);
    return reg;
}

uint64_t get_imm(char* operand, int base) {
    uint64_t imm;
    char* op = operand;
    while (*op < '0' || *op > '9') {
        op++;
    }
    imm = strtoul(op, nullptr, base);
    return imm;
}

uint64_t get_signed_imm(char* operand, int base, bool* sign) {
    uint64_t imm;
    char* op = operand;
    *sign = false;
    while (*op < '0' || *op > '9') {
        if (*op == '-') {
            *sign = true;
        }
        op++;
    }
    imm = strtoul(op, nullptr, base);
    return imm;
}

uint8_t get_cond(char* condition) {
    if (strcmp(condition, "EQ") == 0) {
        return 0b0000;
    } if (strcmp(condition, "NE") == 0) {
        return 0b0001;
    } if (strcmp(condition, "CS") == 0) {
        return 0b0010;
    } if (strcmp(condition, "CC") == 0) {
        return 0b0011;
    } if (strcmp(condition, "MI") == 0) {
        return 0b0100;
    } if (strcmp(condition, "PL") == 0) {
        return 0b0101;
    } if (strcmp(condition, "VS") == 0) {
        return 0b0110;
    } if (strcmp(condition, "VC") == 0) {
        return 0b0111;
    } if (strcmp(condition, "HI") == 0) {
        return 0b1000;
    } if (strcmp(condition, "LS") == 0) {
        return 0b1001;
    } if (strcmp(condition, "GE") == 0) {
        return 0b1010;
    } if (strcmp(condition, "GT") == 0) {
        return 0b1100;
    } if (strcmp(condition, "LE") == 0) {
        return 0b1101;
    } if (strcmp(condition, "AL") == 0) {
        return 0b1111;
    }
    return 0;
}

bool get_shift(char* operand, uint8_t* shift, uint8_t* shift_op) {
    char* op = operand;
    bool found = false;
    while (*op < '0' || *op > '9') {
        if (strcmp(op, "LSL") == 0) {
            *shift_op = 0b00;
            found = true;
        } else if (strcmp(op, "LSR") == 0) {
            *shift_op = 0b01;
            found = true;
        } else if (strcmp(op, "ASR") == 0) {
            *shift_op = 0b10;
            found = true;
        } else if (strcmp(op, "ROR") == 0) {
            *shift_op = 0b11;
            found = true;
        }
        op++;
    }
    *shift = (uint8_t)strtoul(op, nullptr, 10);
    return found;
}

bool get_extend(char* operand, bool sf, uint8_t* option, uint8_t* amount) {
    if (strstr(operand, "UXTB")) {
        *option = 0b000;
    } else if (strstr(operand, "UXTH")) {
        *option = 0b001;
    } else if (strstr(operand, "UXTW")) {
        *option = 0b010;
    } else if (strstr(operand, "UXTX")) {
        *option = 0b011;
    } else if (strstr(operand, "SXTB")) {
        *option = 0b100;
    } else if (strstr(operand, "SXTH")) {
        *option = 0b101;
    } else if (strstr(operand, "SXTW")) {
        *option = 0b110;
    } else if (strstr(operand, "SXTX")) {
        *option = 0b111;
    } else if (strstr(operand, "LSL")) {
        if (sf) {
            *option = 0b010;
        } else {
            *option = 0b011;
        }
    } else {
        return false;
    }
    *amount = get_imm(operand, 10);
    return true;
}

char* get_mnemonic(char* ins) {
    char* mnemonic;
    char* operands;
    operands = strchr(ins, ' ');
    if (!operands) {
        return ins;
    }
    operands++;
    mnemonic = reinterpret_cast<char*>(new char[operands - ins]);
    memcpy(mnemonic, ins, (operands - ins) - 1);
    mnemonic[(operands - ins) - 1] = '\0';
    return mnemonic;
}

size_t get_operands_count(char* ins) {
    size_t count = 0;
    ins = strdup(ins);
    char* rest = strdup(strchr(ins, ' ')) + 1;
    if (!rest) {
        return 0;
    }
    char* tmp = rest;
    char* delim = ", ";
    char delim2 = '[';
    char delim3 = ']';
    char* last_delim = nullptr;
    while (*tmp) {
        if (strncmp(tmp, delim, strlen(delim)) == 0) {
            count++;
            last_delim = tmp;
        }
        if (*tmp == delim2) {
            count++;
        }
        if (*tmp == delim3) {
            count++;
            tmp++;
            if (*tmp && strncmp(tmp, delim, strlen(delim)) != 0) {
                count++;
            } else {
                continue;
            }
        }
        tmp++;
    }
    count++;
    if (rest[strlen(rest) - 1] == ',') {
        return 0;
    }
    return count;
}

char** get_operands(char* ins, size_t count) {
    char** operands;
    char* delim = ", ";
    ins = strdup(ins);
    char* rest = strdup(strchr(ins, ' ')) + 1;
    operands = reinterpret_cast<char**>(new char*[count]);
    rest = strdup(rest);
    size_t idx = 0;
    char* token = strtokmul(rest, delim);
    while (token) {
        if (*token == '[') {
            operands[idx++] = "[";
            token = token + 1;
            if (strchr(token, ']')) {
                char* s = strchr(token, ']');
                token[s - token] = '\0';
                operands[idx++] = strdup(token);
                operands[idx++] = "]";
                token = strtokmul(nullptr, delim);
                continue;
            }
        } else if (strchr(token, ']')) {
            if (strchr(token, ']') - token != strlen(token) - 1) {
                char* s = strchr(token, ']');
                token[s - token] = '\0';
                operands[idx++] = strdup(token);
                operands[idx++] = "]";
                operands[idx++] = s + 1;
                token = strtokmul(nullptr, delim);
                continue;
            }
            operands[idx] = strdup(token);
            operands[idx][strchr(token, ']') - token] = '\0';
            idx++;
            operands[idx++] = "]";
            token = strtokmul(nullptr, delim);
            continue;
        }
        operands[idx++] = strdup(token);
        token = strtokmul(nullptr, delim);
    }
    if (idx != count) {
        delete operands;
        return nullptr;
    }
    return operands;
}

uint32_t assemble_arith(char* ins) {
    uint32_t assembly;
    char* mnemonic = nullptr;
    char** operands = nullptr;
    size_t count = 0;
    mnemonic = get_mnemonic(ins);
    if (strcmp(ins, mnemonic) != 0) {
        count = get_operands_count(ins);
        operands = get_operands(ins, count);
    }
    printf("%zu operands\n", count);
    printf("%s\n", mnemonic);
    for (int i = 0; i < count; i++) {
        printf("%s\n", operands[i]);
    }
    if (count == 0 ||
        (*operands[0] != 'W' && *operands[0] != 'X' && strcmp(operands[0], "SP") != 0)) {
        return 0;
    }
    assembly = 0;
    if (strcmp(mnemonic, "ADC") == 0) {
        if (count == 3) {
            adc_t adc;
            adc.op1 = 0b00111010000;
            adc.op2 = 0b000000;
            if (*operands[0] == 'X') {
                adc.sf = 0b1;
            } else if (*operands[0] == 'W') {
                adc.sf = 0b0;
            } else {
                return 0;
            }
            adc.Rm = get_reg(operands[2]);
            adc.Rn = get_reg(operands[1]);
            adc.Rd = get_reg(operands[0]);
            memcpy(&assembly, &adc, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "ADCS") == 0) {
        if (count == 3) {
            adc_t adcs;
            adcs.op1 = 0b0111010000;
            adcs.op2 = 0b000000;
            if (*operands[0] == 'X') {
                adcs.sf = 0b1;
            } else if (*operands[0] == 'W') {
                adcs.sf = 0b0;
            } else {
                return 0;
            }
            adcs.Rm = get_reg(operands[2]);
            adcs.Rn = get_reg(operands[1]);
            adcs.Rd = get_reg(operands[0]);
            memcpy(&assembly, &adcs, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "NGC") == 0) {
        if (count == 2) {
            ngc_t ngc;
            ngc.op1 = 0b1011010000;
            ngc.op2 = 0b000000;
            if (*operands[0] == 'X') {
                ngc.sf = 0b1;
            } else if (*operands[0] == 'W') {
                ngc.sf = 0b0;
            } else {
                return 0;
            }
            ngc.Rm = get_reg(operands[1]);
            ngc.Rn = 0b11111;
            ngc.Rd = get_reg(operands[0]);
            memcpy(&assembly, &ngc, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "NGCS") == 0) {
        if (count == 2) {
            ngc_t ngcs;
            ngcs.op1 = 0b1111010000;
            ngcs.op2 = 0b000000;
            if (*operands[0] == 'X') {
                ngcs.sf = 0b1;
            } else if (*operands[0] == 'W') {
                ngcs.sf = 0b0;
            } else {
                return 0;
            }
            ngcs.Rm = get_reg(operands[1]);
            ngcs.Rn = 0b11111;
            ngcs.Rd = get_reg(operands[0]);
            memcpy(&assembly, &ngcs, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "SBC") == 0) {
        if (count == 3) {
            sbc_t sbc;
            sbc.op1 = 0b1011010000;
            sbc.op2 = 0b000000;
            if (*operands[0] == 'X') {
                sbc.sf = 0b1;
            } else if (*operands[0] == 'W') {
                sbc.sf = 0b0;
            } else {
                return 0;
            }
            sbc.Rm = get_reg(operands[2]);
            sbc.Rn = get_reg(operands[1]);
            sbc.Rd = get_reg(operands[0]);
            memcpy(&assembly, &sbc, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "CMP") == 0) {
    }

    if (strcmp(mnemonic, "CMN") == 0) {
    }

    if (strcmp(mnemonic, "ADD") == 0 || strcmp(mnemonic, "ADDS") == 0 ||
        strcmp(mnemonic, "SUB") == 0 || strcmp(mnemonic, "SUBS") == 0) {
        uint8_t imm = 0;
        uint8_t shift;
        uint8_t option;
        uint8_t amount;
        if (count == 3 &&
            (*operands[2] == 'X' || *operands[2] == 'W' || strcmp(operands[2], "SP") == 0)) {
            add_reg_t add;
            if (strcmp(mnemonic, "ADD") == 0) {
                add.op1 = 0b0001011;
            } else if (strcmp(mnemonic, "ADDS") == 0) {
                add.op1 = 0b0101011;
            } else if (strcmp(mnemonic, "SUB") == 0) {
                add.op1 = 0b1001011;
            } else if (strcmp(mnemonic, "SUBS") == 0) {
                add.op1 = 0b1101011;
            }
            add.op2 = 0b0;
            if (*operands[0] == 'X' || strcmp(operands[0], "SP") == 0) {
                add.sf = 0b1;
            } else if (*operands[0] == 'W') {
                add.sf = 0b0;
            } else {
                return 0;
            }
            add.Rm = get_reg(operands[2]);
            add.Rn = get_reg(operands[1]);
            add.Rd = get_reg(operands[0]);
            add.imm = 0b000000;
            add.shift = 0b00;
            memcpy(&assembly, &add, sizeof(uint32_t));
            return assembly;

        } else if (count == 3) {
            add_imm_t add;
            if (strcmp(mnemonic, "ADD") == 0) {
                add.op = 0b00100010;
            } else if (strcmp(mnemonic, "ADDS") == 0) {
                add.op = 0b01100010;
            } else if (strcmp(mnemonic, "SUB") == 0) {
                add.op = 0b10100010;
            } else if (strcmp(mnemonic, "SUBS") == 0) {
                add.op = 0b11100010;
            }
            if (*operands[0] == 'X' || strcmp(operands[0], "SP") == 0) {
                add.sf = 0b1;
            } else if (*operands[0] == 'W') {
                add.sf = 0b0;
            } else {
                return 0;
            }
            add.imm = static_cast<uint32_t>(get_imm(operands[2], 16));
            add.sh = 0b0;
            add.Rn = get_reg(operands[1]);
            add.Rd = get_reg(operands[0]);
            memcpy(&assembly, &add, sizeof(uint32_t));
            return assembly;
        } else if (count == 4 && get_shift(operands[3], &imm, &shift)) {
            add_reg_t add;
            if (strcmp(mnemonic, "ADD") == 0) {
                add.op1 = 0b0001011;
            } else if (strcmp(mnemonic, "ADDS") == 0) {
                add.op1 = 0b0101011;
            } else if (strcmp(mnemonic, "SUB") == 0) {
                add.op1 = 0b1001011;
            } else if (strcmp(mnemonic, "SUBS") == 0) {
                add.op1 = 0b1101011;
            }
            add.op2 = 0b0;
            if (*operands[0] == 'X' || strcmp(operands[0], "SP") == 0) {
                add.sf = 0b1;
            } else if (*operands[0] == 'W') {
                add.sf = 0b0;
            } else {
                return 0;
            }
            add.Rm = get_reg(operands[2]);
            add.Rn = get_reg(operands[1]);
            add.Rd = get_reg(operands[0]);
            add.imm = imm;
            add.shift = shift;
            memcpy(&assembly, &add, sizeof(uint32_t));
            return assembly;
        } else if (count == 4 && get_extend(operands[3], true, &option, &amount)) {
            add_ext_t add;
            if (strcmp(mnemonic, "ADD") == 0) {
                add.op = 0b0001011001;
            } else if (strcmp(mnemonic, "ADDS") == 0) {
                add.op = 0b0101011001;
            } else if (strcmp(mnemonic, "SUB") == 0) {
                add.op = 0b1001011001;
            } else if (strcmp(mnemonic, "SUBS") == 0) {
                add.op = 0b1101011001;
            }
            if (*operands[0] == 'X' || strcmp(operands[0], "SP") == 0) {
                add.sf = 0b1;
            } else if (*operands[0] == 'W') {
                add.sf = 0b0;
            } else {
                return 0;
            }
            get_extend(operands[3], add.sf, &option, &amount);
            add.option = option;
            add.imm = amount;
            add.Rm = get_reg(operands[2]);
            add.Rn = get_reg(operands[1]);
            add.Rd = get_reg(operands[0]);
            memcpy(&assembly, &add, sizeof(uint32_t));
            return assembly;
        } else if (count == 4) {
            add_imm_t add;
            if (strcmp(mnemonic, "ADD") == 0) {
                add.op = 0b00100010;
            } else if (strcmp(mnemonic, "ADDS") == 0) {
                add.op = 0b01100010;
            } else if (strcmp(mnemonic, "SUB") == 0) {
                add.op = 0b10100010;
            } else if (strcmp(mnemonic, "SUBS") == 0) {
                add.op = 0b11100010;
            }
            if (*operands[0] == 'X' || strcmp(operands[0], "SP") == 0) {
                add.sf = 0b1;
            } else if (*operands[0] == 'W') {
                add.sf = 0b0;
            } else {
                return 0;
            }
            add.imm = static_cast<uint32_t>(get_imm(operands[2], 16));
            add.sh = 0b0;
            add.Rn = get_reg(operands[1]);
            add.Rd = get_reg(operands[0]);
            if (strstr(operands[3], "LSL") && get_imm(operands[3], 10) == 0) {
                add.sh = 0b0;
            } else if (strstr(operands[3], "LSL") && get_imm(operands[3], 10) == 12) {
                add.sh = 0b1;
            } else {
                return 0;
            }
            memcpy(&assembly, &add, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "NEG") == 0) {
        if (count == 2) {
            neg_t neg;
            neg.op = 0b1001011;
            neg.z = 0b0;
            if (*operands[0] == 'X') {
                neg.sf = 0b1;
            } else if (*operands[0] == 'W') {
                neg.sf = 0b0;
            } else {
                return 0;
            }
            neg.shift = 0;
            neg.imm = 0;
            neg.Rm = get_reg(operands[1]);
            neg.Rn = 0b11111;
            neg.Rd = get_reg(operands[0]);
            memcpy(&assembly, &neg, sizeof(uint32_t));
            return assembly;
        } else if (count == 3) {
            neg_t neg;
            neg.op = 0b1001011;
            neg.z = 0b0;
            if (*operands[0] == 'X') {
                neg.sf = 0b1;
            } else if (*operands[0] == 'W') {
                neg.sf = 0b0;
            } else {
                return 0;
            }
            uint8_t imm = 0;
            uint8_t shift;
            if (get_shift(operands[2], &imm, &shift)) {
                neg.shift = shift;
            } else {
                neg.shift = 0;
            }
            neg.imm = imm;
            neg.Rm = get_reg(operands[1]);
            neg.Rn = 0b11111;
            neg.Rd = get_reg(operands[0]);
            memcpy(&assembly, &neg, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "ASR") == 0) {
        if (count == 3 && (*operands[2] == 'X' || *operands[2] == 'W')) {
            asr_reg_t asr;
            asr.op = 0b0011010110;
            asr.op2 = 0b001010;
            if (*operands[0] == 'X') {
                asr.sf = 0b1;
            } else if (*operands[0] == 'W') {
                asr.sf = 0b0;
            } else {
                return 0;
            }
            asr.Rm = get_reg(operands[2]);
            asr.Rn = get_reg(operands[1]);
            asr.Rd = get_reg(operands[0]);
            memcpy(&assembly, &asr, sizeof(uint32_t));
            return assembly;
        } else if (count == 3) {
            asr_imm_t asr;
            asr.op = 0b00100110;
            if (*operands[0] == 'X') {
                asr.sf = 0b1;
                asr.N = 0b1;
                asr.imms = 0b111111;
            } else if (*operands[0] == 'W') {
                asr.sf = 0b0;
                asr.N = 0b0;
                asr.imms = 0b011111;
            } else {
                return 0;
            }
            asr.immr = static_cast<uint32_t>(get_imm(operands[2], 10));
            asr.Rn = get_reg(operands[1]);
            asr.Rd = get_reg(operands[0]);
            memcpy(&assembly, &asr, sizeof(uint32_t));
            return assembly;
        }
    }
    return assembly;
}

uint32_t assemble_logic(char* ins) {
    uint32_t assembly;
    char* mnemonic = nullptr;
    char** operands = nullptr;
    size_t count = 0;
    mnemonic = get_mnemonic(ins);
    if (strcmp(ins, mnemonic) != 0) {
        count = get_operands_count(ins);
        operands = get_operands(ins, count);
    }
    if (count == 0 ||
        (*operands[0] != 'W' && *operands[0] != 'X' && strcmp(operands[0], "SP") != 0)) {
        return 0;
    }
    assembly = 0;
    if (strcmp(mnemonic, "TST") == 0) {
        if (count == 3 || (count == 2 && (*operands[1] == 'W' || *operands[1] == 'W'))) {
            tst_shift_t tst;
            tst.op = 0b1101010;
            uint8_t imm;
            uint8_t shift;
            if (get_shift(operands[2], &imm, &shift)) {
                tst.shift = shift;
            } else {
                tst.shift = 0;
            }
            tst.N = 0b0;
            tst.Rm = get_reg(operands[1]);
            tst.Rn = get_reg(operands[0]);
            tst.Rd = 0b11111;
            tst.imm = imm;
            memcpy(&assembly, &tst, sizeof(uint32_t));
            return assembly;
        } else if (count == 2) {
            tst_imm_t tst;
            tst.op = 0b11100100;
            if (*operands[0] == 'X') {
                tst.sf = 0b1;
            } else if (*operands[0] == 'W') {
                tst.sf = 0b0;
            } else {
                return 0;
            }
            uint8_t imms = 0;
            uint8_t immr = 0;
            uint8_t N = 0;
            uint64_t imm = get_imm(operands[2], 16);
            if (!encode_bit_masks(imm, &imms, &immr, &N)) {
                return 0;
            }
            tst.imms = imms;
            tst.immr = immr;
            tst.N = N;
            tst.Rn = get_reg(operands[1]);
            tst.Rd = 0b11111;
            memcpy(&assembly, &tst, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "ORR") == 0) {
        if (count == 4 || (count == 3 && (*operands[2] == 'X' || *operands[2] == 'W'))) {
            orr_shift_t orr;
            orr.op = 0b0101010;
            uint8_t imm = 0;
            uint8_t shift;
            if (get_shift(operands[3], &imm, &shift)) {
                orr.shift = shift;
            } else {
                orr.shift = 0;
            }
            orr.N = 0b0;
            orr.Rm = get_reg(operands[2]);
            orr.Rn = get_reg(operands[1]);
            orr.Rd = get_reg(operands[0]);
            orr.imm = imm;
            memcpy(&assembly, &orr, sizeof(uint32_t));
            return assembly;
        } else if (count == 3) {
            orr_t orr;
            orr.op = 0b01100100;
            if (*operands[0] == 'X' || strcmp(operands[0], "SP") == 0) {
                orr.sf = 0b1;
            } else if (*operands[0] == 'W') {
                orr.sf = 0b0;
            } else {
                return 0;
            }
            uint8_t imms = 0;
            uint8_t immr = 0;
            uint8_t N = 0;
            uint64_t imm = get_imm(operands[2], 16);
            if (!encode_bit_masks(imm, &imms, &immr, &N)) {
                return 0;
            }
            orr.imms = imms;
            orr.immr = immr;
            orr.N = N;
            orr.Rn = get_reg(operands[1]);
            orr.Rd = get_reg(operands[0]);
            memcpy(&assembly, &orr, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "ORN") == 0) {
        if (count == 4 || (count == 3 && (*operands[2] == 'X' || *operands[2] == 'W'))) {
            orn_shift_t orn;
            orn.op = 0b0101010;
            uint8_t imm = 0;
            uint8_t shift;
            if (count == 4 && get_shift(operands[3], &imm, &shift)) {
                orn.shift = shift;
            } else {
                orn.shift = 0;
            }
            orn.N = 0b1;
            orn.Rm = get_reg(operands[2]);
            orn.Rn = get_reg(operands[1]);
            orn.Rd = get_reg(operands[0]);
            orn.imm = imm;
            memcpy(&assembly, &orn, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "EOR") == 0) {
        if (count == 4 || (count == 3 && (*operands[2] == 'X' || *operands[2] == 'W'))) {
            eor_shift_t eor;
            eor.op = 0b1001010;
            if (*operands[0] == 'X') {
                eor.sf = 0b1;
            } else if (*operands[0] == 'W') {
                eor.sf = 0b0;
            } else {
                return 0;
            }
            uint8_t imm = 0;
            uint8_t shift;
            if (get_shift(operands[3], &imm, &shift)) {
                eor.shift = shift;
            } else {
                eor.shift = 0;
            }
            eor.N = 0b0;
            eor.Rm = get_reg(operands[2]);
            eor.Rn = get_reg(operands[1]);
            eor.Rd = get_reg(operands[0]);
            eor.imm = imm;
            memcpy(&assembly, &eor, sizeof(uint32_t));
            return assembly;
        } else if (count == 3) {
            eor_t eor;
            eor.op = 0b10100100;
            if (*operands[0] == 'X' || strcmp(operands[0], "SP") == 0) {
                eor.sf = 0b1;
            } else if (*operands[0] == 'W') {
                eor.sf = 0b0;
            } else {
                return 0;
            }
            uint8_t imms = 0;
            uint8_t immr = 0;
            uint8_t N = 0;
            uint64_t imm = get_imm(operands[2], 16);
            if (!encode_bit_masks(imm, &imms, &immr, &N)) {
                return 0;
            }
            eor.imms = imms;
            eor.immr = immr;
            eor.N = N;
            eor.Rn = get_reg(operands[1]);
            eor.Rd = get_reg(operands[0]);
            memcpy(&assembly, &eor, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "EON") == 0) {
        if (count == 4 || (count == 3 && (*operands[2] == 'X' || *operands[2] == 'W'))) {
            eon_shift_t eon;
            eon.op = 0b1001010;
            if (*operands[0] == 'X') {
                eon.sf = 0b1;
            } else if (*operands[0] == 'W') {
                eon.sf = 0b0;
            } else {
                return 0;
            }
            uint8_t imm = 0;
            uint8_t shift;
            if (count == 4 && get_shift(operands[3], &imm, &shift)) {
                eon.shift = shift;
            } else {
                eon.shift = 0;
            }
            eon.N = 0b1;
            eon.Rm = get_reg(operands[2]);
            eon.Rn = get_reg(operands[1]);
            eon.Rd = get_reg(operands[0]);
            eon.imm = imm;
            memcpy(&assembly, &eon, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "AND") == 0) {
        if (count == 4 || (count == 3 && (*operands[2] == 'X' || *operands[2] == 'W'))) {
            and_shift_t and_s;
            and_s.op = 0b0001010;
            if (*operands[0] == 'X') {
                and_s.sf = 0b1;
            } else if (*operands[0] == 'W') {
                and_s.sf = 0b0;
            } else {
                return 0;
            }
            uint8_t imm = 0;
            uint8_t shift;
            if (count == 4 && get_shift(operands[3], &imm, &shift)) {
                and_s.shift = shift;
            } else {
                and_s.shift = 0;
            }
            and_s.N = 0b1;
            and_s.Rm = get_reg(operands[2]);
            and_s.Rn = get_reg(operands[1]);
            and_s.Rd = get_reg(operands[0]);
            and_s.imm = imm;
            memcpy(&assembly, &and_s, sizeof(uint32_t));
            return assembly;
        } else if (count == 3) {
            and_imm_t and_imm;
            and_imm.op = 0b00100100;
            if (*operands[0] == 'X' || strcmp(operands[0], "SP") == 0) {
                and_imm.sf = 0b1;
            } else if (*operands[0] == 'W') {
                and_imm.sf = 0b0;
            } else {
                return 0;
            }
            uint8_t imms = 0;
            uint8_t immr = 0;
            uint8_t N = 0;
            uint64_t imm = get_imm(operands[2], 16);
            if (!encode_bit_masks(imm, &imms, &immr, &N)) {
                return 0;
            }
            and_imm.imms = imms;
            and_imm.immr = immr;
            and_imm.N = N;
            and_imm.Rn = get_reg(operands[1]);
            and_imm.Rd = get_reg(operands[0]);
            memcpy(&assembly, &and_imm, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "ANDS") == 0) {
        if (count == 4 || (count == 3 && (*operands[2] == 'X' || *operands[2] == 'W'))) {
            ands_shift_t ands;
            ands.op = 0b1101010;
            if (*operands[0] == 'X') {
                ands.sf = 0b1;
            } else if (*operands[0] == 'W') {
                ands.sf = 0b0;
            } else {
                return 0;
            }
            uint8_t imm = 0;
            uint8_t shift;
            if (count == 4 && get_shift(operands[3], &imm, &shift)) {
                ands.shift = shift;
            } else {
                ands.shift = 0;
            }
            ands.N = 0b1;
            ands.Rm = get_reg(operands[2]);
            ands.Rn = get_reg(operands[1]);
            ands.Rd = get_reg(operands[0]);
            ands.imm = imm;
            memcpy(&assembly, &ands, sizeof(uint32_t));
            return assembly;;
        } else if (count == 3) {
            ands_imm_t ands;
            ands.op = 0b11100100;
            if (*operands[0] == 'X' || strcmp(operands[0], "SP") == 0) {
                ands.sf = 0b1;
            } else if (*operands[0] == 'W') {
                ands.sf = 0b0;
            } else {
                return 0;
            }
            uint8_t imms = 0;
            uint8_t immr = 0;
            uint8_t N = 0;
            uint64_t imm = get_imm(operands[2], 16);
            if (!encode_bit_masks(imm, &imms, &immr, &N)) {
                return 0;
            }
            ands.imms = imms;
            ands.immr = immr;
            ands.N = N;
            ands.Rn = get_reg(operands[1]);
            ands.Rd = get_reg(operands[0]);
            memcpy(&assembly, &ands, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "MVN") == 0) {
        if (count == 3) {
            mvn_t mvn;
            mvn.op = 0b0101010;
            if (*operands[0] == 'X') {
                mvn.sf = 0b1;
            } else if (*operands[0] == 'W') {
                mvn.sf = 0b0;
            } else {
                return 0;
            }
            uint8_t imm = 0;
            uint8_t shift;
            if (get_shift(operands[2], &imm, &shift)) {
                mvn.shift = shift;
            } else {
                mvn.shift = 0;
            }
            mvn.N = 0b1;
            mvn.imm = imm;
            mvn.Rm = get_reg(operands[1]);
            mvn.Rn = 0b11111;
            mvn.Rd = get_reg(operands[0]);
            memcpy(&assembly, &mvn, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "BIC") == 0) {
        if (count == 4) {
            bic_t bic;
            bic.op = 0b0001010;
            if (*operands[0] == 'X') {
                bic.sf = 0b1;
            } else if (*operands[0] == 'W') {
                bic.sf = 0b0;
            } else {
                return 0;
            }
            uint8_t imm = 0;
            uint8_t shift;
            if (get_shift(operands[3], &imm, &shift)) {
                bic.shift = shift;
            } else {
                bic.shift = 0;
            }
            bic.N = 0b1;
            bic.imm = imm;
            bic.Rm = get_reg(operands[2]);
            bic.Rn = get_reg(operands[1]);
            bic.Rd = get_reg(operands[0]);
            memcpy(&assembly, &bic, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "BICS") == 0) {
        if (count == 4) {
            bic_t bics;
            bics.op = 0b1101010;
            if (*operands[0] == 'X') {
                bics.sf = 0b1;
            } else if (*operands[0] == 'W') {
                bics.sf = 0b0;
            } else {
                return 0;
            }
            uint8_t imm = 0;
            uint8_t shift;
            if (get_shift(operands[3], &imm, &shift)) {
                bics.shift = shift;
            } else {
                bics.shift = 0;
            }
            bics.N = 0b1;
            bics.imm = imm;
            bics.Rm = get_reg(operands[2]);
            bics.Rn = get_reg(operands[1]);
            bics.Rd = get_reg(operands[0]);
            memcpy(&assembly, &bics, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "LSR") == 0) {
        if (count == 3 && (*operands[2] == 'X' || *operands[2] == 'W')) {
            lsr_reg_t lsr;
            lsr.op = 0b0011010110;
            lsr.op2 = 0b001001;
            if (*operands[0] == 'X') {
                lsr.sf = 0b1;
            } else if (*operands[1] == 'W') {
                lsr.sf = 0b0;
            } else {
                return 0;
            }
            lsr.Rm = get_reg(operands[2]);
            lsr.Rn = get_reg(operands[1]);
            lsr.Rd = get_reg(operands[0]);
            memcpy(&assembly, &lsr, sizeof(uint32_t));
            return assembly;
        } else if (count == 3) {
            lsr_imm_t lsr;
            lsr.op = 0b10100110;
            if (*operands[0] == 'X') {
                lsr.sf = 0b1;
                lsr.N = 0b1;
                lsr.imms = 0b111111;
            } else if (*operands[0] == 'W') {
                lsr.sf = 0b0;
                lsr.N = 0b0;
                lsr.imms = 0b011111;
            } else {
                return 0;
            }
            lsr.immr = static_cast<uint32_t>(get_imm(operands[2], 10));
            lsr.Rn = get_reg(operands[1]);
            lsr.Rd = get_reg(operands[0]);
            memcpy(&assembly, &lsr, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "LSL") == 0) {
        if (count == 3 && (*operands[2] == 'X' || *operands[2] == 'W')) {
            lsl_reg_t lsl;
            lsl.op = 0b0011010110;
            lsl.op2 = 0b001000;
            if (*operands[0] == 'X') {
                lsl.sf = 0b1;
            } else if (*operands[0] == 'W') {
                lsl.sf = 0b0;
            } else {
                return 0;
            }
            lsl.Rm = get_reg(operands[2]);
            lsl.Rn = get_reg(operands[1]);
            lsl.Rd = get_reg(operands[0]);
            memcpy(&assembly, &lsl, sizeof(uint32_t));
            return assembly;
        } else if (count == 3) {
            lsl_imm_t lsl;
            uint8_t shift = get_imm(operands[2], 10);
            lsl.op = 0b10100110;
            if (*operands[0] == 'X') {
                lsl.sf = 0b1;
                lsl.N = 0b1;
                lsl.immr = (-shift) % 64;
                lsl.imms = 63 - shift;
            } else if (*operands[0] == 'W') {
                lsl.sf = 0b0;
                lsl.N = 0b0;
                lsl.immr = (-shift) % 32;
                lsl.imms = 32 - shift;
            } else {
                return 0;
            }
            lsl.Rn = get_reg(operands[1]);
            lsl.Rd = get_reg(operands[0]);
            memcpy(&assembly, &lsl, sizeof(uint32_t));
            return assembly;
        }
    }
    return assembly;
}

uint32_t assemble_memory(char* ins) {
    uint32_t assembly;
    char* mnemonic = nullptr;
    char** operands = nullptr;
    size_t count = 0;
    mnemonic = get_mnemonic(ins);
    if (strcmp(ins, mnemonic) != 0) {
        count = get_operands_count(ins);
        operands = get_operands(ins, count);
    }
    if (count == 0 ||
        (*operands[0] != 'W' && *operands[0] != 'X' && strcmp(operands[0], "SP") != 0)) {
        return 0;
    }
    assembly = 0;
    if (strcmp(mnemonic, "LDPSW") == 0) {
        if (strcmp(operands[count - 1], "!") == 0) {
            ldp_t ldpsw;
            ldpsw.sf = 0b0;
            ldpsw.op = 0b110100011;
            if (*operands[0] != 'X') {
                return 0;
            }
            if (count == 7) {
                ldpsw.imm = static_cast<uint32_t>(get_imm(operands[4], 16));
            } else if (count == 6) {
                ldpsw.imm = 0;
            } else {
                return 0;
            }
            ldpsw.Rn = get_reg(operands[3]);
            ldpsw.Rt2 = get_reg(operands[1]);
            ldpsw.Rt = get_reg(operands[0]);
            memcpy(&assembly, &ldpsw, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "LDP") == 0) {
        ldp_t ldp;
        uint64_t imm;
        bool sign = false;
        if ((*operands[0] == 'X' || strcmp(operands[0], "SP") == 0) &&
            (*operands[1] == 'X' || strcmp(operands[1], "SP") == 0)) {
            ldp.sf = 0b1;
        } else if (*operands[0] == 'W' && *operands[1] == 'W') {
            ldp.sf = 0b0;
        } else {
            return 0;
        }
        if (strcmp(operands[count - 1], "!") == 0 && count == 7) {
            // pre-index
            ldp.op = 0b010100111;
            imm = get_signed_imm(operands[4], 16, &sign);
        } else if (strcmp(operands[count - 1], "]") == 0) {
            // signed offset
            ldp.op = 0b010100101;
            if (count == 6) {
                imm = get_signed_imm(operands[4], 16, &sign);
            } else if (count == 5) {
                imm = 0;
            } else {
                return 0;
            }
        } else if (strcmp(operands[count - 2], "]") == 0 && count == 6) {
            // post-index
            ldp.op = 0b010100011;
            imm = get_signed_imm(operands[5], 16, &sign);
        }
        uint8_t ldp_imm;
        imm >>= (2 + ldp.sf);
        if (sign) {
            imm = (~imm & 0b111111);
            imm++;
        }
        ldp_imm = (uint8_t)imm;
        ldp_imm |= sign ? 0b1000000 : 0b0;
        ldp.imm = ldp_imm;
        ldp.Rt = get_reg(operands[0]);
        ldp.Rt2 = get_reg(operands[1]);
        ldp.Rn = get_reg(operands[3]);
        memcpy(&assembly, &ldp, sizeof(uint32_t));
        return assembly;
    }

    if (strcmp(mnemonic, "LDNP") == 0) {
        ldp_t ldnp;
        if ((*operands[0] == 'X' || strcmp(operands[0], "SP") == 0) &&
            (*operands[1] == 'X' || strcmp(operands[1], "SP") == 0)) {
            ldnp.sf = 0b1;
        } else if (*operands[0] == 'W' && *operands[1] == 'W') {
            ldnp.sf = 0b0;
        } else {
            return 0;
        }
        ldnp.op = 0b010100001;
        uint64_t imm;
        uint8_t ldnp_imm;
        if (count == 6) {
            bool sign = false;
            imm = get_signed_imm(operands[4], 16, &sign);
            imm >>= (2 + ldnp.sf);
            if (sign) {
                imm = (~imm & 0b111111);
                imm++;
            }
            ldnp_imm = (uint8_t)imm;
            ldnp_imm |= sign ? 0b1000000 : 0b0;
        } else if (count == 5) {
            ldnp_imm = 0;
        } else {
            return 0;
        }
        ldnp.imm = ldnp_imm;
        ldnp.Rt = get_reg(operands[0]);
        ldnp.Rt2 = get_reg(operands[1]);
        ldnp.Rn = get_reg(operands[3]);
        memcpy(&assembly, &ldnp, sizeof(uint32_t));
        return assembly;
    }

    if (strcmp(mnemonic, "STP") == 0) {
        stp_t stp;
        uint64_t imm;
        bool sign = false;
        if ((*operands[0] == 'X' || strcmp(operands[0], "SP") == 0) &&
            (*operands[1] == 'X' || strcmp(operands[1], "SP") == 0)) {
            stp.sf = 0b1;
        } else if (*operands[0] == 'W' && *operands[1] == 'W') {
            stp.sf = 0b0;
        } else {
            return 0;
        }
        if (strcmp(operands[count - 1], "!") == 0 && count == 7) {
            // pre-index
            stp.op = 0b010100110;
            imm = get_signed_imm(operands[4], 16, &sign);
        } else if (strcmp(operands[count - 1], "]") == 0) {
            // signed offset
            stp.op = 0b010100100;
            if (count == 6) {
                imm = get_signed_imm(operands[4], 16, &sign);
            } else if (count == 5) {
                imm = 0;
            } else {
                return 0;
            }
        } else if (strcmp(operands[count - 2], "]") == 0 && count == 6) {
            // post-index
            stp.op = 0b010100010;
            imm = get_signed_imm(operands[5], 16, &sign);
        } else {
            return 0;
        }
        uint8_t stp_imm;
        imm >>= (2 + stp.sf);
        if (sign) {
            imm = (~imm & 0b111111);
            imm++;
        }
        stp_imm = (uint8_t)imm;
        stp_imm |= sign ? 0b1000000 : 0b0;
        stp.imm = stp_imm;
        stp.Rt = get_reg(operands[0]);
        stp.Rt2 = get_reg(operands[1]);
        stp.Rn = get_reg(operands[3]);
        memcpy(&assembly, &stp, sizeof(uint32_t));
        return assembly;
    }

    if (strcmp(mnemonic, "STNP") == 0) {
        stp_t stnp;
        if (*operands[0] == 'X' || strcmp(operands[0], "SP") == 0) {
            stnp.sf = 0b1;
        } else if (*operands[1] == 'W') {
            stnp.sf = 0b0;
        } else {
            return 0;
        }
        stnp.op = 0b010100000;
        uint64_t imm;
        uint8_t stnp_imm;
        if (count == 6) {
            bool sign = false;
            imm = get_signed_imm(operands[4], 16, &sign);
            imm >>= (2 + stnp.sf);
            if (sign) {
                imm = (~imm & 0b111111);
                imm++;
            }
            stnp_imm = (uint8_t)imm;
            stnp_imm |= sign ? 0b1000000 : 0b0;
        } else if (count == 5)
            stnp_imm = 0;
        else {
            return 0;
        }
        stnp.imm = stnp_imm;
        stnp.Rt = get_reg(operands[0]);
        stnp.Rt2 = get_reg(operands[1]);
        stnp.Rn = get_reg(operands[3]);
        memcpy(&assembly, &stnp, sizeof(uint32_t));
        return assembly;
    }

    if (strcmp(mnemonic, "LDR") == 0) {
        if (count > 3 && (*operands[3] == 'X' || *operands[3] == 'W')) {
            ldr_reg_t ldr;
            ldr.op = 0b111000011;
            ldr.op2 = 0b10;
            if (*operands[0] == 'X') {
                ldr.size = 0b11;
            } else if (*operands[0] == 'W') {
                ldr.size = 0b10;
            } else {
                return 0;
            }
            uint8_t option;
            uint8_t amount;
            if (count == 6) {
                get_extend(operands[4], false, &option, &amount);
            } else {
                option = 0;
                amount = 0;
            }
            bool sf = ldr.size & 0b1;
            if (sf && amount != 0 && amount != 3) {
                return 0;
            } else if (!sf && amount != 0 && amount != 2) {
                return 0;
            }
            ldr.option = option;
            ldr.S = (amount > 0) ? 0b1 : 0b0;
            ldr.Rm = get_reg(operands[3]);
            ldr.Rn = get_reg(operands[2]);
            ldr.Rt = get_reg(operands[0]);
            memcpy(&assembly, &ldr, sizeof(uint32_t));
            return assembly;
        } else if (strcmp(operands[count - 1], "!") == 0 && count == 6) {
            // pre index
            ldr_imm_t ldr;
            if (*operands[0] == 'X' || strcmp(operands[0], "SP") == 0) {
                ldr.sf = 0b1;
            } else if (*operands[0] == 'W') {
                ldr.sf = 0b0;
            } else {
                return 0;
            }
            ldr.op1 = 0b1;
            ldr.op2 = 0b111000010;
            ldr.op3 = 0b11;
            uint64_t imm;
            uint8_t ldr_imm;
            bool sign = false;
            imm = get_signed_imm(operands[3], 16, &sign);
            if (sign) {
                imm = (~imm & 0b11111111);
                imm++;
            }
            ldr_imm = (uint8_t)imm;
            ldr.imm = sign ? (1UL << 8) | ldr_imm : ldr_imm;
            ldr.Rt = get_reg(operands[0]);
            ldr.Rn = get_reg(operands[2]);
            memcpy(&assembly, &ldr, sizeof(uint32_t));
            return assembly;
        } else if (strcmp(operands[count - 1], "]") == 0) {
            // unsigned offset
            ldr_imm_uoff_t ldr;
            if (*operands[0] == 'X' || strcmp(operands[0], "SP") == 0) {
                ldr.sf = 0b1;
            } else if (*operands[0] == 'W') {
                ldr.sf = 0b0;
            } else {
                return 0;
            }
            ldr.op1 = 0b1;
            ldr.op2 = 0b11100101;
            uint64_t imm;
            if (count == 5) {
                imm = get_imm(operands[3], 16);
            } else if (count == 4) {
                imm = 0;
            } else {
                return 0;
            }
            imm >>= (2 + ldr.sf);
            ldr.imm = imm;
            ldr.Rt = get_reg(operands[0]);
            ldr.Rn = get_reg(operands[2]);
            memcpy(&assembly, &ldr, sizeof(uint32_t));
            return assembly;
        } else if (strcmp(operands[count - 2], "]") == 0 && count == 5) {
            // post index
            ldr_imm_t ldr;
            if (*operands[0] == 'X' || strcmp(operands[0], "SP") == 0) {
                ldr.sf = 0b1;
            } else if (*operands[0] == 'W') {
                ldr.sf = 0b0;
            } else {
                return 0;
            }
            ldr.op1 = 0b1;
            ldr.op2 = 0b111000010;
            ldr.op3 = 0b01;
            uint64_t imm;
            uint8_t ldr_imm;
            bool sign = false;
            imm = get_signed_imm(operands[4], 16, &sign);
            if (sign) {
                imm = (~imm & 0b11111111);
                imm++;
            }
            ldr_imm = (uint8_t)imm;
            ldr.imm = sign ? (1UL << 8) | ldr_imm : ldr_imm;
            ldr.Rt = get_reg(operands[0]);
            ldr.Rn = get_reg(operands[2]);
            memcpy(&assembly, &ldr, sizeof(uint32_t));
            return assembly;
        }
        if (count == 2) {
            ldr_lit_t ldr;
            if (*operands[0] == 'X' || strcmp(operands[0], "SP") == 0) {
                ldr.sf = 0b1;
            } else if (*operands[0] == 'W') {
                ldr.sf = 0b0;
            }
            ldr.op1 = 0b0;
            ldr.op2 = 0b011000;
            ldr.Rt = get_reg(operands[0]);
            ldr.imm = static_cast<uint32_t>(get_imm(operands[1], 16));
            memcpy(&assembly, &ldr, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "STR") == 0) {
        if (count > 3 && (*operands[3] == 'X' || *operands[3] == 'W')) {
            // register
            str_reg_t str;
            str.op = 0b111000001;
            str.op2 = 0b10;
            if (*operands[0] == 'X') {
                str.size = 0b11;
            } else if (*operands[0] == 'W') {
                str.size = 0b10;
            } else {
                return 0;
            }
            uint8_t option;
            uint8_t amount;
            if (count == 6)
                get_extend(operands[4], true, &option, &amount);
            else {
                option = 0;
                amount = 0;
            }
            bool sf = str.size & 0b1;
            if (sf && amount != 0 && amount != 3) {
                return 0;
            } else if (!sf && amount != 0 && amount != 2) {
                return 0;
            }
            str.option = option;
            str.S = (amount > 0) ? 0b1 : 0b0;
            str.Rm = get_reg(operands[3]);
            str.Rn = get_reg(operands[2]);
            str.Rt = get_reg(operands[0]);
            memcpy(&assembly, &str, sizeof(uint32_t));
            return assembly;
        } else if (strcmp(operands[count - 1], "!") == 0 && count == 6) {
            // pre index
            str_imm_t str;
            if (*operands[0] == 'X' || strcmp(operands[0], "SP") == 0) {
                str.sf = 0b1;
            } else if (*operands[0] == 'W') {
                str.sf = 0b0;
            } else {
                return 0;
            }
            str.op1 = 0b1;
            str.op2 = 0b111000000;
            str.op3 = 0b11;
            uint64_t imm;
            uint8_t str_imm;
            bool sign = false;
            imm = get_signed_imm(operands[3], 16, &sign);
            if (sign) {
                imm = (~imm & 0b11111111);
                imm++;
            }
            str_imm = (uint8_t)imm;
            str.imm = sign ? (1UL << 8) | str_imm : str_imm;
            str.Rt = get_reg(operands[0]);
            str.Rn = get_reg(operands[2]);
            memcpy(&assembly, &str, sizeof(uint32_t));
            return assembly;
        } else if (strcmp(operands[count - 1], "]") == 0) {
            // unsigned offset
            str_uoff_t str;
            if (*operands[0] == 'X' || strcmp(operands[0], "SP") == 0) {
                str.sf = 0b1;
            } else if (*operands[0] == 'W') {
                str.sf = 0b0;
            } else {
                return 0;
            }
            str.op1 = 0b1;
            str.op2 = 0b11100101;
            uint64_t imm;
            if (count == 5) {
                imm = get_imm(operands[3], 16);
            } else if (count == 4) {
                imm = 0;
            } else {
                return 0;
            }
            imm >>= (2 + str.sf);
            str.imm = imm;
            str.Rt = get_reg(operands[0]);
            str.Rn = get_reg(operands[2]);
            memcpy(&assembly, &str, sizeof(uint32_t));
            return assembly;
        } else if (strcmp(operands[count - 2], "]") == 0 && count == 5) {
            // post index
            str_imm_t str;
            if (*operands[0] == 'X' || strcmp(operands[0], "SP") == 0) {
                str.sf = 0b1;
            } else if (*operands[0] == 'W') {
                str.sf = 0b0;
            } else {
                return 0;
            }
            str.op1 = 0b1;
            str.op2 = 0b11100101;
            str.op3 = 0b11;
            uint64_t imm;
            uint8_t str_imm;
            bool sign = false;
            imm = get_signed_imm(operands[4], 16, &sign);
            if (sign) {
                imm = (~imm & 0b11111111);
                imm++;
            }
            str_imm = (uint8_t)imm;
            str.imm = sign ? (1UL << 8) | str_imm : str_imm;
            str.Rt = get_reg(operands[0]);
            str.Rn = get_reg(operands[2]);
            memcpy(&assembly, &str, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "LDRB") == 0 || strcmp(mnemonic, "LDRH") == 0) {
        if (count > 3 && (*operands[3] == 'X' || *operands[3] == 'W')) {
            // register
            ldr_reg_t ldr;
            if (strcmp(mnemonic, "LDRB") == 0) {
                ldr.size = 0b00;
                ldr.op = 0b111000011;
                if (*operands[0] != 'W') {
                    return 0;
                }
            } else if (strcmp(mnemonic, "LDRH") == 0) {
                ldr.size = 0b01;
                ldr.op = 0b111000011;
                if (*operands[0] != 'W') {
                    return 0;
                }
            } else {
                return 0;
            }
            ldr.op2 = 0b10;
            uint8_t option;
            uint8_t amount;
            if (count == 6) {
                get_extend(operands[4], true, &option, &amount);
            } else {
                option = 0;
                amount = 0;
            }
            bool sf = ldr.size & 0b1;
            if (sf && amount != 0 && amount != 3) {
                return 0;
            } else if (!sf && amount != 0 && amount != 2) {
                return 0;
            }
            ldr.option = option;
            ldr.S = (amount > 0) ? 0b1 : 0b0;
            ldr.Rm = get_reg(operands[3]);
            ldr.Rn = get_reg(operands[2]);
            ldr.Rt = get_reg(operands[0]);
            memcpy(&assembly, &ldr, sizeof(uint32_t));
            return assembly;
        } else if (strcmp(operands[count - 1], "!") == 0 && count == 6) {
            // pre index
            ldrb_imm_t ldr;
            if (strcmp(mnemonic, "LDRB") == 0) {
                ldr.op = 0b00111000010;
            } else if (strcmp(mnemonic, "LDRH") == 0) {
                ldr.op = 0b01111000010;
            }
            ldr.op2 = 0b11;
            uint64_t imm;
            uint8_t ldr_imm;
            bool sign = false;
            imm = get_signed_imm(operands[3], 16, &sign);
            if (sign) {
                imm = (~imm & 0b11111111);
                imm++;
            }
            ldr_imm = (uint8_t)imm;
            ldr.imm = sign ? (1UL << 8) | ldr_imm : ldr_imm;
            ldr.Rt = get_reg(operands[0]);
            ldr.Rn = get_reg(operands[2]);
            memcpy(&assembly, &ldr, sizeof(uint32_t));
            return assembly;
        } else if (strcmp(operands[count - 1], "]") == 0) {
            // unsigned offset
            ldrb_imm_uoff_t ldr;
            if (strcmp(mnemonic, "LDRB") == 0) {
                ldr.op = 0b0011100101;
            } else if (strcmp(mnemonic, "LDRH") == 0) {
                ldr.op = 0b0111100101;
            }
            uint64_t imm;
            if (count == 5) {
                imm = get_imm(operands[3], 16);
            } else if (count == 4) {
                imm = 0;
            } else {
                return 0;
            }
            ldr.imm = imm;
            ldr.Rt = get_reg(operands[0]);
            ldr.Rn = get_reg(operands[2]);
            memcpy(&assembly, &ldr, sizeof(uint32_t));
            return assembly;
        } else if (strcmp(operands[count - 2], "]") == 0 && count == 5) {
            // post index
            ldrb_imm_t ldr;
            if (strcmp(mnemonic, "LDRB") == 0) {
                ldr.op = 0b00111000010;
            } else if (strcmp(mnemonic, "LDRH") == 0) {
                ldr.op = 0b01111000010;
            }
            ldr.op2 = 0b01;
            uint64_t imm;
            uint8_t ldr_imm;
            bool sign = false;
            imm = get_signed_imm(operands[4], 16, &sign);
            if (sign) {
                imm = (~imm & 0b11111111);
                imm++;
            }
            ldr_imm = (uint8_t)imm;
            ldr.imm = sign ? (1UL << 8) | ldr_imm : ldr_imm;
            ldr.Rt = get_reg(operands[0]);
            ldr.Rn = get_reg(operands[2]);
            memcpy(&assembly, &ldr, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "STRB") == 0 || strcmp(mnemonic, "STRH") == 0) {
        if (count > 3 && (*operands[3] == 'X' || *operands[3] == 'W')) {
            // register
            str_reg_t str;
            if (strcmp(mnemonic, "STRB") == 0) {
                str.size = 0b00;
                str.op = 0b111000001;
                if (*operands[0] != 'W') {
                    return 0;
                }
            } else if (strcmp(mnemonic, "STRH") == 0) {
                str.size = 0b01;
                str.op = 0b111000001;
                if (*operands[0] != 'W') {
                    return 0;
                }
            } else {
                return 0;
            }
            str.op2 = 0b10;
            uint8_t option;
            uint8_t amount;
            if (count == 6) {
                get_extend(operands[4], true, &option, &amount);
            } else {
                option = 0;
                amount = 0;
            }
            bool sf = str.size & 0b1;
            if (sf && amount != 0 && amount != 3) {
                return 0;
            } else if (!sf && amount != 0 && amount != 2) {
                return 0;
            }
            str.option = option;
            str.S = (amount > 0) ? 0b1 : 0b0;
            str.Rm = get_reg(operands[3]);
            str.Rn = get_reg(operands[2]);
            str.Rt = get_reg(operands[0]);
            memcpy(&assembly, &str, sizeof(uint32_t));
            return assembly;
        } else if (strcmp(operands[count - 1], "!") == 0 && count == 6) {
            // pre index
            strb_imm_t str;
            if (strcmp(mnemonic, "STRB") == 0) {
                str.op = 0b00111000000;
            } else if (strcmp(mnemonic, "STRH") == 0) {
                str.op = 0b01111000000;
            }
            str.op2 = 0b11;
            uint64_t imm;
            uint8_t str_imm;
            bool sign = false;
            imm = get_signed_imm(operands[3], 16, &sign);
            if (sign) {
                imm = (~imm & 0b11111111);
                imm++;
            }
            str_imm = (uint8_t)imm;
            str.imm = sign ? (1UL << 8) | str_imm : str_imm;
            str.Rt = get_reg(operands[0]);
            str.Rn = get_reg(operands[2]);
            memcpy(&assembly, &str, sizeof(uint32_t));
            return assembly;
        } else if (strcmp(operands[count - 1], "]") == 0) {
            // unsigned offset
            strb_imm_uoff_t str;
            if (strcmp(mnemonic, "STRB") == 0) {
                str.op = 0b0011100100;
            } else if (strcmp(mnemonic, "STRH") == 0) {
                str.op = 0b0111100100;
            }
            uint64_t imm;
            if (count == 5) {
                imm = get_imm(operands[3], 16);
            } else if (count == 4) {
                imm = 0;
            } else {
                return 0;
            }
            str.imm = imm;
            str.Rt = get_reg(operands[0]);
            str.Rn = get_reg(operands[2]);
            memcpy(&assembly, &str, sizeof(uint32_t));
            return assembly;
        } else if (strcmp(operands[count - 2], "]") == 0 && count == 5) {
            // post index
            strb_imm_t str;
            if (strcmp(mnemonic, "STRB") == 0) {
                str.op = 0b00111000000;
            } else if (strcmp(mnemonic, "STRH") == 0) {
                str.op = 0b01111000000;
            }
            str.op2 = 0b01;
            uint64_t imm;
            uint8_t str_imm;
            bool sign = false;
            imm = get_signed_imm(operands[4], 16, &sign);
            if (sign) {
                imm = (~imm & 0b11111111);
                imm++;
            }
            str_imm = (uint8_t)imm;
            str.imm = sign ? (1UL << 8) | str_imm : str_imm;
            str.Rt = get_reg(operands[0]);
            str.Rn = get_reg(operands[2]);
            memcpy(&assembly, &str, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "LDRSB") == 0 || strcmp(mnemonic, "LDRSH") == 0 ||
        strcmp(mnemonic, "LDRSW") == 0) {
        if (count > 3 && (*operands[3] == 'X' || *operands[3] == 'W')) {
            ldr_reg_t ldr;
            if (strcmp(mnemonic, "LDRSB") == 0) {
                ldr.size = 0b00;
                ldr.op = 0b00111000101;
                if (*operands[0] == 'W') {
                    ldr.op |= 0b10;
                } else if (*operands[0] != 'X') {
                    return 0;
                }
            } else if (strcmp(mnemonic, "LDRSH") == 0) {
                ldr.size = 0b01;
                ldr.op = 0b111000101;
                if (*operands[0] == 'W') {
                    ldr.op |= 0b10;
                } else if (*operands[0] != 'X') {
                    return 0;
                }
            } else if (strcmp(mnemonic, "LDRSW") == 0) {
                ldr.size = 0b10;
                ldr.op = 0b111000101;
                if (*operands[0] != 'X') {
                    return 0;
                }
            } else {
                return 0;
            }
            ldr.op2 = 0b10;
            uint8_t option;
            uint8_t amount;
            if (count == 6) {
                get_extend(operands[4], true, &option, &amount);
            } else {
                option = 0;
                amount = 0;
            }
            bool sf = ldr.size & 0b1;
            if (sf && amount != 0 && amount != 3) {
                return 0;
            } else if (!sf && amount != 0 && amount != 2) {
                return 0;
            }
            ldr.option = option;
            ldr.S = (amount > 0) ? 0b1 : 0b0;
            ldr.Rm = get_reg(operands[3]);
            ldr.Rn = get_reg(operands[2]);
            ldr.Rt = get_reg(operands[0]);
            memcpy(&assembly, &ldr, sizeof(uint32_t));
            return assembly;
        } else if (strcmp(operands[count - 1], "!") == 0 && count == 6) {
            // pre index
            ldrsb_imm_t ldr;
            if (strcmp(mnemonic, "LDRSB") == 0) {
                ldr.op = 0b000111000100;
                if (*operands[0] == 'W') {
                    ldr.op |= 0b10;
                } else if (*operands[0] != 'X') {
                    return 0;
                }
            } else if (strcmp(mnemonic, "LDRSH") == 0) {
                ldr.op = 0b01111000100;
                if (*operands[0] == 'W') {
                    ldr.op |= 0b10;
                } else if (*operands[0] != 'X') {
                    return 0;
                }
            } else if (strcmp(mnemonic, "LDRSW") == 0) {
                ldr.op = 0b10111000100;
                if (*operands[0] != 'X') {
                    return 0;
                }
            } else {
                return 0;
            }
            ldr.op2 = 0b11;
            uint64_t imm;
            uint8_t ldr_imm;
            bool sign = false;
            imm = get_signed_imm(operands[3], 16, &sign);
            if (sign) {
                imm = (~imm & 0b11111111);
                imm++;
            }
            ldr_imm = (uint8_t)imm;
            ldr.imm = sign ? (1UL << 8) | ldr_imm : ldr_imm;
            ldr.Rt = get_reg(operands[0]);
            ldr.Rn = get_reg(operands[2]);
            memcpy(&assembly, &ldr, sizeof(uint32_t));
            return assembly;
        } else if (strcmp(operands[count - 1], "]") == 0 && count == 5) {
            // unsigned offset
            ldrsb_imm_uoff_t ldr;
            if (strcmp(mnemonic, "LDRSB") == 0) {
                ldr.op = 0b001110011;
                if (*operands[0] == 'W') {
                    ldr.sf = 0b1;
                } else if (*operands[0] == 'X') {
                    ldr.sf = 0b0;
                } else {
                    return 0;
                }
            } else if (strcmp(mnemonic, "LDRSH") == 0) {
                ldr.op = 0b011110011;
                if (*operands[0] == 'W') {
                    ldr.sf = 0b1;
                } else if (*operands[0] == 'X') {
                    ldr.sf = 0b0;
                } else {
                    return 0;
                }
            } else if (strcmp(mnemonic, "LDRSW") == 0) {
                ldr.op = 0b101110011;
                ldr.sf = 0b1;
                if (*operands[0] != 'X') {
                    return 0;
                }
            } else {
                return 0;
            }
            uint64_t imm;
            if (count == 5) {
                imm = get_imm(operands[3], 16);
            } else if (count == 4) {
                imm = 0;
            } else {
                return 0;
            }
            ldr.imm = imm;
            ldr.Rt = get_reg(operands[0]);
            ldr.Rn = get_reg(operands[2]);
            memcpy(&assembly, &ldr, sizeof(uint32_t));
            return assembly;
        } else if (strcmp(operands[count - 2], "]") == 0 && count == 5) {
            // post index
            ldrsb_imm_t ldr;
            if (strcmp(mnemonic, "LDRSB") == 0) {
                ldr.op = 0b000111000100;
                if (*operands[0] == 'W') {
                    ldr.op |= 0b10;
                } else if (*operands[0] != 'X') {
                    return 0;
                }
            } else if (strcmp(mnemonic, "LDRSH") == 0) {
                ldr.op = 0b01111000100;
                if (*operands[0] == 'W') {
                    ldr.op |= 0b10;
                } else if (*operands[0] != 'X') {
                    return 0;
                }
            } else if (strcmp(mnemonic, "LDRSW") == 0) {
                ldr.op = 0b10111000100;
                if (*operands[0] != 'X') {
                    return 0;
                }
            } else {
                return 0;
            }
            ldr.op2 = 0b01;
            uint64_t imm;
            uint8_t ldr_imm;
            bool sign = false;
            imm = get_signed_imm(operands[4], 16, &sign);
            if (sign) {
                imm = (~imm & 0b11111111);
                imm++;
            }
            ldr_imm = (uint8_t)imm;
            ldr.imm = sign ? (1UL << 8) | ldr_imm : ldr.imm;
            ldr.Rt = get_reg(operands[0]);
            ldr.Rn = get_reg(operands[2]);
            memcpy(&assembly, &ldr, sizeof(uint32_t));
            return assembly;
        }
    }

    return assembly;
}

uint32_t assemble_movknz(char* ins) {
    uint32_t assembly;
    char* mnemonic = nullptr;
    char** operands = nullptr;
    size_t count = 0;
    mnemonic = get_mnemonic(ins);
    if (strcmp(ins, mnemonic) != 0) {
        count = get_operands_count(ins);
        operands = get_operands(ins, count);
    }
    assembly = 0;
    if (strcmp(mnemonic, "MOV") == 0) {
        if (count == 2) {
            mov_t mov;
            if (*operands[0] == 'X') {
                mov.sf = 0b1;
            } else if (*operands[1] == 'W') {
                mov.sf = 0b0;
            } else {
                return 0;
            }
            mov.op1 = 0b0101010000;
            mov.Rm = get_reg(operands[1]);
            mov.op2 = 0b00000011111;
            mov.Rd = get_reg(operands[0]);
            memcpy(&assembly, &mov, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "MOVK") == 0) {
        if (count == 3) {
            movk_t movk;
            if (*operands[0] == 'X' || strcmp(operands[0], "SP") == 0) {
                movk.sf = 0b1;
            } else if (*operands[0] == 'W') {
                movk.sf = 0b0;
            } else {
                return 0;
            }
            movk.op = 0b11100101;
            uint64_t shift = get_imm(operands[2], 10);
            uint64_t imm = get_imm(operands[1], 16);
            movk.hw = shift / 16;
            movk.imm = imm;
            movk.Rd = get_reg(operands[0]);
            memcpy(&assembly, &movk, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "MOVN") == 0) {
        if (count == 3) {
            movn_t movn;
            if (*operands[0] == 'X' || strcmp(operands[0], "SP") == 0) {
                movn.sf = 0b1;
            } else if (*operands[0] == 'W') {
                movn.sf = 0b0;
            } else {
                return 0;
            }
            movn.op = 0b00100101;
            uint64_t shift = get_imm(operands[2], 10);
            uint64_t imm = get_imm(operands[1], 16);
            movn.hw = shift / 16;
            movn.imm = imm;
            movn.Rd = get_reg(operands[0]);
            memcpy(&assembly, &movn, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "MOVZ") == 0) {
        if (count == 3) {
            movz_t movz;
            if (*operands[0] == 'X' || strcmp(operands[0], "SP") == 0) {
                movz.sf = 0b1;
            } else if (*operands[1] == 'W') {
                movz.sf = 0b0;
            } else {
                return 0;
            }
            movz.op = 0b10100101;
            uint64_t shift = get_imm(operands[2], 10);
            uint64_t imm = get_imm(operands[1], 16);
            movz.hw = shift / 16;
            movz.Rd = get_reg(operands[0]);
            memcpy(&assembly, &movz, sizeof(uint32_t));
            return assembly;
        }
    }
    return assembly;
}

uint32_t assemble_adr_b(char* ins) {
    uint32_t assembly;
    char* mnemonic = nullptr;
    char** operands = nullptr;
    size_t count = 0;
    mnemonic = get_mnemonic(ins);
    if (strcmp(ins, mnemonic) != 0) {
        count = get_operands_count(ins);
        operands = get_operands(ins, count);
    }
    assembly = 0;
    if (strcmp(mnemonic, "ADR") == 0) {
        if (count == 2) {
            adr_t adr;
            adr.op1 = 0b0;
            adr.op2 = 0b10000;
            memcpy(&assembly, &adr, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "ADRP") == 0) {
        if (count == 2) {
            adr_t adrp;
            adrp.op1 = 0b0;
            adrp.op2 = 0b10000;
            memcpy(&assembly, &adrp, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "BLR") == 0) {
        if (count == 1) {
            br_t blr;
            blr.op1 = 0b1101011000111111000000;
            blr.Rn = get_reg(operands[0]);
            blr.op2 = 0b00000;
            memcpy(&assembly, &blr, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "BR") == 0) {
        if (count == 1) {
            br_t br;
            br.op1 = 0b1101011000011111000000;
            br.Rn = get_reg(operands[0]);
            br.op2 = 0b00000;
            memcpy(&assembly, &br, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "BL") == 0) {
        if (count == 1) {
            b_t bl;
            uint64_t imm;
            bool sign = false;
            bl.mode = 0b1;
            bl.op = 0b00101;
            imm = get_signed_imm(operands[0], 16, &sign);
            imm >>= 2;
            if (sign) {
                imm = (~imm + 1) | 0x2000000;
            }
            bl.imm = imm;
            memcpy(&assembly, &bl, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "B") == 0) {
        if (count == 1) {
            b_t b;
            uint64_t imm;
            bool sign = false;
            b.mode = 0b0;
            b.op = 0b00101;
            imm = get_signed_imm(operands[0], 16, &sign);
            imm >>= 2;
            if (sign) {
                imm = (~imm + 1) | 0x2000000;
            }
            b.imm = imm;
            memcpy(&assembly, &b, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "CBZ") == 0) {
        if (count == 2) {
            cbz_t cbz;
            if (*operands[0] == 'X') {
                cbz.sf = 0b1;
            } else if (*operands[1] == 'W') {
                cbz.sf = 0b0;
            } else {
                return 0;
            }
            cbz.op = 0b0110100;
            uint64_t imm;
            bool sign = false;
            imm = get_signed_imm(operands[1], 16, &sign);
            imm >>= 2;
            if (sign) {
                imm = (~imm + 1) | (1UL << 18);
            }
            cbz.imm = imm;
            cbz.Rt = get_reg(operands[0]);
            memcpy(&assembly, &cbz, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "CBNZ") == 0) {
        if (count == 2) {
            cbz_t cbnz;
            if (*operands[0] == 'X') {
                cbnz.sf = 0b1;
            } else if (*operands[1] == 'W') {
                cbnz.sf = 0b0;
            } else {
                return 0;
            }
            cbnz.op = 0b0110101;
            uint64_t imm;
            bool sign = false;
            imm = get_signed_imm(operands[1], 16, &sign);
            imm >>= 2;
            if (sign) {
                imm = (~imm + 1) | (1UL << 18);
            }
            cbnz.imm = imm;
            cbnz.Rt = get_reg(operands[0]);
            memcpy(&assembly, &cbnz, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "TBZ") == 0) {
        if (count == 3) {
            tbz_t tbz;
            tbz.op = 0b0110110;
            if (*operands[0] == 'X') {
                tbz.sf = 0b1;
            } else if (*operands[0] == 'W') {
                tbz.sf = 0b0;
            } else {
                return 0;
            }
            uint64_t imm;
            uint64_t bit;
            bool sign = false;
            bit = get_imm(operands[1], 10);
            imm = get_signed_imm(operands[2], 16, &sign);
            imm >>= 2;
            if (sign) {
                imm = (~imm + 1) | (1UL << 13);
            }
            tbz.bit = bit;
            tbz.imm = imm;
            memcpy(&assembly, &tbz, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "TBNZ") == 0) {
        if (count == 3) {
            tbz_t tbnz;
            tbnz.op = 0b0110111;
            if (*operands[0] == 'X') {
                tbnz.sf = 0b1;
            } else if (*operands[0] == 'W') {
                tbnz.sf = 0b0;
            } else {
                return 0;
            }
            uint64_t imm;
            uint64_t bit;
            bool sign = false;
            bit = get_imm(operands[1], 10);
            imm = get_signed_imm(operands[2], 16, &sign);
            imm >>= 2;
            if (sign) {
                imm = (~imm + 1) | (1UL << 13);
            }
            tbnz.bit = bit;
            tbnz.imm = imm;
            memcpy(&assembly, &tbnz, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strncmp(mnemonic, "B.", strlen("B.")) == 0) {
        if (count == 1) {
            b_cond_t bcond;
            char* condition = mnemonic + strlen("B.");
            for (int i = 0; i < strlen(condition); i++) {
                printf("0x%x ", condition[i]);
            }
            printf("\n");

            uint64_t imm;
            uint8_t cond;
            bool sign = false;
            cond = get_cond(condition);
            imm = get_signed_imm(operands[0], 16, &sign);
            imm >>= 2;
            if (sign) {
                imm = (~imm + 1) | (1UL << 18);
            }
            bcond.op1 = 0b01010100;
            bcond.imm = imm;
            bcond.op2 = 0b0;
            bcond.cond = cond;
            memcpy(&assembly, &bcond, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "BLRAA") == 0) {
        if (count == 2) {
            blraa_t blraa;
            blraa.op = 0b1101011;
            blraa.op2 = 0b0011111100001;
            blraa.Z = 0b1;
            blraa.M = 0b0;
            blraa.Rn = get_reg(operands[0]);
            blraa.Rm = get_reg(operands[1]);
            memcpy(&assembly, &blraa, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "BLRAAZ") == 0) {
        if (count == 1) {
            blraaz_t blraaz;
            blraaz.op = 0b1101011;
            blraaz.op2 = 0b001111110001;
            blraaz.Z = 0b0;
            blraaz.M = 0b0;
            blraaz.Rn = get_reg(operands[0]);
            blraaz.Rm = 0b11111;
            memcpy(&assembly, &blraaz, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "BLRAB") == 0) {
        if (count == 2) {
            blrab_t blrab;
            blrab.op = 0b1101011;
            blrab.op2 = 0b001111110001;
            blrab.Z = 0b1;
            blrab.M = 0b1;
            blrab.Rn = get_reg(operands[0]);
            blrab.Rm = get_reg(operands[1]);
            memcpy(&assembly, &blrab, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "BLRAZ") == 0) {
        if (count == 1) {
            blrabz_t blrabz;
            blrabz.op = 0b1101011;
            blrabz.op2 = 0b001111110001;
            blrabz.Z = 0b0;
            blrabz.M = 0b1;
            blrabz.Rn = get_reg(operands[0]);
            blrabz.Rm = 0b11111;
            memcpy(&assembly, &blrabz, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "RET") == 0) {
        ret_t ret;
        ret = 0xD65F0000;
        if (count == 1) {
            ret |= (get_reg(operands[0]) << 5);
        } else {
            ret |= (0x1E << 5);
        }
        assembly = ret;
        return assembly;
    }

    if (strcmp(mnemonic, "RETAA") == 0) {
        if (count == 0) {
            retaa_t retaa;
            retaa.op = 0b11010110010111110000;
            retaa.Rm = 0b11111;
            retaa.Rn = 0b11111;
            retaa.M = 0b0;
            retaa.A = 0b1;
            memcpy(&assembly, &retaa, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "RETAB") == 0) {
        if (count == 0) {
            retab_t retab;

            retab.op = 0b11010110010111110000;
            retab.Rm = 0b11111;
            retab.Rn = 0b11111;
            retab.M = 0b1;
            retab.A = 0b1;
            memcpy(&assembly, &retab, sizeof(uint32_t));
            return assembly;
        }
    }

    return assembly;
}

uint32_t assemble_pac(char* ins) {
    uint32_t assembly;
    char* mnemonic = nullptr;
    char** operands = nullptr;
    size_t count = 0;
    mnemonic = get_mnemonic(ins);
    if (strcmp(ins, mnemonic) != 0) {
        count = get_operands_count(ins);
        operands = get_operands(ins, count);
    }
    assembly = 0;
    if (strcmp(mnemonic, "XPACD") == 0) {
        if (count == 1) {
            xpacd_t xpacd;
            xpacd.op = 0b110110101100000101000;
            xpacd.D = 0b1;
            xpacd.Rn = 0b11111;
            xpacd.Rd = get_reg(operands[0]);
            memcpy(&assembly, &xpacd, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "XPACI") == 0) {
        if (count == 1) {
            xpaci_t xpaci;
            xpaci.op = 0b110110101100000101000;
            xpaci.D = 0b0;
            xpaci.Rn = 0b11111;
            xpaci.Rd = get_reg(operands[0]);
            memcpy(&assembly, &xpaci, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "XPACLRI") == 0) {
        if (count == 0) {
            return 0xd50320ff;
        }
    }

    if (strcmp(mnemonic, "AUTDA") == 0) {
        if (count == 2) {
            autda_t autda;
            autda.op = 0b110110101100000100;
            autda.Z = 0b0;
            autda.op2 = 0b110;
            autda.Rn = get_reg(operands[1]);
            autda.Rd = get_reg(operands[0]);
            memcpy(&assembly, &autda, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "AUTDB") == 0) {
        if (count == 2) {
            autdb_t autdb;
            autdb.op = 0b110110101100000100;
            autdb.Z = 0b0;
            autdb.op2 = 0b111;
            autdb.Rn = get_reg(operands[1]);
            autdb.Rd = get_reg(operands[0]);
            memcpy(&assembly, &autdb, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "AUTIA") == 0) {
        if (count == 2) {
            autia_t autia;
            autia.op = 0b110110101100000100;
            autia.Z = 0b0;
            autia.op2 = 0b100;
            autia.Rn = get_reg(operands[1]);
            autia.Rd = get_reg(operands[0]);
            memcpy(&assembly, &autia, sizeof(uint32_t));
            return assembly;
        }
    }
    if (strcmp(mnemonic, "AUTIB") == 0) {
        if (count == 2) {
            autib_t autib;
            autib.op = 0b110110101100000100;
            autib.Z = 0b0;
            autib.op2 = 0b101;
            autib.Rn = get_reg(operands[1]);
            autib.Rd = get_reg(operands[0]);
            memcpy(&assembly, &autib, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "AUTDZA") == 0) {
        if (count == 1) {
            autdza_t autdza;
            autdza.op = 0b110110101100000100;
            autdza.Z = 0b1;
            autdza.op2 = 0b110;
            autdza.Rn = 0b11111;
            autdza.Rd = get_reg(operands[0]);
            memcpy(&assembly, &autdza, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "AUTDZB") == 0) {
        if (count == 1) {
            autdzb_t autdzb;
            autdzb.op = 0b110110101100000100;
            autdzb.Z = 0b1;
            autdzb.op2 = 0b111;
            autdzb.Rn = 0b11111;
            autdzb.Rd = get_reg(operands[0]);
            memcpy(&assembly, &autdzb, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "AUTIZA") == 0) {
        if (count == 1) {
            autiza_t autiza;
            autiza.op = 0b110110101100000100;
            autiza.Z = 0b1;
            autiza.op2 = 0b100;
            autiza.Rn = 0b11111;
            autiza.Rd = get_reg(operands[0]);
            memcpy(&assembly, &autiza, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "AUTIZB") == 0) {
        if (count == 1) {
            autizb_t autizb;
            autizb.op = 0b110110101100000100;
            autizb.Z = 0b1;
            autizb.op2 = 0b101;
            autizb.Rn = 0b11111;
            autizb.Rd = get_reg(operands[0]);
            memcpy(&assembly, &autizb, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "AUTIA1716") == 0) {
        if (count == 0) {
            autia1716_t autia1716;
            autia1716.op = 0b11010101000000110010;
            autia1716.CRm = 0b0001;
            autia1716.op2 = 0b100;
            autia1716.CRd = 0b11111;
            memcpy(&assembly, &autia1716, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "AUTIASP") == 0) {
        if (count == 0) {
            autiasp_t autiasp;
            autiasp.op = 0b11010101000000110010;
            autiasp.CRm = 0b0011;
            autiasp.op2 = 0b101;
            autiasp.CRd = 0b11111;
            memcpy(&assembly, &autiasp, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "AUTIAZ") == 0) {
        if (count == 0) {
            autiaz_t autiaz;
            autiaz.op = 0b11010101000000110010;
            autiaz.CRm = 0b0011;
            autiaz.op2 = 0b100;
            autiaz.CRd = 0b11111;
            memcpy(&assembly, &autiaz, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "AUTIBSP") == 0) {
        if (count == 0) {
            autibsp_t autibsp;
            autibsp.op = 0b11010101000000110010;
            autibsp.CRm = 0b0011;
            autibsp.op2 = 0b111;
            autibsp.CRd = 0b11111;
            memcpy(&assembly, &autibsp, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "AUTIBZ") == 0) {
        if (count == 0) {
            autibz_t autibz;
            autibz.op = 0b11010101000000110010;
            autibz.CRm = 0b0011;
            autibz.op2 = 0b110;
            autibz.CRd = 0b11111;
            memcpy(&assembly, &autibz, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "AUTIB1716") == 0) {
        if (count == 0) {
            autib1716_t autib1716;
            autib1716.op = 0b11010101000000110010;
            autib1716.CRm = 0b0001;
            autib1716.op2 = 0b110;
            autib1716.CRd = 0b11111;
            memcpy(&assembly, &autib1716, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "PACDA") == 0) {
        if (count == 2) {
            pacda_t pacda;
            pacda.op = 0b110110101100000100;
            pacda.Z = 0b0;
            pacda.op2 = 0b010;
            pacda.Rn = get_reg(operands[1]);
            pacda.Rd = get_reg(operands[0]);
            memcpy(&assembly, &pacda, sizeof(uint32_t));
            return assembly;
        }
    }
    if (strcmp(mnemonic, "PACDB") == 0) {
        if (count == 2) {
            pacdb_t pacdb;
            pacdb.op = 0b110110101100000100;
            pacdb.Z = 0b0;
            pacdb.op2 = 0b011;
            pacdb.Rn = get_reg(operands[1]);
            pacdb.Rd = get_reg(operands[0]);
            memcpy(&assembly, &pacdb, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "PACDZA") == 0) {
        if (count == 1) {
            pacdza_t pacdza;
            pacdza.op = 0b110110101100000100;
            pacdza.Z = 0b1;
            pacdza.op2 = 0b010;
            pacdza.Rn = 0b11111;
            pacdza.Rd = get_reg(operands[0]);
            memcpy(&assembly, &pacdza, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "PACDZB") == 0) {
        if (count == 1) {
            pacdzb_t pacdzb;
            pacdzb.op = 0b110110101100000100;
            pacdzb.Z = 0b1;
            pacdzb.op2 = 0b011;
            pacdzb.Rn = 0b11111;
            pacdzb.Rd = get_reg(operands[0]);
            memcpy(&assembly, &pacdzb, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "PACIA") == 0) {
        if (count == 2) {
            pacia_t pacia;
            pacia.op = 0b110110101100000100;
            pacia.Z = 0b0;
            pacia.op2 = 0b000;
            pacia.Rn = get_reg(operands[1]);
            pacia.Rd = get_reg(operands[0]);
            memcpy(&assembly, &pacia, sizeof(uint32_t));
            return assembly;
        }
    }
    if (strcmp(mnemonic, "PACIB") == 0) {
        if (count == 2) {
            pacib_t pacib;
            pacib.op = 0b110110101100000100;
            pacib.Z = 0b0;
            pacib.op2 = 0b001;
            pacib.Rn = get_reg(operands[1]);
            pacib.Rd = get_reg(operands[0]);
            memcpy(&assembly, &pacib, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "PACIZA") == 0) {
        if (count == 1) {
            paciza_t paciza;
            paciza.op = 0b110110101100000100;
            paciza.Z = 0b1;
            paciza.op2 = 0b000;
            paciza.Rn = 0b11111;
            paciza.Rd = get_reg(operands[0]);
            memcpy(&assembly, &paciza, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "PACIZB") == 0) {
        if (count == 1) {
            pacizb_t pacizb;
            pacizb.op = 0b110110101100000100;
            pacizb.Z = 0b1;
            pacizb.op2 = 0b001;
            pacizb.Rn = 0b11111;
            pacizb.Rd = get_reg(operands[0]);
            memcpy(&assembly, &pacizb, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "PACIA1716") == 0) {
        if (count == 0) {
            pacia1716_t pacia1716;
            pacia1716.op = 0b11010101000000110010;
            pacia1716.CRm = 0b0001;
            pacia1716.op2 = 0b000;
            pacia1716.CRd = 0b11111;
            memcpy(&assembly, &pacia1716, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "PACIB1716") == 0) {
        if (count == 0) {
            pacib1716_t pacib1716;
            pacib1716.op = 0b11010101000000110010;
            pacib1716.CRm = 0b0001;
            pacib1716.op2 = 0b010;
            pacib1716.CRd = 0b11111;
            memcpy(&assembly, &pacib1716, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "PACIASP") == 0) {
        if (count == 0) {
            paciasp_t paciasp;
            paciasp.op = 0b11010101000000110010;
            paciasp.CRm = 0b0011;
            paciasp.op2 = 0b001;
            paciasp.CRd = 0b11111;
            memcpy(&assembly, &paciasp, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "PACIBSP") == 0) {
        if (count == 0) {
            pacibsp_t pacibsp;
            pacibsp.op = 0b11010101000000110010;
            pacibsp.CRm = 0b0011;
            pacibsp.op2 = 0b011;
            pacibsp.CRd = 0b11111;
            memcpy(&assembly, &pacibsp, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "PACIAZ") == 0) {
        if (count == 0) {
            paciaz_t paciaz;
            paciaz.op = 0b11010101000000110010;
            paciaz.CRm = 0b0011;
            paciaz.op2 = 0b000;
            paciaz.CRd = 0b11111;
            memcpy(&assembly, &paciaz, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "PACIBZ") == 0) {
        if (count == 0) {
            pacibz_t pacibz;
            pacibz.op = 0b11010101000000110010;
            pacibz.CRm = 0b0011;
            pacibz.op2 = 0b010;
            pacibz.CRd = 0b11111;
            memcpy(&assembly, &pacibz, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "LDRAA") == 0) {
        ldraa_t ldraa;
        if (count < 5) {
            return 0;
        }
        ldraa.op = 0b11111000;
        ldraa.o1 = 0b1;
        ldraa.o2 = 0b1;
        ldraa.Rn = get_reg(operands[2]);
        ldraa.Rt = get_reg(operands[0]);
        if (count == 6 && strcmp(operands[count - 1], "!") == 0) {
            ldraa.M = 0b0;
            ldraa.W = 0b1;
        } else if (count == 5 && strcmp(operands[count - 1], "]") == 0) {
            ldraa.M = 0b0;
            ldraa.W = 0b0;
        } else {
            return 0;
        }
        uint64_t imm;
        uint8_t ldraa_imm;
        bool sign = false;
        imm = get_signed_imm(operands[3], 16, &sign);
        imm >>= 3;
        if (sign) {
            imm = (~imm & 0b11111111);
            imm++;
        }
        ldraa_imm = (uint8_t)imm;
        ldraa.imm = sign ? (1UL << 8) | ldraa_imm : ldraa_imm;
        memcpy(&assembly, &ldraa, sizeof(uint32_t));
        return assembly;
    }

    if (strcmp(mnemonic, "LDRAB") == 0) {
        ldrab_t ldrab;
        if (count < 5) {
            return 0;
        }
        ldrab.op = 0b11111000;
        ldrab.o1 = 0b1;
        ldrab.o2 = 0b1;
        ldrab.Rn = get_reg(operands[2]);
        ldrab.Rt = get_reg(operands[0]);
        if (count == 6 && strcmp(operands[count - 1], "!") == 0) {
            ldrab.M = 0b1;
            ldrab.W = 0b1;
        } else if (count == 5 && strcmp(operands[count - 1], "]") == 0) {
            ldrab.M = 0b1;
            ldrab.W = 0b0;
        } else {
            return 0;
        }
        uint64_t imm;
        uint8_t ldrab_imm;
        bool sign = false;
        imm = get_signed_imm(operands[3], 16, &sign);
        imm >>= 3;
        if (sign) {
            imm = (~imm & 0b11111111);
            imm++;
        }
        ldrab_imm = (uint8_t)imm;
        ldrab.imm = sign ? (1UL << 8) | ldrab_imm : ldrab_imm;
        memcpy(&assembly, &ldrab, sizeof(uint32_t));
        return assembly;
    }
    return assembly;
}

uint32_t assemble_sys(char* ins) {
    uint32_t assembly;
    char* mnemonic = nullptr;
    char** operands = nullptr;
    size_t count = 0;
    mnemonic = get_mnemonic(ins);
    if (strcmp(ins, mnemonic) != 0) {
        count = get_operands_count(ins);
        operands = get_operands(ins, count);
    }
    assembly = 0;
    if (strcmp(mnemonic, "WFI") == 0) {
        if (count == 0) {
            return 0xd503207f;
        }
    }
    if (strcmp(mnemonic, "WFIT") == 0) {
        if (count == 1) {
            wfit_t wfit;
            wfit.op = 0b110101010000001100010000001;
            wfit.Rd = get_reg(operands[0]);
            memcpy(&assembly, &wfit, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "SB") == 0) {
        if (count == 0) {
            sb_t sb;
            sb.op = 0b11010101000000110011;
            sb.op2 = 0b11111111;
            sb.CRm = 0b0000;
            memcpy(&assembly, &sb, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "ISB") == 0) {
        if (count == 0) {
            isb_t isb;
            isb.op = 0b11010101000000110011;
            isb.CRm = 0b0000;
            isb.op2 = 0b11011111;
        }
        if (count == 1) {
            isb_t isb;
            isb.op = 0b11010101000000110011;
            isb.CRm = 0b0000;
            isb.op2 = 0b11011111;
        }
    }

    if (strcmp(mnemonic, "DSB") == 0) {
    }

    if (strcmp(mnemonic, "ESB") == 0) {
        if (count == 0) {
            esb_t esb;
            esb.op = 0b11010101000000110010;
            esb.CRm = 0b0010;
            esb.op2 = 0b00011111;
            memcpy(&assembly, &esb, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "DMB") == 0) {
    }

    if (strcmp(mnemonic, "CSDB") == 0) {
        if (count == 0) {
            csdb_t csdb;
            csdb.op = 0b11010101000000110010;
            csdb.CRm = 0b0010;
            csdb.op2 = 0b10011111;
            memcpy(&assembly, &csdb, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "BRK") == 0) {
        if (count == 1) {
            brk_t brk;
            brk.op = 0b11010100001;
            brk.Z = 0b00000;
            brk.imm = get_imm(operands[0], 16);
            memcpy(&assembly, &brk, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "MSR") == 0) {
        if (count == 2) {
            msr_imm_t msr;
            msr.msr = 0b1101010100000;
            msr.msr2 = 0b0100;
            msr.msr3 = 0b11111;
            msr.op1 = 0b000;
            msr.op2 = get_imm(operands[0], 10);
            msr.CRm = get_imm(operands[1], 10);
            memcpy(&assembly, &msr, sizeof(uint32_t));
            return assembly;
        } else if (count == 5) {
            msr_reg_t msr;
            msr.msr = 0b110101010001;
            if (*operands[1] != 'c' && *operands[2] != 'c') {
                return 0;
            } if (*operands[4] != 'X') {
                return 0;
            }
            uint8_t op1;
            uint8_t op2;
            msr.o0 = 0b1;
            msr.op1 = get_imm(operands[0], 10);
            msr.op2 = get_imm(operands[3], 10);
            msr.CRn = get_imm(operands[2], 10);
            msr.CRm = get_imm(operands[1], 10);
            msr.Rt = get_reg(operands[4]);
            memcpy(&assembly, &msr, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "MRS") == 0) {
        if (count == 5) {
            mrs_t mrs;
            mrs.mrs = 0b110101010011;
            mrs.op0 = 0b1;
            mrs.op1 = get_imm(operands[1], 10);
            mrs.op2 = get_imm(operands[4], 10);
            mrs.CRn = get_imm(operands[3], 10);
            mrs.CRm = get_imm(operands[2], 10);
            mrs.Rt = get_reg(operands[0]);
            memcpy(&assembly, &mrs, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "TLBI") == 0) {
    }

    if (strcmp(mnemonic, "SYS") == 0) {
        if (count == 5) {
            sys_t sys;
            sys.op = 0b1101010100001;
            sys.op1 = get_imm(operands[0], 10);
            sys.CRn = get_reg(operands[1]);
            sys.CRm = get_reg(operands[2]);
            sys.op2 = get_imm(operands[3], 10);
            sys.Rt = get_reg(operands[4]);
            memcpy(&assembly, &sys, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "SVC") == 0) {
        if (count == 1) {
            svc_t svc;
            svc.op = 0b11010100000;
            svc.op2 = 0b00001;
            svc.imm = get_imm(operands[0], 16);
            memcpy(&assembly, &svc, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "SMC") == 0) {
        if (count == 1) {
            smc_t smc;
            smc.op = 0b11010100000;
            smc.op2 = 0b00011;
            smc.imm = get_imm(operands[0], 16);
            memcpy(&assembly, &smc, sizeof(uint32_t));
            return assembly;
        }
    }

    if (strcmp(mnemonic, "HVC") == 0) {
        if (count == 1) {
            hvc_t hvc;
            hvc.op = 0b11010100000;
            hvc.op = 0b00010;
            hvc.imm = get_imm(operands[0], 16);
            memcpy(&assembly, &hvc, sizeof(uint32_t));
            return assembly;
        }
    }

    return assembly;
}

uint32_t assemble_fp_simd(char* ins) {
    uint32_t assembly;
    assembly = 0;
    return assembly;
}

namespace arch {
namespace arm64 {
namespace assembler {
uint32_t AssembleInstruction(char* ins) {
    uint32_t assembly;
    uint32_t arith;
    uint32_t logic;
    uint32_t memory;
    uint32_t movknz;
    uint32_t adr_b;
    uint32_t pac;
    uint32_t sys;
    uint32_t fp_simd;
    assembly = 0;
    arith = assemble_arith(ins);
    if (arith) {
        assembly = arith;
    }
    logic = assemble_logic(ins);
    if (logic) {
        assembly = logic;
    }
    memory = assemble_memory(ins);
    if (memory) {
        assembly = memory;
    }
    movknz = assemble_movknz(ins);
    if (movknz) {
        assembly = movknz;
    }
    adr_b = assemble_adr_b(ins);
    if (adr_b) {
        assembly = adr_b;
    }
    pac = assemble_pac(ins);
    if (pac) {
        assembly = pac;
    }
    sys = assemble_sys(ins);
    if (sys) {
        assembly = sys;
    }
    fp_simd = assemble_fp_simd(ins);
    if (fp_simd) {
        assembly = fp_simd;
    }
    return assembly;
}

uint32_t* Assemble(char* ins, uint32_t* nins) {
    uint32_t* assembly = nullptr;
    ins = strdup(ins);
    strreplace(ins, ';', '\n');
    char* line = ins;
    uint32_t num_ins = 0;
    while (line) {
        char* next_line = strchr(line, '\n');
        int line_len = next_line ? (next_line - line) : strlen(line);
        char* temp = (char*)new char[line_len + 1];
        memcpy(temp, line, line_len);
        temp[line_len] = '\0';
        temp = trim(temp);
        uint32_t* temp_assembly = reinterpret_cast<uint32_t*>(new uint32_t[(num_ins + 1)]);
        if (num_ins) {
            memcpy(temp_assembly, assembly, num_ins * sizeof(uint32_t));
        }
        temp_assembly[num_ins] = AssembleInstruction(temp);
        num_ins++;
        line = next_line ? (next_line + 1) : nullptr;
        assembly = temp_assembly;
    }
    if (*nins) {
        *nins = num_ins;
    }
    delete ins;
    return assembly;
}
} // namespace Assembler
} // namespace arm64
} // namespace arch