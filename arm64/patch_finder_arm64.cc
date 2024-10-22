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

#include "isa_arm64.h"
#include "patch_finder_arm64.h"

#include "macho.h"

#include "section.h"
#include "segment.h"

extern "C" {
#include <string.h>

#include <mach-o.h>
}

namespace arch {
namespace arm64 {
namespace PatchFinder {
using namespace arch::arm64;

unsigned char* boyermoore_horspool_memmem(const unsigned char* haystack, Size hlen,
                                          const unsigned char* needle, Size nlen) {
    size_t last, scan = 0;
    size_t bad_char_skip[UCHAR_MAX + 1]; /* Officially called:
                                          * bad character shift */

    /* Sanity checks on the parameters */
    if (nlen <= 0 || !haystack || !needle)
        return NULL;

    /* ---- Preprocess ---- */
    /* Initialize the table to default value */
    /* When a character is encountered that does not occur
     * in the needle, we can safely skip ahead for the whole
     * length of the needle.
     */
    for (scan = 0; scan <= UCHAR_MAX; scan = scan + 1)
        bad_char_skip[scan] = nlen;

    /* C arrays have the first byte at [0], therefore:
     * [nlen - 1] is the last byte of the array. */
    last = nlen - 1;

    /* Then populate it with the analysis of the needle */
    for (scan = 0; scan < last; scan = scan + 1)
        bad_char_skip[needle[scan]] = last - scan;

    /* ---- Do the matching ---- */

    /* Search the haystack, while the needle can still be within it. */
    while (hlen >= nlen) {
        /* scan from the end of the needle */
        for (scan = last; haystack[scan] == needle[scan]; scan = scan - 1)
            if (scan == 0) /* If the first byte matches, we've found it. */
                return (unsigned char*)haystack;

        /* otherwise, we need to skip some bytes and start again.
           Note that here we are getting the skip value based on the last byte
           of needle, no matter where we didn't match. So if needle is: "abcd"
           then we are skipping based on 'd' and that value will be 4, and
           for "abcdd" we again skip on 'd' but the value will be only 1.
           The alternative of pretending that the mismatched character was
           the last character is slower in the normal case (E.g. finding
           "abcd" in "...azcd..." gives 4 by using 'd' but only
           4-2==2 using 'z'. */
        hlen -= bad_char_skip[haystack[last]];
        haystack += bad_char_skip[haystack[last]];
    }

    return NULL;
}

xnu::Mach::VmAddress xref64(MachO* macho, xnu::Mach::VmAddress start, xnu::Mach::VmAddress end,
                            xnu::Mach::VmAddress what) {
    xnu::Mach::VmAddress base;

    xnu::Mach::VmAddress current_insn;

    uint64_t state[32];

    base = macho->getBase();

    memset(state, 0x0, sizeof(state));

    end &= ~3;

    if (!start || !end || !what || !base)
        return 0;

    for (current_insn = start & ~3; current_insn < end; current_insn += sizeof(uint32_t)) {
        uint32_t op = *reinterpret_cast<uint32_t*>(current_insn);

        uint32_t reg = op & 0x1F;

        if (is_adrp((adr_t*)&op)) {
            adr_t* adrp = reinterpret_cast<adr_t*>(&op);

            // ADRP <Xd>, <label>

            bool sign;

            uint64_t imm = (adrp->immlo | (adrp->immhi << 2));

            if (imm & 0x100000) {
                imm = ~(imm - 1);
                imm &= 0xFFFFF;

                sign = true;
            } else {
                sign = false;
            }

            imm <<= 12;

            state[reg] = sign ? (current_insn & ~0xFFF) - imm : (current_insn & ~0xFFF) + imm;

            continue;

        } else if (is_adr((adr_t*)&op)) {
            adr_t* adr = reinterpret_cast<adr_t*>(&op);

            // ADR <Xd>, <label>

            signed imm = adr->immlo | (adr->immhi << 2);

            state[reg] = current_insn + imm;

        } else if (is_add_imm((add_imm_t*)&op)) {
            add_imm_t* add = reinterpret_cast<add_imm_t*>(&op);

            // ADD <Xd|SP>, <Xn|SP>, #<imm>{, <shift>}

            uint8_t Rn = add->Rn;

            if (Rn == 31) // skip if SP is rn
            {
                state[reg] = 0;

                continue;
            }

            unsigned imm = add->imm;

            uint8_t shift = add->sh;

            if (shift == 1)
                imm <<= 12;
            else if (shift > 1)
                continue;

            state[reg] = state[Rn] + imm;

        } else if (is_ldr_imm_uoff((ldr_imm_uoff_t*)&op)) {
            ldr_imm_uoff_t* ldr = reinterpret_cast<ldr_imm_uoff_t*>(&op);

            // LDR <Xt>, [<Xn|SP>, #<simm>]!

            unsigned imm = ldr->imm >> (2 + ldr->sf);

            uint8_t Rn = ldr->Rn;

            if (!imm)
                continue;

            state[reg] = state[Rn] + imm;

        } else if (is_ldr_lit((ldr_lit_t*)&op)) {
            ldr_lit_t* ldr = reinterpret_cast<ldr_lit_t*>(&op);

            // LDR <Xt>, <label>

            unsigned addr = ldr->imm << 2; // label is imm * 4

            state[reg] = addr + current_insn;

        } else if (is_bl((bl_t*)&op)) {
            bl_t* bl = reinterpret_cast<bl_t*>(&op);

            // BL <label>

            bool sign;

            uint64_t imm = bl->imm;

            if (imm & 0x2000000) {
                imm = ~(imm - 1);
                imm &= 0x1FFFFFF;

                sign = true;
            } else {
                sign = false;
            }

            imm <<= 2;

            xnu::Mach::VmAddress to = sign ? current_insn - imm : current_insn + imm;

            if (to == what) {
                return current_insn;
            }

        } else if (is_b((b_t*)&op)) {
            b_t* b = reinterpret_cast<b_t*>(&op);

            bool sign;

            uint64_t imm = b->imm;

            if (imm & 0x2000000) {
                imm = ~(imm - 1);
                imm &= 0x1FFFFFF;

                sign = true;
            } else {
                sign = false;
            }

            imm <<= 2;

            xnu::Mach::VmAddress to = sign ? current_insn - imm : current_insn + imm;

            if (to == what) {
                return current_insn;
            }

        } else if (is_cbz((cbz_t*)&op) || is_cbnz((cbz_t*)&op)) {
            cbz_t* cbz = reinterpret_cast<cbz_t*>(&op);

            uint64_t imm = cbz->imm;

            bool sign;

            if (imm & 0x100000) {
                imm = ~(imm - 1);
                imm &= 0xfffff;

                sign = true;
            } else {
                sign = false;
            }

            imm <<= 2;

            xnu::Mach::VmAddress to = sign ? current_insn - imm : current_insn + imm;

            if (to == what) {
                return current_insn;
            }

        } else if (is_tbz((tbz_t*)&op) || is_tbnz((tbz_t*)&op)) {
            tbz_t* tbz = reinterpret_cast<tbz_t*>(&op);

            uint64_t imm = tbz->imm;

            bool sign;

            if (imm & 0x8000) {
                imm = ~(imm - 1);
                imm &= 0xfffff;

                sign = true;
            } else {
                sign = false;
            }

            imm <<= 2;

            xnu::Mach::VmAddress to = sign ? current_insn - imm : current_insn + imm;

            if (to == what) {
                return current_insn;
            }

        } else if (is_ret((ret_t*)&op)) {
            memset(state, 0x0, sizeof(state));

            continue;
        }

        if (state[reg] == what && reg != 31) {
            return current_insn;
        }
    }

    return 0;
}

xnu::Mach::VmAddress findInstruction64(MachO* macho, xnu::Mach::VmAddress start, Size length,
                                       UInt32 ins) {
    uint8_t* buffer;

    xnu::Mach::VmAddress end;

    buffer = reinterpret_cast<uint8_t*>(macho->getBase());

    end = start + length;

    while (start < end) {
        uint32_t x = *reinterpret_cast<uint32_t*>(buffer + start);

        if (x == ins)
            return start;

        start += sizeof(uint32_t);
    }

    return 0;
}

xnu::Mach::VmAddress findInstructionBack64(MachO* macho, xnu::Mach::VmAddress start, Size length,
                                           UInt32 ins) {
    uint8_t* buffer;

    xnu::Mach::VmAddress end;

    buffer = reinterpret_cast<uint8_t*>(macho->getBase());

    end = start + length;

    while (start < end) {
        uint32_t x = *reinterpret_cast<uint32_t*>(buffer + start);

        if (x == ins)
            return start;

        start -= sizeof(uint32_t);
    }

    return 0;
}

xnu::Mach::VmAddress findInstructionNTimes64(MachO* macho, int n, xnu::Mach::VmAddress start,
                                             Size length, UInt32 ins, bool forward) {
    int nfound = 0;

    xnu::Mach::VmAddress result = start + sizeof(uint32_t);

    do {
        xnu::Mach::VmAddress tmp = result - sizeof(uint32_t);

        if (forward)
            result = findInstruction64(macho, tmp, length, ins);
        else
            result = findInstructionBack64(macho, tmp, length, ins);

        if (tmp > result)
            length -= (tmp - result);
        else
            length -= (result - tmp);

        if (result)
            nfound++;

    } while (length && result && nfound < n);

    return nfound == n ? result : 0;
}

xnu::Mach::VmAddress step64(MachO* macho, xnu::Mach::VmAddress start, Size length,
                            bool (*is_ins)(UInt32*), int Rt, int Rn) {
    uint8_t* buffer;

    xnu::Mach::VmAddress end = start + length;

    buffer = reinterpret_cast<uint8_t*>(macho->getBase());

    bool no_Rt = Rt == NO_REG;
    bool no_Rn = Rn == NO_REG;

    bool no_reg = no_Rt && no_Rn;

    while (start <= end) {
        uint32_t x = *reinterpret_cast<uint32_t*>(start);

        if (is_ins(&x) && no_reg)
            return start;
        else if (is_ins(&x) && no_Rt && ((x >> 5) & 0x1F) == Rn)
            return start;
        else if (is_ins(&x) && no_Rn && (x & 0x1F) == Rt)
            return start;
        else if (is_ins(&x) && (x & 0x1F) == Rt && ((x >> 5) & 0x1F) == Rn)
            return start;

        start += sizeof(uint32_t);
    }

    return 0;
}

xnu::Mach::VmAddress stepBack64(MachO* macho, xnu::Mach::VmAddress start, Size length,
                                bool (*is_ins)(UInt32*), int Rt, int Rn) {
    uint8_t* buffer;

    xnu::Mach::VmAddress end = start - length;

    buffer = reinterpret_cast<uint8_t*>(macho->getBase());

    bool no_Rt = Rt == NO_REG;
    bool no_Rn = Rn == NO_REG;

    bool no_reg = no_Rt && no_Rn;

    while (start >= end) {
        uint32_t x = *reinterpret_cast<uint32_t*>(start);

        if (is_ins(&x) && no_reg)
            return start;
        else if (is_ins(&x) && no_Rt && ((x >> 5) & 0x1F) == Rn)
            return start;
        else if (is_ins(&x) && no_Rn && (x & 0x1F) == Rt)
            return start;
        else if (is_ins(&x) && (x & 0x1F) == Rt && ((x >> 5) & 0x1F) == Rn)
            return start;

        start -= sizeof(uint32_t);
    }

    return 0;
}

xnu::Mach::VmAddress findFunctionBegin(MachO* macho, xnu::Mach::VmAddress start,
                                       xnu::Mach::VmAddress where) {
    xnu::Mach::VmAddress base;

    xnu::Mach::VmAddress current_insn;

    base = macho->getBase();

    for (current_insn = where; current_insn >= start; current_insn -= sizeof(uint32_t)) {
        uint32_t op = *reinterpret_cast<uint32_t*>(current_insn);

        if (is_pacsys((pacsys_t*)&op)) {
            pacsys_t* pac = reinterpret_cast<pacsys_t*>(&op);

            if (pac->x == 1 && pac->key == 1 && pac->op2 == 0b10 && pac->C == 1) {
                return current_insn;
            }
        }

        /*
        if(is_stp_soff((stp_t*) &op) || is_stp_post((stp_t*) &op) || is_stp_pre((stp_t*)
        &op))
        {
            // STP <Xt1>, <Xt2>, [<Xn|SP>], #<imm>
            stp_t *stp = (stp_t*) &prev_op;

            if(stp->Rn == SP)
            {
                // STP x, y, [SP,#-imm]!
                // prev_op & 0x3BC003E0 == 0x298003E0 post index
                prev_op = *(uint32_t*) macho->getOffset(prev - ARM64e_INS_SZ);

                uint64_t sub_ins = step64_back(macho, prev, ((delta >> 4) + 1) * 4,
        IS_INS(sub_imm), SP, SP);

                if(sub_ins)
                {
                    prev_op = *(uint32_t*) MACHO_GET_OFFSET(macho, sub_ins -
        ARM64e_INS_SZ); prev = sub_ins;
                }

                if(is_pacsys((pacsys_t*) &prev_op))
                {
                    pacsys_t *pac = (pacsys_t*) &prev_op;

                    if(pac->op3 == 0b11111 && pac->x == 1 && pac->key == 1 && pac->op2
        == 0b10 && pac->C == 1) prev -= ARM64e_INS_SZ;
                }

                return prev;
            }
        } else if(is_sub_imm((sub_imm_t*) &prev_op))
        {
            // SUB <Xd|SP>, <Xn|SP>, #<imm>{, <shift>}
            sub_imm_t *sub = (sub_imm_t*) &prev_op;

            // SUB SP, SP, #imm
            // prev_op & 0x7F8003FF == 0x510003FF
            if(sub->Rn == SP && sub->Rd == SP)
            {
                prev_op = *(uint32_t*) MACHO_GET_OFFSET(macho, prev - ARM64e_INS_SZ);

                if(is_pacsys((pacsys_t*) &prev_op))
                {
                    pacsys_t *pac = (pacsys_t*) &prev_op;

                    if(pac->op3 == 0b11111 && pac->x == 1 && pac->key == 1 && pac->op2
        == 0b10 && pac->C == 1) prev -= ARM64e_INS_SZ;
                }

                return prev;
            }
        }
        */
    }

    return 0;
}

xnu::Mach::VmAddress findReference(MachO* macho, xnu::Mach::VmAddress to, int n,
                                   enum text which_text) {
    Segment* segment;

    xnu::Mach::VmAddress ref;

    xnu::Mach::VmAddress text_base = 0;
    xnu::Mach::VmAddress text_size = 0;

    xnu::Mach::VmAddress text_end;

    if ((segment = macho->getSegment("__TEXT_EXEC"))) {
        struct segment_command_64* segment_command = segment->getSegmentCommand();

        text_base = segment_command->vmaddr;
        text_size = segment_command->vmsize;
    }

    switch (which_text) {
    case __TEXT_XNU_BASE:
        break;

    case __TEXT_PRELINK_BASE:

        if ((segment = macho->getSegment("__PRELINK_TEXT"))) {
            struct segment_command_64* segment_command = segment->getSegmentCommand();

            text_base = segment_command->vmaddr;
            text_size = segment_command->vmsize;
        }

        break;
    case __TEXT_PPL_BASE:

        if ((segment = macho->getSegment("__PPLTEXT"))) {
            struct segment_command_64* segment_command =
                macho->getSegment("__PPLTEXT")->getSegmentCommand();

            text_base = segment_command->vmaddr;
            text_size = segment_command->vmsize;
        }

        break;
    default:
        return 0;
    }

    if (n <= 0) {
        n = 1;
    }

    text_end = text_base + text_size;

    do {
        ref = xref64(macho, text_base, text_end, to);

        if (!ref)
            return 0;

        text_base = ref + sizeof(uint32_t);

    } while (--n > 0);

    return ref;
}

xnu::Mach::VmAddress findDataReference(MachO* macho, xnu::Mach::VmAddress to, enum data which_data,
                                       int n) {
    Segment* segment;

    struct segment_command_64* segment_command;

    xnu::Mach::VmAddress start;
    xnu::Mach::VmAddress end;

    segment = NULL;
    segment_command = NULL;

    switch (which_data) {
    case __DATA_CONST:

        if ((segment = macho->getSegment("__DATA_CONST"))) {
            segment_command = segment->getSegmentCommand();
        }

        break;
    case __PPLDATA_CONST:

        if ((segment = macho->getSegment("__PPLDATA_CONST"))) {
            segment_command = segment->getSegmentCommand();
        }

        break;
    case __PPLDATA:

        if ((segment = macho->getSegment("__PPLDATA"))) {
            segment_command = segment->getSegmentCommand();
        }

        break;
    case __DATA:

        if ((segment = macho->getSegment("__DATA"))) {
            segment_command = segment->getSegmentCommand();
        }

        break;
    case __BOOTDATA:

        if ((segment = macho->getSegment("__BOOTDATA"))) {
            segment_command = segment->getSegmentCommand();
        }

        break;
    case __PRELINK_DATA:

        if ((segment = macho->getSegment("__PRELINK_DATA"))) {
            segment_command = segment->getSegmentCommand();
        }

        break;
    case __PLK_DATA_CONST:

        if ((segment = macho->getSegment("__PLK_DATA_CONST"))) {
            segment_command = segment->getSegmentCommand();
        }

        break;
    default:
        segment = NULL;

        segment_command = NULL;

        return 0;
    }

    if (!segment || !segment_command)
        return 0;

    start = segment_command->vmaddr;
    end = segment_command->vmaddr + segment_command->vmsize;

    for (xnu::Mach::VmAddress i = start; i <= end; i += sizeof(uint16_t)) {
        xnu::Mach::VmAddress ref = *reinterpret_cast<xnu::Mach::VmAddress*>(i);

#if defined(__arm64__) || defined(__arm64e__)

        __asm__ volatile("XPACI %[pac]" : [pac] "+rm"(ref));

#endif

        if (ref == to) {
            return i;
        }
    }

    return 0;
}

uint8_t* findString(MachO* macho, char* string, xnu::Mach::VmAddress base,
                    xnu::Mach::VmAddress size, bool full_match) {
    uint8_t* find;

    xnu::Mach::VmAddress offset = 0;

    while ((find = boyermoore_horspool_memmem(reinterpret_cast<unsigned char*>(base + offset),
                                              size - offset, (uint8_t*)string, strlen(string)))) {
        if ((find == reinterpret_cast<unsigned char*>(base) || *(string - 1) == '\0') &&
            (!full_match || strcmp((char*)find, string) == 0))
            break;

        offset = (uint64_t)(find - base + 1);
    }

    return find;
}

xnu::Mach::VmAddress findStringReference(MachO* macho, char* string, int n,
                                         enum string which_string, enum text which_text,
                                         bool full_match) {
    Segment* segment;
    Section* section;

    uint8_t* find;

    xnu::Mach::VmAddress base;

    size_t size = 0;

    switch (which_string) {
    case __const_:

        segment = macho->getSegment("__TEXT");

        if (segment) {
            section = macho->getSection("__TEXT", "__const");

            if (section) {
                struct section_64* sect = section->getSection();

                base = sect->addr;
                size = sect->size;
            }
        }

        break;
    case __data_:

        segment = macho->getSegment("__DATA");

        if (segment) {
            section = macho->getSection("__DATA", "__data");

            if (section) {
                struct section_64* sect = section->getSection();

                base = sect->addr;
                size = sect->size;
            }
        }

        break;
    case __oslstring_:

        segment = macho->getSegment("__TEXT");

        if (segment) {
            section = macho->getSection("__TEXT", "__os_log");

            if (section) {
                struct section_64* sect = section->getSection();

                base = sect->addr;
                size = sect->size;
            }
        }

        break;
    case __pstring_:

        segment = macho->getSegment("__TEXT");

        if (segment) {
            section = macho->getSection("__TEXT", "__text");

            if (section) {
                struct section_64* sect = section->getSection();

                base = sect->addr;
                size = sect->size;
            }
        }

        break;
    case __cstring_:

        segment = macho->getSegment("__TEXT");

        if (segment) {
            section = macho->getSection("__TEXT", "__cstring");

            if (section) {
                struct section_64* sect = section->getSection();

                base = sect->addr;
                size = sect->size;
            }
        }

        break;
    default:
        break;
    }

    if (!base && !size)
        return 0;

    find = findString(macho, string, base, size, full_match);

    if (!find)
        return 0;

    return arch::arm64::PatchFinder::findReference(macho, (xnu::Mach::VmAddress)find, n,
                                                   which_text);
}

void printInstruction64(MachO* macho, xnu::Mach::VmAddress start, UInt32 length,
                        bool (*is_ins)(UInt32*), int Rt, int Rn) {
    return;
}

} // namespace PatchFinder
} // namespace arm64
} // namespace arch