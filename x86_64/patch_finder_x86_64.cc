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

#include "disassembler_x86_64.h"
#include "isa_x86_64.h"
#include "patch_finder_x86_64.h"

namespace arch {
namespace x86_64 {
namespace patchfinder {
unsigned char* boyermoore_horspool_memmem(const unsigned char* haystack, Size hlen,
                                          const unsigned char* needle, Size nlen) {
    size_t last, scan = 0;
    size_t bad_char_skip[UCHAR_MAX + 1]; /* Officially called:
                                          * bad character shift */

    /* Sanity checks on the parameters */
    if (nlen <= 0 || !haystack || !needle)
        return nullptr;

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
           Note that here we are Getting the skip value based on the last byte
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

    return nullptr;
}

xnu::mach::VmAddress Xref64(MachO* macho, xnu::mach::VmAddress start, xnu::mach::VmAddress end,
                            xnu::mach::VmAddress what) {
    cs_insn* insns;
    size_t count;
    for (uint32_t i = 0; i < end; i++) {
        xnu::mach::VmAddress address = start + i;
        uint64_t offset = macho->AddressToOffset(start + i);
        if (offset) {
            size_t size = arch::x86_64::disassembler::Disassemble(
                reinterpret_cast<xnu::mach::VmAddress>((*macho)[offset]), 0x1000, &insns);
            for (uint32_t j = 0; j < size; j++) {
                xnu::mach::VmAddress xref;
                cs_insn* insn = &insns[j];
                if (strcmp(insn->mnemonic, "lea") == 0) {
                    if (insns[i].detail->x86.operands[1].type == X86_OP_MEM &&
                        insns[i].detail->x86.operands[1].reg == X86_REG_RIP) {
                        xref = address + insns[i].detail->x86.operands[1].mem.disp;
                        if (xref == what) {
                            return address;
                        }
                    }

                } else if (strcmp(insn->mnemonic, "call") == 0) {
                    if (insns[i].detail->x86.operands[0].type == X86_OP_IMM) {
                        xref = address + insns[i].detail->x86.operands[0].imm;

                        if (xref == what) {
                            return address;
                        }
                    }
                } else if (strcmp(insn->mnemonic, "jmp") == 0 ||
                           strcmp(insn->mnemonic, "jz") == 0 || strcmp(insn->mnemonic, "je") == 0 ||
                           strcmp(insn->mnemonic, "jnz") == 0 ||
                           strcmp(insn->mnemonic, "jne") == 0 ||
                           strcmp(insn->mnemonic, "js") == 0 ||
                           strcmp(insn->mnemonic, "jns") == 0 ||
                           strcmp(insn->mnemonic, "jo") == 0 ||
                           strcmp(insn->mnemonic, "jno") == 0 ||
                           strcmp(insn->mnemonic, "ja") == 0 ||
                           strcmp(insn->mnemonic, "jnbe") == 0 ||
                           strcmp(insn->mnemonic, "jb") == 0 || strcmp(insn->mnemonic, "jc") == 0 ||
                           strcmp(insn->mnemonic, "jnae") == 0 ||
                           strcmp(insn->mnemonic, "jae") == 0 ||
                           strcmp(insn->mnemonic, "jnb") == 0 ||
                           strcmp(insn->mnemonic, "jnc") == 0 ||
                           strcmp(insn->mnemonic, "jbe") == 0 ||
                           strcmp(insn->mnemonic, "jna") == 0) {
                    if (insns[i].detail->x86.operands[0].type == X86_OP_IMM) {
                        xref = address + insns[i].detail->x86.operands[0].imm;
                        if (xref == what) {
                            return address;
                        }
                    }

                } else if (strcmp(insn->mnemonic, "mov") == 0) {
                    if (insns[i].detail->x86.operands[1].type == X86_OP_MEM &&
                        insns[i].detail->x86.operands[1].reg == X86_REG_RIP) {
                        xref = address + insns[i].detail->x86.operands[1].mem.disp;
                        if (xref == what) {
                            return address;
                        }
                    }
                    cs_regs read, write;
                    uint8_t nread, nwrite;
                    if (arch::x86_64::disassembler::RegisterAccess(insn, read, &nread, write,
                                                                   &nwrite)) {
                        if (nread) {
                            x86_reg reg = static_cast<x86_reg>(read[0]);
                            if (reg == X86_REG_CS) {
                            }
                            if (reg == X86_REG_DS) {
                            }
                            if (reg == X86_REG_ES) {
                            }
                            if (reg == X86_REG_FS) {
                            }
                            if (reg == X86_REG_GS) {
                            }
                            if (reg == X86_REG_SS) {
                            }
                        }
                    }
                }
                address += insn->size;
            }
        } else {
            break;
        }
        i += 0x1000;
    }
    return 0;
}

xnu::mach::VmAddress FindInstruction64(MachO* macho, xnu::mach::VmAddress start, Size length,
                                       UInt8* stream) {
    cs_insn* insn;
    size_t count;
    uint64_t offset = macho->AddressToOffset(start);
    arch::x86_64::disassembler::Disassemble(reinterpret_cast<xnu::mach::VmAddress>(stream),
                                            arch::x86_64::MaxInstructionSize, &insn);
    size_t size = insn->size;
    if (offset) {
        uint32_t j = 0;
        while (j < length) {
            if (memcmp((*macho)[offset + j], stream, size) == 0) {
                return start + j;
            }
            j += insn->size;
        }
    }
    return 0;
}

xnu::mach::VmAddress FindInstructionBack64(MachO* macho, xnu::mach::VmAddress start, Size length,
                                           UInt8* stream) {
    cs_insn* insn;
    size_t count;
    uint64_t offset = macho->AddressToOffset(start);
    arch::x86_64::disassembler::Disassemble(reinterpret_cast<xnu::mach::VmAddress>(stream),
                                            arch::x86_64::MaxInstructionSize, &insn);
    size_t size = insn->size;
    while (offset) {
        size_t n = 0;
        uint32_t j = 0;
        do {
            n = arch::x86_64::disassembler::Disassemble(
                reinterpret_cast<xnu::mach::VmAddress>((*macho)[offset - ++j]),
                arch::x86_64::MaxInstructionSize, &insn);
        } while (insn->size + (offset - j) != offset && n != 1);
        if (insn->size + (offset - j) != offset) {
            return 0;
        }
        if (memcmp((*macho)[offset - j], stream, size) == 0) {
            return start - j;
        }
        offset -= insn->size;
    }
    return 0;
}

xnu::mach::VmAddress FindInstructionNTimes64(MachO* macho, int n, xnu::mach::VmAddress start,
                                             Size length, UInt8* stream, Bool forward) {
    uint32_t n_insns = 0;
    while (n_insns < n && start) {
        if (forward) {
            start = FindInstruction64(macho, start, length, stream);
        } else {
            start = FindInstructionBack64(macho, start, length, stream);
        }
    }
    return start;
}

xnu::mach::VmAddress Step64(MachO* macho, xnu::mach::VmAddress start, Size length, char* mnemonic,
                            char* op_string) {
    cs_insn* insn;
    size_t count;
    uint64_t offset = macho->AddressToOffset(start);
    if (offset) {
        uint32_t j = 0;
        while (j < length) {
            arch::x86_64::disassembler::Disassemble(
                reinterpret_cast<xnu::mach::VmAddress>((*macho)[offset + j]),
                arch::x86_64::MaxInstructionSize, &insn);
            if (strcmp(insn->mnemonic, mnemonic) == 0) {
                if (op_string && strcmp(insn->op_str, op_string) == 0) {
                    return start + j;
                } else {
                    return start + j;
                }
            }
            j += insn->size;
        }
    }
    return 0;
}

xnu::mach::VmAddress StepBack64(MachO* macho, xnu::mach::VmAddress start, Size length,
                                char* mnemonic, char* op_string) {
    cs_insn* insn = nullptr;
    size_t count;
    uint64_t offset = macho->AddressToOffset(start);
    if (offset) {
        uint32_t j = 0;
        while (j < length) {
            size_t n = 0;
            while (n != 1)
                n = arch::x86_64::disassembler::Disassemble(
                    reinterpret_cast<xnu::mach::VmAddress>((*macho)[offset - ++j]),
                    arch::x86_64::MaxInstructionSize, &insn);
            if (!insn) {
                return 0;
            }
            if (insn->size + (offset - j) != offset) {
                return 0;
            }
            if (strcmp(insn->mnemonic, mnemonic) == 0) {
                if (op_string && strcmp(insn->op_str, op_string) == 0) {
                    return start + j;
                } else {
                    return start + j;
                }
            }
            offset -= insn->size;
        }
    }
    return 0;
}

xnu::mach::VmAddress FindFunctionBegin(MachO* macho, xnu::mach::VmAddress start,
                                       xnu::mach::VmAddress where) {
    return StepBack64(macho, start, 0x400, "push", "rsp");
}

xnu::mach::VmAddress FindReference(MachO* macho, xnu::mach::VmAddress to, int n,
                                   enum text which_text) {
    Segment* segment;
    xnu::mach::VmAddress ref;
    xnu::mach::VmAddress text_base = 0;
    xnu::mach::VmAddress text_size = 0;
    xnu::mach::VmAddress text_end;
    if ((segment = macho->GetSegment("__TEXT_EXEC"))) {
        struct segment_command_64* segment_command = segment->GetSegmentCommand();
        text_base = segment_command->vmaddr;
        text_size = segment_command->vmsize;
    }
    switch (which_text) {
    case __TEXT_XNU_BASE:
        break;
    case __TEXT_PRELINK_BASE:
        if ((segment = macho->GetSegment("__PRELINK_TEXT"))) {
            struct segment_command_64* segment_command = segment->GetSegmentCommand();

            text_base = segment_command->vmaddr;
            text_size = segment_command->vmsize;
        }
        break;
    case __TEXT_PPL_BASE:
        if ((segment = macho->GetSegment("__PPLTEXT"))) {
            struct segment_command_64* segment_command =
                macho->GetSegment("__PPLTEXT")->GetSegmentCommand();

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
        ref = Xref64(macho, text_base, text_end, to);
        if (!ref) {
            return 0;
        }
        text_base = ref + sizeof(uint32_t);
    } while (--n > 0);
    return ref;
}

xnu::mach::VmAddress FindDataReference(MachO* macho, xnu::mach::VmAddress to, enum data which_data,
                                       int n) {
    Segment* segment;
    struct segment_command_64* segment_command;
    xnu::mach::VmAddress start;
    xnu::mach::VmAddress end;
    segment = nullptr;
    segment_command = nullptr;
    switch (which_data) {
    case __DATA_CONST:
        if ((segment = macho->GetSegment("__DATA_CONST"))) {
            segment_command = segment->GetSegmentCommand();
        }
        break;
    case __PPLDATA_CONST:
        if ((segment = macho->GetSegment("__PPLDATA_CONST"))) {
            segment_command = segment->GetSegmentCommand();
        }
        break;
    case __PPLDATA:
        if ((segment = macho->GetSegment("__PPLDATA"))) {
            segment_command = segment->GetSegmentCommand();
        }
        break;
    case __DATA:
        if ((segment = macho->GetSegment("__DATA"))) {
            segment_command = segment->GetSegmentCommand();
        }
        break;
    case __BOOTDATA:
        if ((segment = macho->GetSegment("__BOOTDATA"))) {
            segment_command = segment->GetSegmentCommand();
        }
        break;
    case __PRELINK_DATA:
        if ((segment = macho->GetSegment("__PRELINK_DATA"))) {
            segment_command = segment->GetSegmentCommand();
        }
        break;
    case __PLK_DATA_CONST:
        if ((segment = macho->GetSegment("__PLK_DATA_CONST"))) {
            segment_command = segment->GetSegmentCommand();
        }
        break;
    default:
        segment = nullptr;
        segment_command = nullptr;
        return 0;
    }
    if (!segment || !segment_command) {
        return 0;
    }
    start = segment_command->vmaddr;
    end = segment_command->vmaddr + segment_command->vmsize;
    for (xnu::mach::VmAddress i = start; i <= end; i += sizeof(uint16_t)) {
        xnu::mach::VmAddress ref = *reinterpret_cast<xnu::mach::VmAddress*>(i);
        if (ref == to) {
            return i;
        }
    }
    return 0;
}

uint8_t* FindString(MachO* macho, char* string, xnu::mach::VmAddress base, Size size,
                    Bool full_match) {
    uint8_t* find;
    xnu::mach::VmAddress offset = 0;
    while ((find = boyermoore_horspool_memmem(reinterpret_cast<unsigned char*>(base + offset),
                                              size - offset, (uint8_t*)string, strlen(string)))) {
        if ((find == reinterpret_cast<unsigned char*>(base) || *(string - 1) == '\0') &&
            (!full_match || strcmp((char*)find, string) == 0)) {
            break;
        }
        offset = (uint64_t)(find - base + 1);
    }
    return find;
}

xnu::mach::VmAddress FindStringReference(MachO* macho, char* string, int n,
                                         enum string which_string, enum text which_text,
                                         Bool full_match) {
    Segment* segment;
    Section* section;
    uint8_t* find;
    xnu::mach::VmAddress base;
    size_t size = 0;
    switch (which_string) {
    case __const_:
        segment = macho->GetSegment("__TEXT");
        if (segment) {
            section = macho->GetSection("__TEXT", "__const");
            if (section) {
                struct section_64* sect = section->GetSection();
                base = sect->addr;
                size = sect->size;
            }
        }
        break;
    case __data_:
        segment = macho->GetSegment("__DATA");
        if (segment) {
            section = macho->GetSection("__DATA", "__data");
            if (section) {
                struct section_64* sect = section->GetSection();
                base = sect->addr;
                size = sect->size;
            }
        }
        break;
    case __oslstring_:
        segment = macho->GetSegment("__TEXT");
        if (segment) {
            section = macho->GetSection("__TEXT", "__os_log");
            if (section) {
                struct section_64* sect = section->GetSection();
                base = sect->addr;
                size = sect->size;
            }
        }
        break;
    case __pstring_:
        segment = macho->GetSegment("__TEXT");
        if (segment) {
            section = macho->GetSection("__TEXT", "__text");
            if (section) {
                struct section_64* sect = section->GetSection();
                base = sect->addr;
                size = sect->size;
            }
        }
        break;
    case __cstring_:
        segment = macho->GetSegment("__TEXT");
        if (segment) {
            section = macho->GetSection("__TEXT", "__cstring");
            if (section) {
                struct section_64* sect = section->GetSection();
                base = sect->addr;
                size = sect->size;
            }
        }
        break;
    default:
        break;
    }
    if (!base && !size) {
        return 0;
    }
    find = FindString(macho, string, base, size, full_match);
    if (!find) {
        return 0;
    }
    return arch::x86_64::patchfinder::FindReference(macho, (xnu::mach::VmAddress)find, n,
                                                    which_text);
}

void PrintInstruction64(MachO* macho, xnu::mach::VmAddress start, uint32_t length, char* mnemonic,
                        char* op_string) {}

} // namespace patchfinder
} // namespace x86_64
} // namespace arch