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

namespace arch {
namespace x86_64 {
#define CR0_PG 0x80000000 /*	 Enable paging */
#define CR0_CD 0x40000000 /* i486: Cache disable */
#define CR0_NW 0x20000000 /* i486: No write-through */
#define CR0_AM 0x00040000 /* i486: Alignment check mask */
#define CR0_WP 0x00010000 /* i486: Write-protect kernel access */
#define CR0_NE 0x00000020 /* i486: Handle numeric exceptions */
#define CR0_ET 0x00000010 /*	 Extension type is 80387 */
                          /*	 (not official) */
#define CR0_TS 0x00000008 /*	 Task switch */
#define CR0_EM 0x00000004 /*	 Emulate coprocessor */
#define CR0_MP 0x00000002 /*	 Monitor coprocessor */
#define CR0_PE 0x00000001 /*	 Enable protected mode */

#define EFL_CF 0x00000001          /* carry */
#define EFL_PF 0x00000004          /* parity of low 8 bits */
#define EFL_AF 0x00000010          /* carry out of bit 3 */
#define EFL_ZF 0x00000040          /* zero */
#define EFL_SF 0x00000080          /* sign */
#define EFL_TF 0x00000100          /* trace trap */
#define EFL_IF 0x00000200          /* interrupt enable */
#define EFL_DF 0x00000400          /* direction */
#define EFL_OF 0x00000800          /* overflow */
#define EFL_IOPL 0x00003000        /* IO privilege level: */
#define EFL_IOPL_KERNEL 0x00000000 /* kernel */
#define EFL_IOPL_USER 0x00003000   /* user */
#define EFL_NT 0x00004000          /* nested task */
#define EFL_RF 0x00010000          /* resume without tracing */
#define EFL_VM 0x00020000          /* virtual 8086 mode */
#define EFL_AC 0x00040000          /* alignment check */
#define EFL_VIF 0x00080000         /* virtual interrupt flag */
#define EFL_VIP 0x00100000         /* virtual interrupt pending */
#define EFL_ID 0x00200000          /* cpuID instruction */

#define EFL_CLR 0xfff88028
#define EFL_SET 0x00000002

#define EFL_USER_SET (EFL_IF)
#define EFL_USER_CLEAR (EFL_IOPL | EFL_NT | EFL_RF)

#define MSR_IA32_EFER 0xC0000080
#define MSR_IA32_EFER_SCE 0x00000001
#define MSR_IA32_EFER_LME 0x00000100
#define MSR_IA32_EFER_LMA 0x00000400
#define MSR_IA32_EFER_NXE 0x00000800

uintptr_t getCR0();

void setCR0(uintptr_t value);

uintptr_t getEFER();

void setEFER(uintptr_t value);
} // namespace x86_64
} // namespace arch
