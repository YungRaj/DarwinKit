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
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define KCOV_COVERAGE_BITMAP_SIZE 64 * 1024

extern Bool userspace;
extern Int32 current_pid;
extern task_t client_task;
extern UInt64 coverage_bitmap[KCOV_COVERAGE_BITMAP_SIZE / sizeof(uint64_t)];

UInt8* sanitizer_cov_get_bitmap();

void sanitizer_cov_enable_coverage();
void sanitizer_cov_disable_coverage();

void sanitizer_cov_trace_pc(UInt16 kext, UInt64 address);
void sanitizer_cov_trace_lr(UInt16 kext);

#ifdef __cplusplus
}
#endif
