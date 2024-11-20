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

#include <sys/fcntl.h>
#include <sys/kernel_types.h>
#include <sys/time.h>
#include <sys/vnode.h>

#include <IOKit/IOLib.h>

#include <types.h>

namespace FileIO {
vnode_t VnodeForPath(const char* path);

int PerformIO(void* buffer, Offset off, Size size, vnode_t vnode, vfs_context_t ctxt, bool write);

int Read(void* buffer, Offset off, Size sz, vnode_t vnode, vfs_context_t ctxt);

int Write(void* buffer, Offset off, Size sz, vnode_t vnode, vfs_context_t ctxt);

UInt8* ReadFile(const char* path, Size* size);

int WriteFile(const char* path, void* buffer, Size size,
              int fmode = O_TRUNC | O_CREAT | FWRITE | O_NOFOLLOW,
              int cmode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);

Size GetSize(vnode_t vnode, vfs_context_t ctxt);
} // namespace FileIO
