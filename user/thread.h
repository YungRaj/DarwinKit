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

#include <stdint.h>
#include <string.h>

#include <pthread.h>

#include <mach/mach_types.h>
#include <sys/types.h>

#include <arch.h>
#include <types.h>

namespace xnu {
class Thread {
public:
    explicit Thread() {}

    ~Thread() {}

    thread_t GetThread() {
        return thread;
    }

    pthread_t GetPthread() {
        return pthread;
    }

    Task* GetTask() {
        return task;
    }

    xnu::mach::Port GetPortHandle() {
        return handle;
    }

    xnu::mach::VmAddress GetThread() {
        return thread;
    }
    xnu::mach::VmAddress GetUThread() {
        return uthread;
    }

    union ThreadState* GetThreadState() {
        return &state;
    }

    void SetThreadState(union ThreadState* thread_state);

    void GetThreadState(union ThreadState* thread_state);

    void Resume();

    void Suspend();

    void Terminate();

    void ConvertThreadState(xnu::Task* task, union ThreadState* thread_state);

    void SetEntryPoint(xnu::mach::VmAddress address);

    void SetReturnAddress(xnu::mach::VmAddress address);

    void CreatePosixThreadFromMachThread(thread_t thread);

private:
    xnu::Task* task;

    pthread_t pthread;

    thread_t thread;

    xnu::mach::Port handle;

    xnu::mach::VmAddress thread;
    xnu::mach::VmAddress uthread;

    xnu::mach::VmAddress stack;
    xnu::mach::VmAddress code;
    xnu::mach::VmAddress data;

    union ThreadState state;
};
} // namespace xnu
