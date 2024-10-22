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

#include <types.h>

#include <arch.h>

namespace xnu {
class Thread {
public:
    Thread() {}

    ~Thread() {}

    thread_t getThread() {
        return thread;
    }

    pthread_t getPthread() {
        return pthread;
    }

    Task* getTask() {
        return task;
    }

    xnu::Mach::Port getPortHandle() {
        return handle;
    }

    xnu::Mach::VmAddress getThread() {
        return thread;
    }
    xnu::Mach::VmAddress getUThread() {
        return uthread;
    }

    union ThreadState* getThreadState() {
        return &state;
    }

    void resume();

    void suspend();

    void terminate();

    void setThreadState(union ThreadState* thread_state);

    void getThreadState(union ThreadState* thread_state);

    void convertThreadState(Task* task, union ThreadState* thread_state);

    void setEntryPoint(xnu::Mach::VmAddress address);

    void setReturnAddress(xnu::Mach::VmAddress address);

    void createPosixThreadFromMachThread(thread_t thread);

private:
    xnu::Task* task;

    pthread_t pthread;

    thread_t thread;

    xnu::Mach::Port handle;

    xnu::Mach::VmAddress thread;
    xnu::Mach::VmAddress uthread;

    xnu::Mach::VmAddress stack;
    xnu::Mach::VmAddress code;
    xnu::Mach::VmAddress data;

    union ThreadState state;
};
} // namespace xnu
