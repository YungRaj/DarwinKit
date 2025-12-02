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
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/types.h>

#include <mach/exc.h>
#include <mach/mach.h>

#include <pthread.h>
#include <ptrauth.h>

#include <memory>

#include <IOKit/IOKitLib.h>

#include "dwarf.h"
#include "dyld.h"
#include "injector.h"
#include "kernel.h"
#include "macho_userspace.h"
#include "pac.h"
#include "task.h"

extern "C" {
#include "api.h"
}

using namespace std;

static struct option long_options[] = {{"pid", required_argument, 0, 'p'},
                                       {"wait_for_process", required_argument, 0, 'w'},
                                       {"fuzz", no_argument, 0, 'f'},
                                       {"kernel", no_argument, 0, 'k'},
                                       {"user", no_argument, 0, 'u'}};

void print_usage() {
    printf("darwinkit_tool -p <pid> -w <process_name> /path/to/dynamic/library.dylib\n");
    printf("               -f -k\n");
    printf("               -f -u\n");
    exit(-1);
}

#include "fuzzer.h"

int main(int argc, char** argv, char** envp) {
    bool fuzz, from_kernel, from_user = false;
    int err;
    char* wait_for_process_name = nullptr;
    char* process_name;
    int pid = -1;
    int c;

    xnu::Kernel* kernel = xnu::Kernel::Xnu();
    std::unique_ptr<xnu::Task> task = nullptr;

    // Example - running code in the macOS kernel in userspace
    // fuzzer::Harness *harness = new fuzzer::Harness(new xnu::Kernel());

    // Example - dumping a library from a kext
    // task = new Task(kernel, 614);
    // mach_vm_address_t ASD = task->GetDyld()->GetImageLoadedAt("AppStoreDaemon", nullptr);
    // printf("AppStoreDaemon loaded at 0x%llx\n", ASD);
    // MachO *AppStoreDaemon = task->GetDyld()->CacheDumpImage("AppStoreDaemon");

    // Example - parsing the Dwarf segments on a kernel
    // using namespace debug;
    // Dwarf<xnu::KernelMachO*>
    // dwarf("/Library/Developer/KDKs/KDK_13.6_22G120.kdk/System/Library/Kernels/kernel.release.t8112.dSYM/Contents/Resources/DWARF/kernel.release.t8112");
    while (1) {
        int option_index = 0;
        c = getopt_long(argc, argv, "p:w:fku", long_options, &option_index);
        if (c == -1) {
            break;
        }
        switch (c) {
        case 'p':
            pid = atoi(optarg);
            break;
        case 'w':
            wait_for_process_name = optarg;
            break;
        case 'f':
            fuzz = true;
            break;
        case 'k':
            from_kernel = true;
            break;
        case 'u':
            from_user = true;
        default:
            break;
        }
    }

    if (fuzz && from_kernel) {
        kernel->Fuzz(kLibAFLFuzzInKernel);
    } else if (fuzz && from_user) {
        kernel->Fuzz(kLibAFLFuzzFromUserspace);
    }
    if (pid <= 0) {
        print_usage();
    }
    if (pid) {
        task = std::make_unique<Task>(kernel, pid);
    }
    if (!task) {
        print_usage();
    }
    printf("Kernel base = 0x%llx slide = 0x%llx\n", kernel->GetBase(), kernel->GetSlide());
    printf("PID = %d task = 0x%llx proc = 0x%llx\n", task->GetPid(), task->GetTask(),
           task->GetProc());

    int argi = optind;
    while (argi < argc) {
        char* library = argv[argi];
        mach_vm_address_t libraryLoadedAt = task->GetDyld()->GetImageLoadedAt(library, nullptr);

        if (!libraryLoadedAt) {
            if (wait_for_process_name) {
                Injector::WaitForProcessAndInjectLibrary(argc, argv, envp, wait_for_process_name,
                                                         library);
            } else {
                Injector injector(kernel, task.get());
                err = injector.InjectLibrary(library);
                if (err != 0) {
                    return err;
                }
                libraryLoadedAt = task->GetDyld()->GetImageLoadedAt(library, nullptr);
            }
        }
        printf("%s loaded at 0x%llx\n", library, libraryLoadedAt);

        argi++;
    }
    return err;
}
