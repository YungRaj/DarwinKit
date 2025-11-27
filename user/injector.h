#pragma once

#include "types.h"
#include "dwarf.h"
#include "dyld.h"
#include "kernel.h"
#include "macho_userspace.h"
#include "pac.h"
#include "task.h"

#define STACK_SIZE ((1024 * 1024) * 512)

#define ROP_ret "\xff\x0f\x5f\xd6"
#define ALIGNSIZE 8
#define align64(x) (((x) + ALIGNSIZE - 1) & ~(ALIGNSIZE - 1))

namespace darwin {

class Injector {
public:
    explicit Injector(xnu::Kernel *kernel, xnu::Task *task)
        : kernel(kernel), task(task) {
        LocateAddresses();
    }

    static bool IsTranslated(pid_t pid);
    static bool IsCodeSigningEnforced(pid_t pid);

    void* FindGadget(const char* gadget, int gadget_len);

    UInt64 RopCall(xnu::mach::VmAddress function, char* argMap, UInt64* arg1, UInt64* arg2,
                 UInt64* arg3, UInt64* arg4);

    void LocateAddresses();

    int InjectLibrary(char* dylib);

    static int WaitForProcessAndInjectLibrary(
        int argc, char **argv, char **envp, char *process_name, char *dylib);

private:
    Kernel* kernel;

    Task* task;

    MachO* libDyld;
    MachO* libSystemPthread;

    xnu::mach::VmAddress dlopen;
    xnu::mach::VmAddress dlerror;

    xnu::mach::VmAddress pthread_create_from_mach_thread;
    xnu::mach::VmAddress gadget_address;

    xnu::VmAddress remote_stack;
    xnu::VmAddress remote_code;
    xnu::VmAddress remote_data;

    thread_t remote_thread;

    arm_thread_state64_t state = {0};

    mach_msg_type_number_t stateCount = ARM_THREAD_STATE64_COUNT;
};
}
