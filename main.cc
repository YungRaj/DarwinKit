#include <stdio.h>

#include "kern_user.h"
#include "libafl_fuzzer.h"

extern "C" int darwinkit_tool_main(int argc, char** argv, char** envp);

int main(int argc, char** argv, char** envp) {
    int ret = darwinkit_tool_main(argc, argv, envp);
    if (ret == 1) {
        UInt8* coverage_map = kcov_get_coverage_map();
        libafl_start_darwin_kit_fuzzer(coverage_map);
    } else if (ret == 2) {
        kcov_begin_fuzzing();
    }
}
