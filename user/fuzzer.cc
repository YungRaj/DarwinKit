#include "fuzzer.h"

#include "kernel.h"

int LLVMFuzzerTestOneInput(uint8_t* data, size_t size) {
    xnu::Kernel* kernel = xnu::Kernel::Xnu();
    // Only enable coverage during each test case
    kernel->EnableCoverage();
    // Start fuzzing here
    kernel->DisableCoverage();
}
