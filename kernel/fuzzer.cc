#include "fuzzer.h"

#include "kernel.h"

int LibAFLFuzzerTestOneInput(uint8_t *data, size_t size) {
    // Only enable coverage during each test case
    sanitizer_cov_enable_coverage();
    xnu::Kernel *kernel = xnu::Kernel::Xnu();
    // Start fuzzing here
    sanitizer_cov_disable_coverage();
}
