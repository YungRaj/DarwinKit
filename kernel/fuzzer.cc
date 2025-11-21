#include "fuzzer.h"

#include "kernel.h"

extern void sanitizer_cov_enable_coverage();
extern void sanitizer_cov_disable_coverage();

int LibAFLFuzzerTestOneInput(uint8_t *data, size_t size) {
    // Only enable coverage during each test case
    sanitizer_cov_enable_coverage();
    xnu::Kernel *kernel = xnu::Kernel::xnu();
    // Start fuzzing here
    sanitizer_cov_disable_coverage();
}
