#pragma once

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

extern void sanitizer_cov_enable_coverage();
extern void sanitizer_cov_disable_coverage();

int LibAFLFuzzerTestOneInput(uint8_t *data, size_t size);
#ifdef __cplusplus
}
#endif
