#pragma once

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int LibAFLFuzzerTestOneInput(uint8_t *data, size_t size);
#ifdef __cplusplus
}
#endif
