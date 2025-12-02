#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int LibAFLFuzzerTestOneInput(uint8_t* data, size_t size);
#ifdef __cplusplus
}
#endif
