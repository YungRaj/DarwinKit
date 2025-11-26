#pragma once

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif
int LLVMFuzzerTestOneInput(uint8_t *data, size_t size);
#ifdef __cplusplus
}
#endif
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
int LLVMFuzzerTestOneInput(uint8_t *data, size_t size);
#ifdef __cplusplus
}
#endif