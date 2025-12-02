#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "api.h"

#ifdef __cplusplus
}
#endif

#ifdef __KERNEL__

#include <os/log.h>
#include <stdarg.h>
#include <sys/systm.h>

// Kernel: must log with a constant format string
static inline void DARWIN_KIT_LOG_VA(const char* fmt, va_list args) {
    char buffer[256];
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    os_log(OS_LOG_DEFAULT, "%s", buffer);
}

#define DARWIN_KIT_LOG(fmt, ...) os_log(OS_LOG_DEFAULT, fmt, ##__VA_ARGS__)

#endif // __KERNEL__

#ifdef __USER__

#include <stdarg.h>
#include <stdio.h>

static inline void DARWIN_KIT_LOG_VA(const char* fmt, va_list args) {
    vprintf(fmt, args);
}

#define DARWIN_KIT_LOG printf

#endif // __USER__

#ifdef __cplusplus
extern "C" {
#endif

void darwin_kit_log(const char* fmt, ...);

#ifdef __cplusplus
}
#endif
