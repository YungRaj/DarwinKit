#include <stdint.h>
#include <stdio.h>

extern int64_t img4_chip_select_personalized_ap();
extern uint8_t* img4_firmware_init_from_buff(void *buff, size_t len);
extern uint8_t* img4_firmware_new(uint8_t* a1, uint64_t* a2, int a3, uint64_t a4, uint64_t a5);
extern int64_t img4_firmware_execute(uint8_t a1, uint64_t a2, uint64_t a3);

#define FUZZ_TARGET_MODIFIERS __attribute__((noinline))

int FUZZ_TARGET_MODIFIERS fuzz(const char* filename) {
    return 1;
}

int main(int argc, const char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <filename>\n", argv[0]);
        return 0;
    }
    fuzz(argv[1]);
    return 0;
}