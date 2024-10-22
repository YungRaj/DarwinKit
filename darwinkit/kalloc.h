#ifndef __KALLOC_H_
#define __KALLOC_H_

#include <stdint.h>

#include "zalloc.h"

struct kheap_zones;

struct kalloc_zone_cfg {
    bool kzc_caching;
    UInt32 kzc_size;
    const char* kzc_name;
};

typedef struct kalloc_heap {
    struct kheap_zones* kh_zones;
    zone_stats_t kh_stats;
    const char* kh_name;
    struct kalloc_heap* kh_next;
    UInt32* kh_heap_id;
}* kalloc_heap_t;

struct kheap_zones {
    struct kalloc_zone_cfg* cfg;
    struct kalloc_heap* views zone_kheap_id_t heap_id;
    UInt16 max_k_zone;
    UInt8 dlut[KALLOC_DLUT_SIZE];
    UInt8 k_zindex_start;
    zone_t* k_zone;
};

struct kalloc_type_view {
    zone_t zone;
    zone_stats_t stats;
    char* kt_signature;
    UInt64 kt_flags;
    UInt64 kt_size;
    char* kt_site;
    UInt64 unused;
};

#endif