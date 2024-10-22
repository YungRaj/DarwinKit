#pragma once

#include <stdint.h>

#define Z_SUBMAP_IDX_VA_RESTRICTED 0
#define Z_SUBMAP_IDX_VA_RESERVE 0
#define Z_SUBMAP_IDX_GENERAL 1
#define Z_SUBMAP_IDX_BAG_OF_BYTES 2
#define Z_SUBMAP_IDX_COUNT 3

struct zone;

typedef struct zone* zone_t;

typedef UInt16 zone_id_t;

typedef UInt32 zone_kheap_id_t;

typedef UInt32 hw_lock_bit_t;

enum zone_create_flags_t {
    /** The default value to pass to zone_create() */
    ZC_NONE = 0x00000000,

    /** Force the created zone to use VA sequestering */
    ZC_SEQUESTER = 0x00000001,
    /** Force the created zone @b NOT to use VA sequestering */
    ZC_NOSEQUESTER = 0x00000002,

    /** Enable per-CPU zone caching for this zone */
    ZC_CACHING = 0x00000010,
    /** Disable per-CPU zone caching for this zone */
    ZC_NOCACHING = 0x00000020,

    /** Mark zone as a per-cpu zone */
    ZC_PERCPU = 0x01000000,

    /** Force the created zone to clear every allocation on free */
    ZC_ZFREE_CLEARMEM = 0x02000000,

    /** Mark zone as non collectable by zone_gc() */
    ZC_NOGC = 0x04000000,

    /** Do not encrypt this zone during hibernation */
    ZC_NOENCRYPT = 0x08000000,

    /** Type requires alignment to be preserved */
    ZC_ALIGNMENT_REQUIRED = 0x10000000,

    /** Do not track this zone when gzalloc is engaged */
    ZC_NOGZALLOC = 0x20000000,

    /** Don't asynchronously replenish the zone via callouts */
    ZC_NOCALLOUT = 0x40000000,

    /** Can be zdestroy()ed, not default unlike zinit() */
    ZC_DESTRUCTIBLE = 0x80000000,

#ifdef XNU_KERNEL_PRIVATE

    /** This zone will back a kalloc heap */
    ZC_KALLOC_HEAP = 0x0800000000000000,

    /** This zone can be crammed with foreign pages */
    ZC_ALLOW_FOREIGN = 0x1000000000000000,

    /** This zone contains bytes / data buffers only */
    ZC_DATA_BUFFERS = 0x2000000000000000,

    /** Disable kasan quarantine for this zone */
    ZC_KASAN_NOQUARANTINE = 0x4000000000000000,

    /** Disable kasan redzones for this zone */
    ZC_KASAN_NOREDZONE = 0x8000000000000000,
#endif
};

enum zone_security_options_t {
    /*
     * Zsecurity option to enable sequestering VA of zones
     */
    ZSECURITY_OPTIONS_SEQUESTER = 0x00000001,
    /*
     * Zsecurity option to enable creating separate kalloc zones for
     * bags of bytes
     */
    ZSECURITY_OPTIONS_SUBMAP_USER_DATA = 0x00000004,
    /*
     * Zsecurity option to enable sequestering of kalloc zones used by
     * kexts (KHEAP_KEXT heap)
     */
    ZSECURITY_OPTIONS_SEQUESTER_KEXT_KALLOC = 0x00000008,
    /*
     * Zsecurity option to enable strict free of iokit objects to zone
     * or heap they were allocated from.
     */
    ZSECURITY_OPTIONS_STRICT_IOKIT_FREE = 0x00000010,
};

enum zone_kheap_id_t {
    KHEAP_ID_NONE,
    KHEAP_ID_DEFAULT,
    KHEAP_ID_DATA_BUFFERS,
    KHEAP_ID_KEXT,

#define KHEAP_ID_COUNT (KHEAP_ID_KEXT + 1)
};

enum zone_gc_level_t {
    ZONE_GC_TRIM,
    ZONE_GC_DRAIN,
    ZONE_GC_JETSAM,
};

enum zone_reserved_id_t {
    ZONE_ID__ZERO,

    ZONE_ID_PERMANENT,
    ZONE_ID_PERCPU_PERMANENT,

    ZONE_ID_IPC_PORT,
    ZONE_ID_IPC_PORT_SET,
    ZONE_ID_IPC_VOUCHERS,
    ZONE_ID_TASK,
    ZONE_ID_PROC,
    ZONE_ID_VM_MAP_COPY,
    ZONE_ID_PMAP,
    ZONE_ID_VM_MAP,

    ZONE_ID__FIRST_DYNAMIC,
};

enum zalloc_flags_t {
    // values smaller than 0xff are shared with the M_* flags from BSD MALLOC
    Z_WAITOK = 0x0000,
    Z_NOWAIT = 0x0001,
    Z_NOPAGEWAIT = 0x0002,
    Z_ZERO = 0x0004,

    Z_NOFAIL = 0x8000,
    /** used by kalloc to propagate vm tags for -zt */
    Z_VM_TAG_MASK = 0xffff0000,

#define Z_VM_TAG_SHIFT 16
#define Z_VM_TAG(tag) ((zalloc_flags_t)(tag) << Z_VM_TAG_SHIFT)
};

typedef struct zone_element {
    vm_offset_t ze_value;
} zone_element_t;

typedef struct zone_packed_virtual_address {
    UInt32 packed_address;
} zone_pva_t;

struct zone_map_range {
    vm_offset_t min_address;
    vm_offset_t max_address;
} __attribute__((aligned(2 * sizeof(vm_offset_t))));

struct zone_depot {
    UInt64 first;
    UInt64 last;
};

typedef struct zone_view* zone_view_t;

struct zone_view {
    zone_t zv_zone;
    zone_stats_t zv_stats;
    const char* zv_name;
    zone_view_t zv_next;
};

struct zone_page_metadata {
    /* The index of the zone this metadata page belongs to */
    zone_id_t zm_index : 11;

    /* Whether `zm_bitmap` is an inline bitmap or a packed bitmap reference */
    UInt16 zm_inline_bitmap : 1;

    /*
     * Zones allocate in "chunks" of zone_t::z_chunk_pages consecutive
     * pages, or zpercpu_count() pages if the zone is percpu.
     *
     * The first page of it has its metadata set with:
     * - 0 if none of the pages are currently wired
     * - the number of wired pages in the chunk (not scaled for percpu).
     *
     * Other pages in the chunk have their zm_chunk_len set to
     * ZM_SECONDARY_PAGE or ZM_SECONDARY_PCPU_PAGE depending on whether
     * the zone is percpu or not. For those, zm_page_index holds the
     * index of that page in the run.
     */
    UInt16 zm_chunk_len : 4;
#define ZM_CHUNK_LEN_MAX 0x8
#define ZM_SECONDARY_PAGE 0xe
#define ZM_SECONDARY_PCPU_PAGE 0xf

    union {
#define ZM_ALLOC_SIZE_LOCK 1u
        UInt16 zm_alloc_size; /* first page only */
        UInt16 zm_page_index; /* secondary pages only */
    };
    union {
        UInt32 zm_bitmap; /* most zones */
        UInt32 zm_bump;   /* permanent zones */
    };

    zone_pva_t zm_page_next;
    zone_pva_t zm_page_prev;
};

/*!
 * @struct zone_stats
 *
 * @abstract
 * Per-cpu structure used for basic zone stats.
 *
 * @discussion
 * The values aren't scaled for per-cpu zones.
 */

typedef struct zone_stats {
    UInt64 zs_mem_allocated;
    UInt64 zs_mem_freed;
    UInt32 zs_poison_seqno;
    UInt32 zs_alloc_rr;
}* zone_stats_t;

/*
 * @field zc_alloc_cur      denormalized number of elements in the (a) magazine
 * @field zc_free_cur       denormalized number of elements in the (f) magazine
 * @field zc_alloc_elems    a pointer to the array of elements in (a)
 * @field zc_free_elems     a pointer to the array of elements in (f)
 *
 * @field zc_depot_lock     a lock to access @c zc_depot, @c zc_depot_cur.
 * @field zc_depot          a list of @c zc_depot_cur full magazines
 * @field zc_depot_cur      number of magazines in @c zc_depot
 * @field zc_depot_max      the maximum number of elements in @c zc_depot,
 *                          protected by the zone lock.
 */

typedef struct zone_cache {
    UInt16 zc_alloc_cur;
    UInt16 zc_free_cur;
    UInt16 zc_depot_cur;
    UInt16 __zc_padding;
    zone_element_t* zc_alloc_elems;
    zone_element_t* zc_free_elems;
    hw_lock_bit_t zc_depot_lock;
    UInt32 zc_depot_max;
    struct zone_depot zc_depot;
}* zone_cache_t;

typedef struct zone_info {
    integer_t zi_count;       /* Number of elements used now */
    vm_Size zi_cur_size;      /* current memory utilization */
    vm_Size zi_max_size;      /* how large can this zone grow */
    vm_Size zi_elem_size;     /* size of an element */
    vm_Size zi_alloc_size;    /* size used for more memory */
    integer_t zi_pageable;    /* zone pageable? */
    integer_t zi_sleepable;   /* sleep if empty? */
    integer_t zi_exhaustible; /* merely return if empty? */
    integer_t zi_collectable; /* garbage collect elements? */
} zone_info_t;

struct zone {
    /*
     * Readonly / rarely written fields
     */

    /*
     * The first 4 fields match a zone_view.
     *
     * z_self points back to the zone when the zone is initialized,
     * or is nullptr else.
     */
    struct zone* z_self;
    zone_stats_t z_stats;
    const char* z_name;
    struct zone_view* z_views;

    UInt64 z_expander;
    struct zone_cache* __zpercpu z_pcpu_cache;

    UInt16 z_chunk_pages; /* size used for more memory in pages  */
    UInt16 z_chunk_elems; /* count of allocations per chunk */
    UInt16 z_elems_rsv;   /* maintain a free reserve of elements */
    UInt16 z_elem_size;   /* size of an element                  */

    UInt64
        /*
         * Lifecycle state (Mutable after creation)
         */
        z_destroyed : 1,        /* zone is (being) destroyed */
        z_async_refilling : 1,  /* asynchronous allocation pending? */
        z_replenish_wait : 1,   /* someone is waiting on the replenish thread */
        z_expanding_wait : 1,   /* is thread waiting for expansion? */
        z_expander_vm_priv : 1, /* a vm privileged thread is expanding */

        /*
         * Security sensitive configuration bits
         */
        z_allows_foreign : 1, /* allow non-zalloc space  */
        z_destructible : 1,   /* zone can be zdestroy()ed  */
        kalloc_heap : 2,      /* zone_kheap_id_t when part of a kalloc heap */
        z_noencrypt : 1,      /* do not encrypt pages when hibernating */
        z_submap_idx : 2,     /* a Z_SUBMAP_IDX_* value */
        z_va_sequester : 1,   /* page sequester: no VA reuse with other zones */
        z_free_zeroes : 1,    /* clear memory of elements on free and assert on alloc */

        /*
         * Behavior configuration bits
         */
        z_percpu : 1,      /* the zone is percpu */
        z_permanent : 1,   /* the zone allocations are permanent */
        z_replenishes : 1, /* uses the async replenish mechanism for VM */
        z_nocaching : 1,   /* disallow zone caching for this zone */
        collectable : 1,   /* garbage collect empty pages */
        exhaustible : 1,   /* merely return if empty? */
        expandable : 1,    /* expand zone (with message)? */
        no_callout : 1,

        _reserved : 26,

        /*
         * Debugging features
         */
        alignment_required : 1, /* element alignment needs to be preserved */
        gzalloc_tracked : 1,    /* this zone is tracked by gzalloc */
        gzalloc_exempt : 1,     /* this zone doesn't participate with gzalloc */
        kasan_fakestacks : 1, kasan_noquarantine : 1, /* whether to use the kasan quarantine */
        tag_zone_index : 7, tags : 1, tags_inline : 1,
        zleak_on : 1,     /* Are we collecting allocation information? */
        zone_logging : 1; /* Enable zone logging for this zone. */

    /*
     * often mutated fields
     */

    UInt64 z_lock;
    struct zone_depot z_recirc;

    /*
     * Page accounting (wired / VA)
     *
     * Those numbers are unscaled for z_percpu zones
     * (zone_scale_for_percpu() needs to be used to find the true value).
     */
    UInt32 z_wired_max;   /* how large can this zone grow        */
    UInt32 z_wired_hwm;   /* z_wired_cur high watermark          */
    UInt32 z_wired_cur;   /* number of pages used by this zone   */
    UInt32 z_wired_empty; /* pages collectable by GC             */
    UInt32 z_va_cur;      /* amount of VA used by this zone      */

    /*
     * list of metadata structs, which maintain per-page free element lists
     *
     * Note: Due to the index packing in page metadata,
     *       these pointers can't be at the beginning of the zone struct.
     */
    zone_pva_t z_pageq_empty;   /* populated, completely empty pages   */
    zone_pva_t z_pageq_partial; /* populated, partially filled pages   */
    zone_pva_t z_pageq_full;    /* populated, completely full pages    */
    zone_pva_t z_pageq_va;      /* non-populated VA pages              */

    /*
     * Zone statistics
     *
     * z_contention_wma:
     *   weighted moving average of the number of contentions per second,
     *   in Z_CONTENTION_WMA_UNIT units (fixed point decimal).
     *
     * z_contention_cur:
     *   count of recorded contentions that will be fused in z_contention_wma
     *   at the next period.
     *
     * z_recirc_cur:
     *   number of magazines in the recirculation depot.
     *
     * z_elems_free:
     *   number of free elements in the zone.
     *
     * z_elems_{min,max}:
     *   tracks the low/high watermark of z_elems_free for the current
     *   weighted moving average period.
     *
     * z_elems_free_wss:
     *   weighted moving average of the (z_elems_free_max - z_elems_free_min)
     *   amplited which is used by the GC for trim operations.
     *
     * z_elems_avail:
     *   number of elements in the zone (at all).
     */
#define Z_CONTENTION_WMA_UNIT (1u << 8)
    UInt32 z_contention_wma;
    UInt32 z_contention_cur;
    UInt32 z_recirc_cur;
    UInt32 z_elems_free_max;
    UInt32 z_elems_free_wss;
    UInt32 z_elems_free_min;
    UInt32 z_elems_free;  /* Number of free elements             */
    UInt32 z_elems_avail; /* Number of elements available        */
};