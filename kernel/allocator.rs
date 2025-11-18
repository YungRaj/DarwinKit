#![no_std]
extern crate alloc;

use core::alloc::{GlobalAlloc, Layout};
use core::ptr::null_mut;

extern "C" {
    fn IOMalloc(size: usize) -> *mut core::ffi::c_void;
    fn IOFree(ptr: *mut core::ffi::c_void, size: usize);
}

struct KernelAllocator;

unsafe impl GlobalAlloc for KernelAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = IOMalloc(layout.size()) as *mut u8;
        if ptr.is_null() {
            null_mut()
        } else {
            ptr
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        IOFree(ptr as *mut core::ffi::c_void, layout.size());
    }
}

#[global_allocator]
static GLOBAL_ALLOC: KernelAllocator = KernelAllocator;
