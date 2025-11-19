#![no_std]
// Embedded targets: build with no_main
#![cfg_attr(not(any(windows)), no_main)]

mod allocator;

#[cfg(any(windows, unix))]
extern crate alloc;
#[cfg(any(windows, unix))]
use alloc::ffi::CString;
#[cfg(not(any(windows)))]
use core::panic::PanicInfo;

use core::ptr::NonNull;

use libafl::{
    corpus::InMemoryCorpus,
    events::SimpleEventManager,
    executors::{inprocess::InProcessExecutor, ExitKind},
    feedbacks::{CrashFeedback, MaxMapFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::RandPrintablesGenerator,
    inputs::{BytesInput, HasTargetBytes},
    monitors::SimpleMonitor,
    mutators::{havoc_mutations::havoc_mutations, scheduled::HavocScheduledMutator},
    observers::ConstMapObserver,
    schedulers::QueueScheduler,
    stages::mutational::StdMutationalStage,
    state::StdState,
};
use libafl_bolts::{nonnull_raw_mut, nonzero, rands::StdRand, tuples::tuple_list, AsSlice};
#[cfg(any(windows, unix))]
use libc::{abort, printf};

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    #[cfg(unix)]
    unsafe {
        abort();
    }
    #[cfg(not(unix))]
    loop {
        // On embedded, there's not much left to do.
    }
}

/// The DarwinKit LibAFL fuzzer entry point so that the fuzz harness can e.g. fetch symbols
/// and call the appropriate functions that are meant for fuzzing
#[no_mangle]
extern "C" {
    pub fn LibAFLFuzzerTestOneInput(data: *const core::ffi::c_uchar, size: usize) -> u64;
}

/// Provides the macOS kernel os_log function to Rust in `no_std` environment
#[no_mangle]
extern "C" {
    pub fn darwin_kit_log(fmt: *const core::ffi::c_char, ...);
}

/// Provides the macOS kernel time in millsecs to Rust in `no_std` environment
#[no_mangle]
extern "C" {
    pub fn clock_get_system_microtime(secs: *mut core::ffi::c_ulong, microsecs: *mut core::ffi::c_ulong);
}

/// Provide custom time in `no_std` environment
/// Use a time provider of your choice
#[no_mangle]
pub extern "C" fn external_current_millis() -> u64 {
    let mut secs: core::ffi::c_ulong = 0;
    let mut microsecs: core::ffi::c_ulong = 0;
    unsafe {
        clock_get_system_microtime(&mut secs, &mut microsecs);
    }
    microsecs
}

const COVERAGE_MAP_SIZE: usize = 65536;

/// The main of this program.
/// # Panics
/// Will panic once the fuzzer finds the correct conditions.
#[no_mangle]
pub extern "C" fn libafl_start_darwin_kit_fuzzer(coverage_map: *const u8) -> isize {
    // The closure that we want to fuzz
    let mut harness = |input: &BytesInput| {
        let target = input.target_bytes();
        let buf = target.as_slice();
        unsafe {
            LibAFLFuzzerTestOneInput(
                buf.as_ptr() as *const core::ffi::c_uchar,
                buf.len() as usize,
            );
        }
        ExitKind::Ok
    };

    let map_ptr = NonNull::new(coverage_map as *mut u8)
        .expect("coverage_map is null")
        .cast::<[u8; COVERAGE_MAP_SIZE]>();

    // Create an observation channel using the signals map
    let observer = unsafe { ConstMapObserver::from_mut_ptr("signals", map_ptr) };
    // Feedback to rate the interestingness of an input
    let mut feedback = MaxMapFeedback::new(&observer);

    // A feedback to choose if an input is a solution or not
    let mut objective = CrashFeedback::new();

    // create a State from scratch
    let mut state = StdState::new(
        // RNG
        StdRand::new(),
        // Corpus that will be evolved, we keep it in memory for performance
        InMemoryCorpus::new(),
        // Corpus in which we store solutions (crashes in this example),
        // on disk so the user can get them after stopping the fuzzer
        InMemoryCorpus::new(),
        // States of the feedbacks.
        // The feedbacks can report the data that should persist in the State.
        &mut feedback,
        // Same for objective feedbacks
        &mut objective,
    )
    .unwrap();

    // The Monitor trait define how the fuzzer stats are reported to the user
    let monitor = SimpleMonitor::new(|s| {
        // TODO: Print `s` here, if your target permits it.
        #[cfg(any(windows, unix))]
        unsafe {
            let s = CString::new(s).unwrap();
            darwin_kit_log(c"%s\n".as_ptr().cast(), s.as_ptr());
        }
    });

    // The event manager handle the various events generated during the fuzzing loop
    // such as the notification of the addition of a new item to the corpus
    let mut mgr = SimpleEventManager::new(monitor);

    // A queue policy to get testcasess from the corpus
    let scheduler = QueueScheduler::new();

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // Create the executor for an in-process function with just one observer
    let mut executor = InProcessExecutor::new(
        &mut harness,
        tuple_list!(observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
    )
    .expect("Failed to create the Executor");

    // Generator of printable bytearrays of max size 32
    let mut generator = RandPrintablesGenerator::new(nonzero!(32));

    // Generate 8 initial inputs
    state
        .generate_initial_inputs(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 8)
        .expect("Failed to generate the initial corpus");

    // Setup a mutational stage with a basic bytes mutator
    let mutator = HavocScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");

    0
}

