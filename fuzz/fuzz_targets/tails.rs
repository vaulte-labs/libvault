#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| libvault::fuzzing::tails(data));
