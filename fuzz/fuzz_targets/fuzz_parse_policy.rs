#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz the TOML policy parser with arbitrary byte strings.
fuzz_target!(|data: &[u8]| {
    if let Ok(input) = std::str::from_utf8(data) {
        // Must never panic — errors are fine, panics are not
        let _ = shakti::parse_policy(input);
    }
});
