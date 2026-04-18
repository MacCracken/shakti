#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz username validation with invariant checks on accepted inputs.
fuzz_target!(|data: &[u8]| {
    if let Ok(input) = std::str::from_utf8(data) {
        let result = shakti::validate_username(input);

        // Invariant checks: if the function accepts the input,
        // it must not contain dangerous characters
        if result.is_ok() {
            assert!(!input.is_empty(), "Empty username accepted");
            assert!(!input.contains('/'), "Username with / accepted");
            assert!(!input.contains('\0'), "Username with null byte accepted");
            assert!(input != "." && input != "..", "Dot username accepted");
        }
    }
});
