#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// Structured input for command validation fuzzing.
#[derive(Debug, Arbitrary)]
struct CommandInput {
    args: Vec<String>,
    max_len: usize,
}

// Fuzz command validation with arbitrary argument lists and limits.
fuzz_target!(|input: CommandInput| {
    let max_len = input.max_len.min(1_000_000); // cap to avoid OOM
    let _ = shakti::validate_command(&input.args, max_len);
});
