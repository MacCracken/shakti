#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// Structured input for command matching fuzzing.
#[derive(Debug, Arbitrary)]
struct MatchInput {
    command: String,
    pattern: String,
}

// Fuzz command matching with arbitrary command/pattern pairs.
fuzz_target!(|input: MatchInput| {
    // Must never panic — any input combination should return true or false
    let _ = shakti::command_matches(&input.command, &input.pattern);
});
