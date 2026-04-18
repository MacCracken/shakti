.PHONY: check fmt clippy test audit deny build doc clean

check: fmt clippy test audit

fmt:
	cargo fmt --all -- --check

clippy:
	cargo clippy --all-targets -- -D warnings

test:
	cargo test

audit:
	cargo audit

deny:
	cargo deny check

build:
	cargo build --release

doc:
	RUSTDOCFLAGS="-D warnings" cargo doc --no-deps

clean:
	cargo clean
