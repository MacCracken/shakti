# Contributing to Shakti

Thank you for your interest in contributing to Shakti!

## Getting Started

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run `make check` to verify
5. Submit a pull request

## Development

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

## Security

Shakti is a privilege escalation tool — security is paramount. Please review `SECURITY.md` before contributing security-sensitive changes.

## License

By contributing, you agree that your contributions will be licensed under GPL-3.0-only.
