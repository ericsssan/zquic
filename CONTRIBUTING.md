# Contributing to zquic

Thanks for your interest in contributing. zquic is a QUIC transport library — contributions that improve RFC correctness, performance, or test coverage are especially welcome.

## Getting started

```sh
git clone https://github.com/ericsssan/zquic.git
cd zquic
zig build test --summary all
```

All 110 tests should pass before you make any changes.

## What to work on

Check the [open issues](https://github.com/ericsssan/zquic/issues) for things that need doing. If you want to work on something not listed, open an issue first to discuss it before writing code.

## Making changes

1. Fork the repo and create a branch from `main`
2. Make your changes
3. Ensure all tests pass: `zig build test --summary all`
4. Add tests for any new behavior
5. Open a pull request against `main`

## Code style

- Follow the conventions already in the codebase
- No external dependencies — all crypto via `std.crypto`, all I/O via `std.posix`
- No allocator in the hot path — use `Pool(T)` for heap-like allocation
- RFC references in comments where relevant (e.g. `// RFC 9000 §17.2`)

## RFC compliance

zquic aims to be correct before fast. If you find a deviation from RFC 9000, RFC 9001, or RFC 9438, please open a bug report with the relevant section cited.

## Security issues

Do not open public issues for security vulnerabilities. See [SECURITY.md](SECURITY.md).
