# keccak-const

[![Build status](https://github.com/OffchainLabs/keccak-const/workflows/CI/badge.svg)](https://github.com/OffchainLabs/keccak-const/actions)
[![Crate](https://img.shields.io/crates/v/keccak-const.svg)](https://crates.io/crates/keccak-const)
[![Documentation](https://docs.rs/keccak-const/badge.svg)](https://docs.rs/keccak-const)

`const fn` implementation of the SHA-3 family of hash and extendable-output functions (inspired by [sha2-const](https://crates.io/crates/sha2-const)). This crate allows you to use use the Sha3 hash functions as constant expressions in rust. For all other usages, the [sha3](https://crates.io/crates/sha3) crate includes more optimized implementations of these hash functions.

Based on the [Keccak specification implementations](https://keccak.team/keccak_specs_summary.html).

A fork of the excellent [sha3-const](https://github.com/andrewmilson/sha3-const) that uses purely stable Rust.

## License

&copy; 2023 Offchain Labs, Inc.

This project is licensed under either of

- [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([licenses/Apache-2.0](licenses/Apache-2.0))
- [MIT license](https://opensource.org/licenses/MIT) ([licenses/MIT](licenses/MIT))

at your option.

The [SPDX](https://spdx.dev) license identifier for this project is `MIT OR Apache-2.0`.
