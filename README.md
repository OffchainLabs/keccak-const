# sha3-const

[![Build status](https://github.com/andrewmilson/sha3-const/workflows/CI/badge.svg)](https://github.com/andrewmilson/sha3-const/actions)
[![Crate](https://img.shields.io/crates/v/sha3-const.svg)](https://crates.io/crates/sha3-const)
[![Documentation](https://docs.rs/sha3-const/badge.svg)](https://docs.rs/sha3-const)

`const fn` implementation of the SHA-3 family of hash and extendable-output functions (inspired by [sha2-const](https://crates.io/crates/sha2-const)). This crate allows you to use use the Sha3 hash functions as constant expressions in rust. For all other usages, the [sha3](https://crates.io/crates/sha3) crate includes more optimized implementations of these hash functions.

Based on the [Keccak specifications](https://keccak.team/keccak_specs_summary.html).
