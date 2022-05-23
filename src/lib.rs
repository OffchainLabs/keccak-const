//! `const fn` implementation of the SHA-3 family of hash and extendable-output
//! functions.
//!
//! This crate allows you to use the SHA-3 hash and extendable-output functions
//! as constant expressions in Rust. For all other usages, the [sha3](https://crates.io/crates/sha3)
//! crate includes more
//! optimized implementations of these hash functions.
//!
//! # Example
//!
//! ```rust
//! # use sha3_const::Shake256;
//! const PSEUDO_RANDOM_BYTES: [u8; 1000] = Shake256::new()
//!         .update(b":)")
//!         .update(b";)")
//!         .finalize();
//! ```

#![feature(const_mut_refs)]
#![no_std]

mod keccak;

use keccak::KeccakState;
use keccak::XofReader;

macro_rules! sha3 {
    (
        $(#[$doc:meta])* $name:ident,
        $security:literal,
    ) => {
        $(#[$doc])*
        pub struct $name {
            state: KeccakState,
        }

        impl $name {
            /// Constructs a new hasher
            pub const fn new() -> $name {
                $name {
                    state: KeccakState::new($security, 0x06),
                }
            }

            /// Absorbs additional input
            ///
            /// Can be called multiple times
            ///
            /// Takes `mut self` instead of `&mut self` because mutable references are unstable in constants.
            pub const fn update(mut self, input: &[u8]) -> Self {
                self.state.update(input);
                self
            }

            /// Pads and squeezes the state to the output
            pub const fn finalize(&self) -> [u8; {$security / 8}] {
                let mut reader = self.state.finalize();
                let mut output = [0; {$security / 8}];
                reader.read(&mut output);
                output
            }
        }
    };
}

sha3!(
    /// The `SHA3-224` hash function
    Sha3_224,
    224,
);

sha3!(
    /// The `SHA3-256` hash function
    Sha3_256,
    256,
);

sha3!(
    /// The `SHA3-384` hash function
    Sha3_384,
    384,
);

sha3!(
    /// The `SHA3-512` hash function
    Sha3_512,
    512,
);

macro_rules! shake {
    (
        $(#[$doc:meta])* $name:ident,
        $security:literal,
    ) => {
        $(#[$doc])*
        pub struct $name {
            state: KeccakState,
        }

        impl $name {
            /// Constructs a new hasher
            pub const fn new() -> $name {
                $name {
                    state: KeccakState::new($security, 0x1f),
                }
            }

            /// Absorbs additional input
            ///
            /// Can be called multiple times.
            ///
            /// Takes `mut self` instead of `&mut self` because mutable references are unstable in constants.
            pub const fn update(mut self, input: &[u8]) -> Self {
                self.state.update(input);
                self
            }

            /// Retrieves an extendable-output function (XOF) reader for current hasher instance
            pub const fn finalize_xof(&self) -> XofReader {
                self.state.finalize()
            }

            /// Finalizes the context and compute the output
            pub const fn finalize<const N: usize>(&self) -> [u8; N] {
                let mut reader = self.finalize_xof();
                let mut output = [0; N];
                reader.read(&mut output);
                output
            }
        }

        impl Default for $name {
            fn default() -> Self {
                $name::new()
            }
        }
    };
}

shake!(
    /// The `SHAKE128` extendable-output function
    Shake128,
    128,
);

shake!(
    /// The `SHAKE256` extendable-output function
    Shake256,
    256,
);
