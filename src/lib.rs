#![feature(const_mut_refs)]
// #![no_std]

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
            pub const fn update(&mut self, input: &[u8]) {
                self.state.update(input);
            }

            /// Pads and squeezes the state to the output
            pub const fn finalize(&self) -> [u8; {$security / 8}] {
                let mut xof_reader = self.state.finalize();
                let mut output = [0; {$security / 8}];
                xof_reader.read(&mut output);
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
            /// Can be called multiple times
            pub const fn update(&mut self, input: &[u8]) {
                self.state.update(input);
            }

            /// Retrieves an extendable-output function (XOF) reader for current hasher instance
            pub const fn finalize_xof(&self) -> XofReader {
                self.state.finalize()
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
