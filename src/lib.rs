#![feature(const_mut_refs)]
// #![no_std]

mod keccak;

use keccak::KeccakState;

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
            const OUTPUT_BYTES_LEN: usize = $security / 8;

            pub const fn new() -> $name {
                $name {
                    state: KeccakState::new($security, 0x06),
                }
            }

            pub const fn update(&mut self, input: &[u8]) {
                self.state.update(input);
            }

            pub const fn finish(&self) -> [u8; Self::OUTPUT_BYTES_LEN] {
                self.state.finish()
            }
        }
    };
}

sha3!(
    /// The `SHA3-224` hash function.
    Sha224,
    224,
);

sha3!(
    /// The `SHA3-256` hash function.
    Sha256,
    256,
);

sha3!(
    /// The `SHA3-384` hash function.
    Sha384,
    384,
);

sha3!(
    /// The `SHA3-512` hash function.
    Sha512,
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
            pub const fn new() -> $name {
                $name {
                    state: KeccakState::new($security, 0x1f),
                }
            }

            pub const fn update(&mut self, input: &[u8]) {
                self.state.update(input);
            }

            pub const fn finish<const N: usize>(&self) -> [u8; N] {
                self.state.finish()
            }
        }
    };
}

shake!(
    /// The `SHAKE128` hash function.
    Shake128,
    128,
);

shake!(
    /// The `SHAKE256` hash function.
    Shake256,
    256,
);

#[test]
fn shake_works() {
    let mut hasher = Shake256::new();
    hasher.update(b"Rescue-XLIX");

    let result = hasher.finish();

    assert_eq!([192, 33, 251, 3, 222, 123, 6, 0, 132, 72], result);
}
