//! `const fn` implementation of the SHA-3 family of hash and extendable-output
//! functions.
//!
//! This crate allows you to use the SHA-3 hash and extendable-output functions
//! as constant expressions in Rust. For all other usages, the [sha3](https://crates.io/crates/sha3)
//! crate includes more optimized implementations of these hash functions.
//!
//! # Examples
//!
//! ```rust
//! # use keccak_const::Shake256;
//! const PSEUDO_RANDOM_BYTES: [u8; 1000] = Shake256::new()
//!         .update(b"The quick brown fox ")
//!         .update(b"jumps over the lazy dog")
//!         .finalize();
//! ```
//!
//! ```rust
//! # use keccak_const::Shake128;
//! const ROUND_CONSTANTS: [u128; 8] = {
//!     let shake = Shake128::new()
//!         .update(b"The quick brown fox ")
//!         .update(b"jumps over the lazy dog");
//!
//!     let mut reader = shake.finalize_xof();
//!     let mut output = [0; 8];
//!
//!     let mut i = 0;
//!     while i < 8 {
//!         let buf: [u8; 16];
//!         buf = reader.read();
//!         output[i] = u128::from_be_bytes(buf);
//!         i += 1;
//!     }
//!
//!     output
//! };
//!
//! assert_eq!(
//!     [
//!         324498722242859095401832112442782838951,
//!         100470442341479765851591908475476895342,
//!         241049111671168257801898223573666863059,
//!         139197826094415251816510671569090212218,
//!         73371475849610774600276735485442220492,
//!         321031806373587100556524628628207173306,
//!         70553598458795679727810425741185559539,
//!         297273966300911440566694043047331846682,
//!     ],
//!     ROUND_CONSTANTS,
//! );
//! ```

#![no_std]

mod keccak;

use keccak::KeccakState;
use keccak::XofReader;

const PADDING_SHA3: u8 = 0x06;
const PADDING_KECCAK: u8 = 0x01;

macro_rules! sha3 {
    (
        $(#[$doc:meta])* $name:ident,
        $security:literal,
        $padding:expr,
    ) => {
        $(#[$doc])*
        #[derive(Clone)]
        pub struct $name {
            state: KeccakState,
        }

        impl $name {
            /// Constructs a new hasher
            pub const fn new() -> $name {
                $name {
                    state: KeccakState::new($security, $padding),
                }
            }

            /// Absorbs additional input
            ///
            /// Can be called multiple times
            pub const fn update(mut self, input: &[u8]) -> Self {
                self.state = self.state.update(input);
                self
            }

            /// Pads and squeezes the state to the output
            pub const fn finalize(&self) -> [u8; {$security / 8}] {
                let mut reader = self.state.finalize();
                reader.read::<{$security / 8}>()
            }

            /// Pads and squeezes the state to the output
            pub const fn finalize_into(&self, output: &mut [u8; {$security / 8}]) {
                let mut reader = self.state.finalize();
                reader.read_into::<{$security / 8}>(output);
            }
        }

        impl Default for $name {
            fn default() -> Self {
                $name::new()
            }
        }
    };
}

sha3!(
    /// The `SHA3-224` hash function
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use keccak_const::Sha3_224;
    /// const DIGEST: [u8; 28] = Sha3_224::new()
    ///     .update(b"The quick brown fox ")
    ///     .update(b"jumps over the lazy dog")
    ///     .finalize();
    ///
    /// assert_eq!(
    ///     [
    ///         0xd1, 0x5d, 0xad, 0xce, 0xaa, 0x4d, 0x5d, 0x7b, 0xb3, 0xb4, 0x8f, 0x44, 0x64, 0x21,
    ///         0xd5, 0x42, 0xe0, 0x8a, 0xd8, 0x88, 0x73, 0x05, 0xe2, 0x8d, 0x58, 0x33, 0x57, 0x95
    ///     ],
    ///     DIGEST,
    /// );
    /// ```
    Sha3_224,
    224,
    PADDING_SHA3,
);

sha3!(
    /// The `SHA3-256` hash function
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use keccak_const::Sha3_256;
    /// const DIGEST: [u8; 32] = Sha3_256::new()
    ///     .update(b"The quick brown fox ")
    ///     .update(b"jumps over the lazy dog")
    ///     .finalize();
    ///
    /// assert_eq!(
    ///     [
    ///         0x69, 0x07, 0x0d, 0xda, 0x01, 0x97, 0x5c, 0x8c, 0x12, 0x0c, 0x3a, 0xad, 0xa1, 0xb2,
    ///         0x82, 0x39, 0x4e, 0x7f, 0x03, 0x2f, 0xa9, 0xcf, 0x32, 0xf4, 0xcb, 0x22, 0x59, 0xa0,
    ///         0x89, 0x7d, 0xfc, 0x04
    ///     ],
    ///     DIGEST,
    /// );
    /// ```
    Sha3_256,
    256,
    PADDING_SHA3,
);

sha3!(
    /// The `SHA3-384` hash function
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use keccak_const::Sha3_384;
    /// const DIGEST: [u8; 48] = Sha3_384::new()
    ///     .update(b"The quick brown fox ")
    ///     .update(b"jumps over the lazy dog")
    ///     .finalize();
    ///
    /// assert_eq!(
    ///     [
    ///         0x70, 0x63, 0x46, 0x5e, 0x08, 0xa9, 0x3b, 0xce, 0x31, 0xcd, 0x89, 0xd2, 0xe3, 0xca,
    ///         0x8f, 0x60, 0x24, 0x98, 0x69, 0x6e, 0x25, 0x35, 0x92, 0xed, 0x26, 0xf0, 0x7b, 0xf7,
    ///         0xe7, 0x03, 0xcf, 0x32, 0x85, 0x81, 0xe1, 0x47, 0x1a, 0x7b, 0xa7, 0xab, 0x11, 0x9b,
    ///         0x1a, 0x9e, 0xbd, 0xf8, 0xbe, 0x41
    ///     ],
    ///     DIGEST,
    /// );
    /// ```
    Sha3_384,
    384,
    PADDING_SHA3,
);

sha3!(
    /// The `SHA3-512` hash function
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use keccak_const::Sha3_512;
    /// const DIGEST: [u8; 64] = Sha3_512::new()
    ///     .update(b"The quick brown fox ")
    ///     .update(b"jumps over the lazy dog")
    ///     .finalize();
    ///
    /// assert_eq!(
    ///     [
    ///         0x01, 0xde, 0xdd, 0x5d, 0xe4, 0xef, 0x14, 0x64, 0x24, 0x45, 0xba, 0x5f, 0x5b, 0x97,
    ///         0xc1, 0x5e, 0x47, 0xb9, 0xad, 0x93, 0x13, 0x26, 0xe4, 0xb0, 0x72, 0x7c, 0xd9, 0x4c,
    ///         0xef, 0xc4, 0x4f, 0xff, 0x23, 0xf0, 0x7b, 0xf5, 0x43, 0x13, 0x99, 0x39, 0xb4, 0x91,
    ///         0x28, 0xca, 0xf4, 0x36, 0xdc, 0x1b, 0xde, 0xe5, 0x4f, 0xcb, 0x24, 0x02, 0x3a, 0x08,
    ///         0xd9, 0x40, 0x3f, 0x9b, 0x4b, 0xf0, 0xd4, 0x50
    ///     ],
    ///     DIGEST,
    /// );
    /// ```
    Sha3_512,
    512,
    PADDING_SHA3,
);

sha3!(
    /// The `KECCAK-224` hash function
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use keccak_const::Keccak224;
    /// const DIGEST: [u8; 28] = Keccak224::new()
    ///     .update(b"The quick brown fox ")
    ///     .update(b"jumps over the lazy dog")
    ///     .finalize();
    ///
    /// assert_eq!(
    ///     [
    ///         0x31, 0x0a, 0xee, 0x6b, 0x30, 0xc4, 0x73, 0x50, 0x57, 0x6a, 0xc2, 0x87, 0x3f, 0xa8,
    ///         0x9f, 0xd1, 0x90, 0xcd, 0xc4, 0x88, 0x44, 0x2f, 0x3e, 0xf6, 0x54, 0xcf, 0x23, 0xfe
    ///     ],
    ///     DIGEST,
    /// );
    /// ```
    Keccak224,
    224,
    PADDING_KECCAK,
);

sha3!(
    /// The `KECCAK-256` hash function
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use keccak_const::Keccak256;
    /// const DIGEST: [u8; 32] = Keccak256::new()
    ///     .update(b"The quick brown fox ")
    ///     .update(b"jumps over the lazy dog")
    ///     .finalize();
    ///
    /// assert_eq!(
    ///     [
    ///         0x4d, 0x74, 0x1b, 0x6f, 0x1e, 0xb2, 0x9c, 0xb2, 0xa9, 0xb9, 0x91, 0x1c, 0x82, 0xf5,
    ///         0x6f, 0xa8, 0xd7, 0x3b, 0x04, 0x95, 0x9d, 0x3d, 0x9d, 0x22, 0x28, 0x95, 0xdf, 0x6c,
    ///         0x0b, 0x28, 0xaa, 0x15
    ///     ],
    ///     DIGEST,
    /// );
    /// ```
    Keccak256,
    256,
    PADDING_KECCAK,
);

sha3!(
    /// The `KECCAK-384` hash function
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use keccak_const::Keccak384;
    /// const DIGEST: [u8; 48] = Keccak384::new()
    ///     .update(b"The quick brown fox ")
    ///     .update(b"jumps over the lazy dog")
    ///     .finalize();
    ///
    /// assert_eq!(
    ///     [
    ///         0x28, 0x39, 0x90, 0xfa, 0x9d, 0x5f, 0xb7, 0x31, 0xd7, 0x86, 0xc5, 0xbb, 0xee, 0x94,
    ///         0xea, 0x4d, 0xb4, 0x91, 0x0f, 0x18, 0xc6, 0x2c, 0x03, 0xd1, 0x73, 0xfc, 0x0a, 0x5e,
    ///         0x49, 0x44, 0x22, 0xe8, 0xa0, 0xb3, 0xda, 0x75, 0x74, 0xda, 0xe7, 0xfa, 0x0b, 0xaf,
    ///         0x00, 0x5e, 0x50, 0x40, 0x63, 0xb3
    ///     ],
    ///     DIGEST,
    /// );
    /// ```
    Keccak384,
    384,
    PADDING_KECCAK,
);

sha3!(
    /// The `KECCAK-512` hash function
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use keccak_const::Keccak512;
    /// const DIGEST: [u8; 64] = Keccak512::new()
    ///     .update(b"The quick brown fox ")
    ///     .update(b"jumps over the lazy dog")
    ///     .finalize();
    ///
    /// assert_eq!(
    ///     [
    ///         0xd1, 0x35, 0xbb, 0x84, 0xd0, 0x43, 0x9d, 0xba, 0xc4, 0x32, 0x24, 0x7e, 0xe5, 0x73,
    ///         0xa2, 0x3e, 0xa7, 0xd3, 0xc9, 0xde, 0xb2, 0xa9, 0x68, 0xeb, 0x31, 0xd4, 0x7c, 0x4f,
    ///         0xb4, 0x5f, 0x1e, 0xf4, 0x42, 0x2d, 0x6c, 0x53, 0x1b, 0x5b, 0x9b, 0xd6, 0xf4, 0x49,
    ///         0xeb, 0xcc, 0x44, 0x9e, 0xa9, 0x4d, 0x0a, 0x8f, 0x05, 0xf6, 0x21, 0x30, 0xfd, 0xa6,
    ///         0x12, 0xda, 0x53, 0xc7, 0x96, 0x59, 0xf6, 0x09
    ///     ],
    ///     DIGEST,
    /// );
    /// ```
    Keccak512,
    512,
    PADDING_KECCAK,
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
            pub const fn update(mut self, input: &[u8]) -> Self {
                self.state = self.state.update(input);
                self
            }

            /// Retrieves an extendable-output function (XOF) reader for current hasher instance
            pub const fn finalize_xof(&self) -> XofReader {
                self.state.finalize()
            }

            /// Finalizes the context and compute the output
            pub const fn finalize<const N: usize>(&self) -> [u8; N] {
                let mut reader = self.finalize_xof();
                reader.read::<N>()
            }

            /// Finalizes the context and compute the output
            pub const fn finalize_into<const N: usize>(&self, output: &mut [u8; N]) {
                let mut reader = self.finalize_xof();
                reader.read_into::<N>(output);
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
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use keccak_const::Shake128;
    /// const PSEUDO_RANDOM_BYTES: [u8; 32] = Shake128::new()
    ///     .update(b"The quick brown fox ")
    ///     .update(b"jumps over the lazy dog")
    ///     .finalize();
    ///
    /// assert_eq!(
    ///     [
    ///         0xf4, 0x20, 0x2e, 0x3c, 0x58, 0x52, 0xf9, 0x18, 0x2a, 0x04, 0x30, 0xfd, 0x81, 0x44,
    ///         0xf0, 0xa7, 0x4b, 0x95, 0xe7, 0x41, 0x7e, 0xca, 0xe1, 0x7d, 0xb0, 0xf8, 0xcf, 0xee,
    ///         0xd0, 0xe3, 0xe6, 0x6e,
    ///     ],
    ///     PSEUDO_RANDOM_BYTES,
    /// );
    /// ```
    ///
    /// ```rust
    /// # use keccak_const::Shake128;
    /// const ROUND_CONSTANTS_LEN: usize = 16;
    /// const ROUND_CONSTANTS: [u128; ROUND_CONSTANTS_LEN] = {
    ///     let shake = Shake128::new()
    ///         .update(b"The quick brown fox ")
    ///         .update(b"jumps over the lazy dog");
    ///     let mut reader = shake.finalize_xof();
    ///     let mut output = [0; ROUND_CONSTANTS_LEN];
    ///     let mut i = 0;
    ///     while i < ROUND_CONSTANTS_LEN {
    ///         let buf: [u8; 16];
    ///         buf = reader.read();
    ///         output[i] = u128::from_be_bytes(buf);
    ///         i += 1;
    ///     }
    ///     output
    /// };
    ///
    /// assert_eq!(
    ///     [
    ///         324498722242859095401832112442782838951,
    ///         100470442341479765851591908475476895342,
    ///         241049111671168257801898223573666863059,
    ///         139197826094415251816510671569090212218,
    ///         73371475849610774600276735485442220492,
    ///         321031806373587100556524628628207173306,
    ///         70553598458795679727810425741185559539,
    ///         297273966300911440566694043047331846682,
    ///         112409550095757610585880508546188812219,
    ///         9460513120811775587939596453044060211,
    ///         211668019939948365501534576791633315998,
    ///         50002500201489421996668063727168431450,
    ///         333627932176661322387974747609682513723,
    ///         182198809023207418976073231225478277370,
    ///         318669594573585197479605797034214181928,
    ///         298412008578376288352503392148066037786,
    ///     ],
    ///     ROUND_CONSTANTS,
    /// );
    /// ```
    Shake128,
    128,
);

shake!(
    /// The `SHAKE256` extendable-output function
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use keccak_const::Shake256;
    /// const PSEUDO_RANDOM_BYTES: [u8; 64] = Shake256::new()
    ///     .update(b"The quick brown fox ")
    ///     .update(b"jumps over the lazy dog")
    ///     .finalize();
    ///
    /// assert_eq!(
    ///     [
    ///         0x2f, 0x67, 0x13, 0x43, 0xd9, 0xb2, 0xe1, 0x60, 0x4d, 0xc9, 0xdc, 0xf0, 0x75, 0x3e,
    ///         0x5f, 0xe1, 0x5c, 0x7c, 0x64, 0xa0, 0xd2, 0x83, 0xcb, 0xbf, 0x72, 0x2d, 0x41, 0x1a,
    ///         0x0e, 0x36, 0xf6, 0xca, 0x1d, 0x01, 0xd1, 0x36, 0x9a, 0x23, 0x53, 0x9c, 0xd8, 0x0f,
    ///         0x7c, 0x05, 0x4b, 0x6e, 0x5d, 0xaf, 0x9c, 0x96, 0x2c, 0xad, 0x5b, 0x8e, 0xd5, 0xbd,
    ///         0x11, 0x99, 0x8b, 0x40, 0xd5, 0x73, 0x44, 0x42
    ///     ],
    ///     PSEUDO_RANDOM_BYTES,
    /// );
    /// ```
    ///
    /// ```rust
    /// # use keccak_const::Shake256;
    /// const ROUND_CONSTANTS_LEN: usize = 16;
    /// const ROUND_CONSTANTS: [u128; ROUND_CONSTANTS_LEN] = {
    ///     let shake = Shake256::new()
    ///         .update(b"The quick brown fox ")
    ///         .update(b"jumps over the lazy dog");
    ///     let mut reader = shake.finalize_xof();
    ///     let mut output = [0; ROUND_CONSTANTS_LEN];
    ///     let mut i = 0;
    ///     while i < ROUND_CONSTANTS_LEN {
    ///         let buf: [u8; 16];
    ///         buf = reader.read();
    ///         output[i] = u128::from_be_bytes(buf);
    ///         i += 1;
    ///     }
    ///     output
    /// };
    ///
    /// assert_eq!(
    ///     [
    ///         63008913119763991345740861509526773729,
    ///         122934861405288129899227865927808120522,
    ///         38557047524252432877084375354350394799,
    ///         208139318032057588670393890858232661058,
    ///         253672765511221901359815901266029094236,
    ///         24673942916364082950221119418287074493,
    ///         314501551299016784988697613270261126631,
    ///         55846473543301730160082510643706458461,
    ///         74217159387677683656408416866508597390,
    ///         103097936643341605695740861737581768184,
    ///         43427127028232698635034841870476065529,
    ///         30671809218547569588332151812578484838,
    ///         234968987069139406291454845949508600001,
    ///         174416227018858056231916805199588046174,
    ///         206220167108618043277683992075133751175,
    ///         50389517484914419772600260972881863524,
    ///     ],
    ///     ROUND_CONSTANTS,
    /// );
    /// ```
    Shake256,
    256,
);

macro_rules! cshake {
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
            pub const fn new(name: &[u8], custom_string: &[u8]) -> $name {
                $name {
                    state: KeccakState::new_custom($security, name, custom_string),
                }
            }

            /// Absorbs additional input
            ///
            /// Can be called multiple times.
            pub const fn update(mut self, input: &[u8]) -> Self {
                self.state = self.state.update(input);
                self
            }

            /// Retrieves an extendable-output function (XOF) reader for current hasher instance
            pub const fn finalize_xof(&self) -> XofReader {
                self.state.finalize()
            }

            /// Finalizes the context and compute the output
            pub const fn finalize<const N: usize>(&self) -> [u8; N] {
                let mut reader = self.finalize_xof();
                reader.read::<N>()
            }

            /// Finalizes the context and compute the output
            pub const fn finalize_into<const N: usize>(&self, output: &mut [u8; N]) {
                let mut reader = self.finalize_xof();
                reader.read_into::<N>(output);
            }
        }
    };
}

cshake!(
    /// The `cSHAKE128` extendable-output function with explicit domain separation
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use keccak_const::CShake128;
    /// const PSEUDO_RANDOM_BYTES: [u8; 32] = CShake128::new(b"", b"Email Signature")
    ///     .update(b"The quick brown fox ")
    ///     .update(b"jumps over the lazy dog")
    ///     .finalize();
    ///
    /// assert_eq!(
    ///     [
    ///         0x99, 0x83, 0xd0, 0x72, 0xc4, 0xfd, 0xdc, 0xd9, 0xb1, 0x17, 0x4e, 0x11, 0xa6, 0x53,
    ///         0x11, 0xa5, 0xff, 0x5e, 0xc8, 0x22, 0xd2, 0xa9, 0x4a, 0x72, 0x2c, 0x28, 0x61, 0x0d,
    ///         0x5d, 0x2e, 0xea, 0x16,
    ///     ],
    ///     PSEUDO_RANDOM_BYTES,
    /// );
    /// ```
    ///
    /// ```rust
    /// # use keccak_const::CShake128;
    /// const ROUND_CONSTANTS_LEN: usize = 16;
    /// const ROUND_CONSTANTS: [u128; ROUND_CONSTANTS_LEN] = {
    ///     let shake = CShake128::new(b"", b"Email Signature")
    ///         .update(b"The quick brown fox ")
    ///         .update(b"jumps over the lazy dog");
    ///     let mut reader = shake.finalize_xof();
    ///     let mut output = [0; ROUND_CONSTANTS_LEN];
    ///     let mut i = 0;
    ///     while i < ROUND_CONSTANTS_LEN {
    ///         let buf: [u8; 16];
    ///         buf = reader.read();
    ///         output[i] = u128::from_be_bytes(buf);
    ///         i += 1;
    ///     }
    ///     output
    /// };
    ///
    /// assert_eq!(
    ///     [
    ///         204056302077734240240879225809365307813,
    ///         339445274070730589293852728023313213974,
    ///         311034419446408954611264450268137939208,
    ///         169833205514626068102220920404881299347,
    ///         128779754926350612467392383462135991915,
    ///         169596822230703494769597829420356525863,
    ///         338838196030380375062802366596142924088,
    ///         265015862682257661285131614916376299461,
    ///         265076480552089556643027922422174729374,
    ///         250167117179187385998538284585514868340,
    ///         189998676605234792367838451471032457698,
    ///         48895371892810347736363246647811124490,
    ///         223136061692570272601203217511554762399,
    ///         283232081694859150497502828176157152835,
    ///         223709651807484560997162663981801935765,
    ///         6571448238390366486053042731136101175
    ///     ],
    ///     ROUND_CONSTANTS,
    /// );
    /// ```
    CShake128,
    128,
);

cshake!(
    /// The `cSHAKE256` extendable-output function
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use keccak_const::CShake256;
    /// const PSEUDO_RANDOM_BYTES: [u8; 64] = CShake256::new(b"", b"Email Signature")
    ///     .update(b"The quick brown fox ")
    ///     .update(b"jumps over the lazy dog")
    ///     .finalize();
    ///
    /// assert_eq!(
    ///     [
    ///         0xa0, 0xef, 0x16, 0x20, 0x7f, 0xee, 0x1f, 0x24, 0x10, 0x2b, 0xbf, 0x54, 0x47, 0x8d,
    ///         0xae, 0xc5, 0xcc, 0x31, 0xee, 0xac, 0xd6, 0xa0, 0xf4, 0x63, 0x6c, 0xa5, 0x7e, 0x69,
    ///         0xc7, 0x31, 0x8f, 0x5e, 0xd2, 0x1f, 0xa8, 0x83, 0x88, 0x69, 0x49, 0xfa, 0x80, 0x5a,
    ///         0xb7, 0x9c, 0xeb, 0xca, 0x4f, 0xd1, 0x71, 0xc8, 0x8a, 0x19, 0x50, 0x37, 0x9d, 0x87,
    ///         0xd4, 0x11, 0xaa, 0x15, 0x62, 0x62, 0xf6, 0x37,
    ///     ],
    ///     PSEUDO_RANDOM_BYTES,
    /// );
    /// ```
    ///
    /// ```rust
    /// # use keccak_const::CShake256;
    /// const ROUND_CONSTANTS_LEN: usize = 16;
    /// const ROUND_CONSTANTS: [u128; ROUND_CONSTANTS_LEN] = {
    ///     let shake = CShake256::new(b"", b"Email Signature")
    ///         .update(b"The quick brown fox ")
    ///         .update(b"jumps over the lazy dog");
    ///     let mut reader = shake.finalize_xof();
    ///     let mut output = [0; ROUND_CONSTANTS_LEN];
    ///     let mut i = 0;
    ///     while i < ROUND_CONSTANTS_LEN {
    ///         let buf: [u8; 16];
    ///         buf = reader.read();
    ///         output[i] = u128::from_be_bytes(buf);
    ///         i += 1;
    ///     }
    ///     output
    /// };
    ///
    /// assert_eq!(
    ///     [
    ///         213917887062681311912024144481950215877,
    ///         271421774593345040501586071538453548894,
    ///         279302258183366863715994015928312025041,
    ///         151244023873457861573879094243945018935,
    ///         46789858736507269204053399607645187198,
    ///         248640048152571734342586449302509022469,
    ///         87086772420130548284400646298592643535,
    ///         199417999797902562945334686535761913572,
    ///         81962406407140912004770489768959623055,
    ///         111010449653295045276375386463252108001,
    ///         162516068383131012052791378781991998144,
    ///         177189787204746392129035534133259592877,
    ///         200113111696997708342773515999166260128,
    ///         331676797110137524588588956973531151341,
    ///         20637875926079105932508270204733169627,
    ///         67866115595833730269190197080092801034
    ///     ],
    ///     ROUND_CONSTANTS,
    /// );
    /// ```
    CShake256,
    256,
);
