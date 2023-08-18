//! Tests from https://github.com/emn178/js-sha3/blob/master/tests/test.js

use keccak_const::Keccak224;
use keccak_const::Keccak256;
use keccak_const::Keccak384;
use keccak_const::Keccak512;

#[test]
fn keccak224_empty_string() {
    assert_eq!(
        [
            0xf7, 0x18, 0x37, 0x50, 0x2b, 0xa8, 0xe1, 0x08, 0x37, 0xbd, 0xd8, 0xd3, 0x65, 0xad,
            0xb8, 0x55, 0x91, 0x89, 0x56, 0x02, 0xfc, 0x55, 0x2b, 0x48, 0xb7, 0x39, 0x0a, 0xbd,
        ],
        Keccak224::new().finalize(),
    );
}

#[test]
fn keccak224_ascii() {
    let output = Keccak224::new()
        .update(b"The quick brown fox jumps over the lazy dog")
        .finalize();

    assert_eq!(
        [
            0x31, 0x0a, 0xee, 0x6b, 0x30, 0xc4, 0x73, 0x50, 0x57, 0x6a, 0xc2, 0x87, 0x3f, 0xa8,
            0x9f, 0xd1, 0x90, 0xcd, 0xc4, 0x88, 0x44, 0x2f, 0x3e, 0xf6, 0x54, 0xcf, 0x23, 0xfe,
        ],
        output,
    );
}

#[test]
fn keccak224_utf8() {
    let output = Keccak224::new()
        .update("訊息摘要演算法第五版（英語：Message-Digest Algorithm 5，縮寫為MD5），是當前電腦領域用於確保資訊傳輸完整一致而廣泛使用的雜湊演算法之一".as_bytes())
        .finalize();

    assert_eq!(
        [
            0xd5, 0x9e, 0xef, 0x8f, 0x39, 0x4e, 0xf7, 0xd9, 0x69, 0x67, 0xbb, 0x0b, 0xde, 0x57,
            0x87, 0x85, 0xc0, 0x33, 0xf7, 0xf0, 0xa2, 0x19, 0x13, 0xd6, 0xba, 0x41, 0xed, 0x1b,
        ],
        output,
    );
}

#[test]
fn keccak224_updates() {
    let output = Keccak224::new()
        .update("訊息摘要演算法第五版（英語：Message-Digest Algorithm 5，縮寫為MD5），是當前電腦領域用於確保資訊傳輸".as_bytes())
        .update("完整一致而廣泛使用的雜湊演算法之一（又譯雜湊演算法、摘要演算法等），主流程式語言普遍已有MD5的實作。".as_bytes())
        .finalize();

    assert_eq!(
        [
            0x27, 0x12, 0x3a, 0x2a, 0x38, 0x60, 0xd1, 0x04, 0x1d, 0x47, 0x69, 0x77, 0x8c, 0x4b,
            0x07, 0x87, 0x32, 0xbf, 0x43, 0x00, 0xf7, 0xe1, 0xc5, 0x65, 0x36, 0xab, 0x26, 0x44,
        ],
        output,
    );
}

#[test]
fn keccak256_empty_string() {
    assert_eq!(
        [
            0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7,
            0x03, 0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04,
            0x5d, 0x85, 0xa4, 0x70,
        ],
        Keccak256::new().finalize(),
    );
}

#[test]
fn keccak256_ascii() {
    let output = Keccak256::new()
        .update(b"The quick brown fox jumps over the lazy dog")
        .finalize();

    assert_eq!(
        [
            0x4d, 0x74, 0x1b, 0x6f, 0x1e, 0xb2, 0x9c, 0xb2, 0xa9, 0xb9, 0x91, 0x1c, 0x82, 0xf5,
            0x6f, 0xa8, 0xd7, 0x3b, 0x04, 0x95, 0x9d, 0x3d, 0x9d, 0x22, 0x28, 0x95, 0xdf, 0x6c,
            0x0b, 0x28, 0xaa, 0x15,
        ],
        output,
    );
}

#[test]
fn keccak256_utf8() {
    let output = Keccak256::new()
        .update("訊息摘要演算法第五版（英語：Message-Digest Algorithm 5，縮寫為MD5），是當前電腦領域用於確保資訊傳輸完整一致而廣泛使用的雜湊演算法之一".as_bytes())
        .finalize();

    assert_eq!(
        [
            0xd1, 0x02, 0x1d, 0x2d, 0x4c, 0x5c, 0x7e, 0x88, 0x09, 0x8c, 0x40, 0xf4, 0x22, 0xaf,
            0x68, 0x49, 0x3b, 0x4b, 0x64, 0xc9, 0x13, 0xcb, 0xd6, 0x82, 0x20, 0xbf, 0x5e, 0x61,
            0x27, 0xc3, 0x7a, 0x88,
        ],
        output,
    );
}

#[test]
fn keccak256_updates() {
    let output = Keccak256::new()
        .update("訊息摘要演算法第五版（英語：Message-Digest Algorithm 5，縮寫為MD5），是當前電腦領域用於確保資訊傳輸".as_bytes())
        .update("完整一致而廣泛使用的雜湊演算法之一（又譯雜湊演算法、摘要演算法等），主流程式語言普遍已有MD5的實作。".as_bytes())
        .finalize();

    assert_eq!(
        [
            0xff, 0xab, 0xf9, 0xbb, 0xa2, 0x12, 0x7c, 0x49, 0x28, 0xd3, 0x60, 0xc9, 0x90, 0x5c,
            0xb4, 0x91, 0x1f, 0x0e, 0xc2, 0x1b, 0x9c, 0x3b, 0x89, 0xf3, 0xb2, 0x42, 0xbc, 0xcc,
            0x68, 0x38, 0x9e, 0x36,
        ],
        output,
    );
}

#[test]
fn keccak384_empty_string() {
    let hasher = Keccak384::new();

    let output = hasher.finalize();

    assert_eq!(
        [
            0x2c, 0x23, 0x14, 0x6a, 0x63, 0xa2, 0x9a, 0xcf, 0x99, 0xe7, 0x3b, 0x88, 0xf8, 0xc2,
            0x4e, 0xaa, 0x7d, 0xc6, 0x0a, 0xa7, 0x71, 0x78, 0x0c, 0xcc, 0x00, 0x6a, 0xfb, 0xfa,
            0x8f, 0xe2, 0x47, 0x9b, 0x2d, 0xd2, 0xb2, 0x13, 0x62, 0x33, 0x74, 0x41, 0xac, 0x12,
            0xb5, 0x15, 0x91, 0x19, 0x57, 0xff,
        ],
        output,
    );
}

#[test]
fn keccak384_ascii() {
    let output = Keccak384::new()
        .update(b"The quick brown fox jumps over the lazy dog")
        .finalize();

    assert_eq!(
        [
            0x28, 0x39, 0x90, 0xfa, 0x9d, 0x5f, 0xb7, 0x31, 0xd7, 0x86, 0xc5, 0xbb, 0xee, 0x94,
            0xea, 0x4d, 0xb4, 0x91, 0x0f, 0x18, 0xc6, 0x2c, 0x03, 0xd1, 0x73, 0xfc, 0x0a, 0x5e,
            0x49, 0x44, 0x22, 0xe8, 0xa0, 0xb3, 0xda, 0x75, 0x74, 0xda, 0xe7, 0xfa, 0x0b, 0xaf,
            0x00, 0x5e, 0x50, 0x40, 0x63, 0xb3,
        ],
        output,
    );
}

#[test]
fn keccak384_utf8() {
    let output = Keccak384::new()
        .update("訊息摘要演算法第五版（英語：Message-Digest Algorithm 5，縮寫為MD5），是當前電腦領域用於確保資訊傳輸完整一致而廣泛使用的雜湊演算法之一".as_bytes())
        .finalize();

    assert_eq!(
        [
            0xa3, 0xb0, 0x43, 0xa2, 0xf6, 0x9e, 0x43, 0x26, 0xa0, 0x5d, 0x47, 0x8f, 0xa4, 0xc8,
            0xaa, 0x2b, 0xd7, 0x61, 0x24, 0x53, 0xd7, 0x75, 0xaf, 0x37, 0x66, 0x5a, 0x0b, 0x96,
            0xef, 0x22, 0x07, 0xcd, 0xc7, 0x4c, 0x50, 0xcd, 0xba, 0x16, 0x29, 0x79, 0x6a, 0x51,
            0x36, 0xfe, 0x77, 0x30, 0x0b, 0x05,
        ],
        output,
    );
}

#[test]
fn keccak384_updates() {
    let output = Keccak384::new()
        .update("訊息摘要演算法第五版（英語：Message-Digest Algorithm 5，縮寫為MD5），是當前電腦領域用於確保資訊傳輸".as_bytes())
        .update("完整一致而廣泛使用的雜湊演算法之一（又譯雜湊演算法、摘要演算法等），主流程式語言普遍已有MD5的實作。".as_bytes())
        .finalize();

    assert_eq!(
        [
            0x66, 0x41, 0x4c, 0x09, 0x0c, 0xc3, 0xfe, 0x9c, 0x39, 0x6d, 0x31, 0x3c, 0xba, 0xa1,
            0x00, 0xae, 0xfd, 0x33, 0x5e, 0x85, 0x18, 0x38, 0xb2, 0x93, 0x82, 0x56, 0x8b, 0x7f,
            0x57, 0x35, 0x7a, 0xda, 0x7c, 0x54, 0xb8, 0xfa, 0x8c, 0x17, 0xf8, 0x59, 0x94, 0x5b,
            0xba, 0x88, 0xb2, 0xc2, 0xe3, 0x32,
        ],
        output,
    );
}

#[test]
fn keccak512_empty_string() {
    let hasher = Keccak512::new();

    let output = hasher.finalize();

    assert_eq!(
        [
            0x0e, 0xab, 0x42, 0xde, 0x4c, 0x3c, 0xeb, 0x92, 0x35, 0xfc, 0x91, 0xac, 0xff, 0xe7,
            0x46, 0xb2, 0x9c, 0x29, 0xa8, 0xc3, 0x66, 0xb7, 0xc6, 0x0e, 0x4e, 0x67, 0xc4, 0x66,
            0xf3, 0x6a, 0x43, 0x04, 0xc0, 0x0f, 0xa9, 0xca, 0xf9, 0xd8, 0x79, 0x76, 0xba, 0x46,
            0x9b, 0xcb, 0xe0, 0x67, 0x13, 0xb4, 0x35, 0xf0, 0x91, 0xef, 0x27, 0x69, 0xfb, 0x16,
            0x0c, 0xda, 0xb3, 0x3d, 0x36, 0x70, 0x68, 0x0e,
        ],
        output,
    );
}

#[test]
fn keccak512_ascii() {
    let output = Keccak512::new()
        .update(b"The quick brown fox jumps over the lazy dog")
        .finalize();

    assert_eq!(
        [
            0xd1, 0x35, 0xbb, 0x84, 0xd0, 0x43, 0x9d, 0xba, 0xc4, 0x32, 0x24, 0x7e, 0xe5, 0x73,
            0xa2, 0x3e, 0xa7, 0xd3, 0xc9, 0xde, 0xb2, 0xa9, 0x68, 0xeb, 0x31, 0xd4, 0x7c, 0x4f,
            0xb4, 0x5f, 0x1e, 0xf4, 0x42, 0x2d, 0x6c, 0x53, 0x1b, 0x5b, 0x9b, 0xd6, 0xf4, 0x49,
            0xeb, 0xcc, 0x44, 0x9e, 0xa9, 0x4d, 0x0a, 0x8f, 0x05, 0xf6, 0x21, 0x30, 0xfd, 0xa6,
            0x12, 0xda, 0x53, 0xc7, 0x96, 0x59, 0xf6, 0x09,
        ],
        output,
    );
}

#[test]
fn keccak512_utf8() {
    let output = Keccak512::new()
        .update("訊息摘要演算法第五版（英語：Message-Digest Algorithm 5，縮寫為MD5），是當前電腦領域用於確保資訊傳輸完整一致而廣泛使用的雜湊演算法之一".as_bytes())
        .finalize();

    assert_eq!(
        [
            0x6a, 0x67, 0xc2, 0x8a, 0xa1, 0x94, 0x6c, 0xa1, 0xbe, 0x83, 0x82, 0xb8, 0x61, 0xaa,
            0xc4, 0xaa, 0xf2, 0x00, 0x52, 0xf4, 0x95, 0xdb, 0x9b, 0x69, 0x02, 0xd1, 0x3a, 0xdf,
            0xa6, 0x03, 0xea, 0xba, 0x5d, 0x16, 0x9f, 0x88, 0x96, 0xb8, 0x6d, 0x46, 0x1b, 0x29,
            0x49, 0x28, 0x3e, 0xb9, 0x8e, 0x50, 0x3c, 0x3f, 0x06, 0x40, 0x18, 0x8e, 0xa7, 0xd6,
            0x73, 0x15, 0x26, 0xfc, 0x06, 0x56, 0x8d, 0x37,
        ],
        output,
    );
}

#[test]
fn keccak512_updates() {
    let output = Keccak512::new()
        .update("訊息摘要演算法第五版（英語：Message-Digest Algorithm 5，縮寫為MD5），是當前電腦領域用於確保資訊傳輸".as_bytes())
        .update("完整一致而廣泛使用的雜湊演算法之一（又譯雜湊演算法、摘要演算法等），主流程式語言普遍已有MD5的實作。".as_bytes())
        .finalize();

    assert_eq!(
        [
            0xd0, 0x4f, 0xf5, 0xb0, 0xe8, 0x5e, 0x99, 0x68, 0xbe, 0x2a, 0x4d, 0x4e, 0x13, 0x3c,
            0x15, 0xc7, 0xcc, 0xee, 0x74, 0x97, 0x19, 0x8b, 0xb6, 0x51, 0x59, 0x9a, 0x97, 0xd1,
            0x1d, 0x00, 0xbc, 0xa6, 0x04, 0x8d, 0x32, 0x9a, 0xb7, 0x5a, 0xa4, 0x54, 0x56, 0x6c,
            0xd5, 0x32, 0x64, 0x8f, 0xa1, 0xcb, 0x45, 0x51, 0x98, 0x5d, 0x9d, 0x64, 0x5d, 0xe9,
            0xfa, 0x43, 0xa3, 0x11, 0xa9, 0xee, 0x8e, 0x4d,
        ],
        output,
    );
}