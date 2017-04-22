//! Data Encryption Standard Rust implementation.
//!
//! The only supported mode is Electronic Codebook (ECB).
//!
//! # Example
//!
//! ```c
//! extern crate des;
//!
//! let key = [0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1];
//! let message = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
//! let cipher = des::encrypt(&message, &key);
//! let message = des::decrypt(&cipher, &key);
//! ```
//!
//! # Usage
//!
//! Des exports two functions: `encrypt` and `decrypt`.
//! Use the former to encrypt some data with a key and the later to decrypt the data.

pub type Key = [u8; 8];

const FIRST_BIT:        u32 = 1 << 31;
const HALF_KEY_SIZE:    i64 = KEY_SIZE / 2;
const KEY_SIZE:         i64 = 56;

enum Ip {
    Direct,
    Reverse
}

/// Do a circular left shift on a width of `HALF_KEY_SIZE`.
fn circular_left_shift(ci: u32, di: u32, shift_count: u8) -> (u32, u32) {
    let mut ci_next = ci;
    let mut di_next = di;
    for _ in 0 .. shift_count {
        ci_next = (ci_next << 1) | ((ci_next & FIRST_BIT) >> (HALF_KEY_SIZE - 1));
        di_next = (di_next << 1) | ((di_next & FIRST_BIT) >> (HALF_KEY_SIZE - 1));
    }
    (ci_next, di_next)
}

/// Swap bits in `a` using a delta swap.
fn delta_swap(a: u64, delta: u8, mask: u64) -> u64 {
    let b = (a ^ (a >> delta)) & mask;
    a ^ b ^ (b << delta)
}

/// Convert a `Key` to a 64-bits integer.
fn key_to_u64(key: &Key) -> u64 {
    let mut result = 0;
    for &part in key {
        result <<= 8;
        result += part as u64;
    }
    result
}

/// Convert a message to a vector of 64-bits integer.
fn message_to_u64s(message: &[u8]) -> Vec<u64> {
    message.chunks(8)
        .map(|m| key_to_u64(&to_key(m)))
        .collect()
}

/// Convert a slice to a `Key`.
fn to_key(slice: &[u8]) -> Key {
    let mut vec: Vec<u8> = slice.iter().cloned().collect();
    let mut key = [0; 8];
    let diff = key.len() - vec.len();
    if diff > 0 {
        vec.append(&mut vec![0; diff]);
    }
    key.clone_from_slice(&vec);
    key
}

/// Convert a `u64` to a `Vec<u8>`.
fn to_u8_vec(num: u64) -> Vec<u8> {
    vec![
        ((num & 0xFF00000000000000) >> 56) as u8,
        ((num & 0x00FF000000000000) >> 48) as u8,
        ((num & 0x0000FF0000000000) >> 40) as u8,
        ((num & 0x000000FF00000000) >> 32) as u8,
        ((num & 0x00000000FF000000) >> 24) as u8,
        ((num & 0x0000000000FF0000) >> 16) as u8,
        ((num & 0x000000000000FF00) >>  8) as u8,
        ((num & 0x00000000000000FF) >>  0) as u8
    ]
}

/// Create the 16 subkeys.
fn compute_subkeys(key: u64) -> Vec<u64> {
    let table = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];
    let k0 = pc1(key);
    let mut subkeys = vec![k0];

    for shift_count in &table {
        let last_key = *subkeys.last().unwrap();
        let last_ci = ((last_key & 0xFFFFFFF000000000) >> 32) as u32;
        let last_di = (last_key >> 4) as u32;
        let (ci, di) = circular_left_shift(last_ci, last_di, *shift_count);
        let current_key = ((ci as u64) << 32) | ((di as u64) << 4);
        subkeys.push(current_key);
    }

    subkeys.remove(0);
    subkeys.iter().map(|&n| { pc2(n) }).collect()
}

/// Swap bits using the PC-1 table.
fn pc1(key: u64) -> u64 {
    let key = delta_swap(key,  2, 0x3333000033330000);
    let key = delta_swap(key,  4, 0x0F0F0F0F00000000);
    let key = delta_swap(key,  8, 0x009A000A00A200A8);
    let key = delta_swap(key, 16, 0x00006C6C0000CCCC);
    let key = delta_swap(key,  1, 0x1045500500550550);
    let key = delta_swap(key, 32, 0x00000000F0F0F5FA);
    let key = delta_swap(key,  8, 0x00550055006A00AA);
    let key = delta_swap(key,  2, 0x0000333330000300);
    key & 0xFFFFFFFFFFFFFF00
}

/// Swap bits using the PC-2 table.
fn pc2(key: u64) -> u64 {
    let key = key.rotate_left(61);
    let b1 = (key & 0x0021000002000000) >> 7;
    let b2 = (key & 0x0008020010080000) << 1;
    let b3 = key & 0x0002200000000000;
    let b4 = (key & 0x0000000000100020) << 19;
    let b5 = (key.rotate_left(54) & 0x0005312400000011).wrapping_mul(0x0000000094200201) & 0xea40100880000000;
    let b6 = (key.rotate_left(7) & 0x0022110000012001).wrapping_mul(0x0001000000610006) & 0x1185004400000000;
    let b7 = (key.rotate_left(6) & 0x0000520040200002).wrapping_mul(0x00000080000000c1) & 0x0028811000200000;
    let b8 = (key & 0x01000004c0011100).wrapping_mul(0x0000000000004284) & 0x0400082244400000;
    let b9 = (key.rotate_left(60) & 0x0000000000820280).wrapping_mul(0x0000000000089001) & 0x0000000110880000;
    let b10 = (key.rotate_left(49) & 0x0000000000024084).wrapping_mul(0x0000000002040005) & 0x000000000a030000;
    b1 | b2 | b3 | b4 | b5 | b6 | b7 | b8 | b9 | b10
}

/// Swap bits using the E table.
fn e(block: u32) -> u64 {
    const BLOCK_LEN: usize = 32;
    const RESULT_LEN: usize = 48;
    let block_exp = (block as u64) << 32;
    let b1 = ((block_exp << (BLOCK_LEN - 1))    & 0x8000000000000000) as u64;
    let b2 = ((block_exp >> 1)                  & 0x7C00000000000000) as u64;;
    let b3 = ((block_exp >> 3)                  & 0x03F0000000000000) as u64;;
    let b4 = ((block_exp >> 5)                  & 0x000FC00000000000) as u64;;
    let b5 = ((block_exp >> 7)                  & 0x00003F0000000000) as u64;;
    let b6 = ((block_exp >> 9)                  & 0x000000FC00000000) as u64;;
    let b7 = ((block_exp >> 11)                 & 0x00000003F0000000) as u64;;
    let b8 = ((block_exp >> 13)                 & 0x000000000FC00000) as u64;;
    let b9 = ((block_exp >> 15)                 & 0x00000000003E0000) as u64;;
    let b10 = ((block_exp >> (RESULT_LEN - 1))  & 0x0000000000010000) as u64;;
    b1 | b2 | b3 | b4 | b5 | b6 | b7 | b8 | b9 | b10
}

/// Swap bits using the P table.
fn p(block: u32) -> u32 {
    const P_TABLE: [u8; 32] = [
        16,  7, 20, 21, 29, 12, 28, 17,
         1, 15, 23, 26,  5, 18, 31, 10,
         2,  8, 24, 14, 32, 27,  3,  9,
        19, 13, 30,  6, 22, 11,  4, 25
    ];
    const BLOCK_SIZE: u8 = 32;

    let mut result: u32 = 0;
    for m in 0 .. BLOCK_SIZE as usize {
        if P_TABLE[m] > m as u8 {
            result |= (block & (0x01 << BLOCK_SIZE - P_TABLE[m])) << P_TABLE[m] - (m as u8 + 1);
        } else {
            result |= (block & (0x01 << BLOCK_SIZE - P_TABLE[m])) >> (m as u8 + 1) - P_TABLE[m];
        }
    }
    result
}

/// Produce 4-bits using an S box.
fn s(box_id: usize, block: u8) -> u8 {
    const TABLES: [[[u8; 16]; 4]; 8] = [
        [
            [ 14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7],
            [  0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8],
            [  4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0],
            [ 15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13]
        ],
        [
            [ 15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10],
            [  3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5],
            [  0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15],
            [ 13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9]
        ],
        [
            [ 10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8],
            [ 13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1],
            [ 13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7],
            [  1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12]
        ],
        [
            [  7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15],
            [ 13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9],
            [ 10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4],
            [  3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14]
        ],
        [
            [  2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9],
            [ 14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6],
            [  4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14],
            [ 11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3]
        ],
        [
            [ 12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11],
            [ 10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8],
            [  9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6],
            [  4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13]
        ],
        [
            [  4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1],
            [ 13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6],
            [  1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2],
            [  6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12]
        ],
        [
            [ 13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7],
            [  1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2],
            [  7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8],
            [  2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11]
        ]
    ];
    let i = ((block & 0x20) >> 4 | (block & 0x01)) as usize;
    let j = ((block & 0x1E) >> 1) as usize;
    TABLES[box_id][i][j]
}

/// ---------------------------------------------------------------
/// # Функции, используемые непосредственно в главном алгоритме DES
/// ---------------------------------------------------------------

/// Функция, выполняющая IP-перестановку (прямую и обратную)
fn ip(message: u64, dir: Ip) -> u64 {
    const COUNT: usize = 5;
    const MASK: [u64; COUNT] = [
        0x0055005500550055,
        0x0000333300003333,
        0x000000000F0F0F0F,
        0x00000000FF00FF00,
        0x000000FF000000FF
    ];
    const DELTA: [u8; COUNT] = [ 9, 18, 36, 24, 24];

    let mut result: u64 = message;
    match dir {
        Ip::Direct  => for i in 0 .. COUNT {
            result = delta_swap(result, DELTA[i], MASK[i])
        },
        Ip::Reverse => for i in (0 .. COUNT).rev() {
            result = delta_swap(result, DELTA[i], MASK[i])
        }
    }
    result
}

/// Feistel function.
fn feistel(half_block: u32, subkey: u64) -> u32 {
    let expanded = e(half_block);
    let mut intermediate = expanded ^ subkey;
    let mut result = 0 as u32;

    for i in 0 .. 8 {
        let block = ((intermediate & 0xFC00000000000000) >> 58) as u8;
        intermediate <<= 6;
        result <<= 4;
        result |= s(i, block) as u32;
    }

    p(result)
}

/// Encrypt `message` using `subkeys`.
fn des(message: &[u8], subkeys: Vec<u64>) -> Vec<u8> {
    let message_len = message.len();
    let message = message_to_u64s(message);

    let mut blocks = vec![];

    for msg in message {
        let permuted = ip(msg, Ip::Direct);
        let mut li: u32 = ((permuted & 0xFFFFFFFF00000000) >> 32) as u32;
        let mut ri: u32 = ((permuted & 0x00000000FFFFFFFF)) as u32;

        for subkey in &subkeys {
            let last_li = li;
            li = ri;
            ri = last_li ^ feistel(ri, *subkey);
        }

        let r16l16 = ( ( ri as u64 ) << 32 ) | li as u64;
        blocks.push(to_u8_vec(ip(r16l16, Ip::Reverse)));
    }

    let mut result = Vec::with_capacity(message_len);
    for mut block in blocks.into_iter() {
        result.append(&mut block);
    }
    result
}

/// Encrypt `message` using the `key`.
pub fn encrypt(message: &[u8], key: &Key) -> Vec<u8> {
    let key = key_to_u64(key);
    let subkeys = compute_subkeys(key);
    des(message, subkeys)
}

/// Decrypt `message` using the `key`.
pub fn decrypt(cipher: &[u8], key: &Key) -> Vec<u8> {
    let key = key_to_u64(key);
    let mut subkeys = compute_subkeys(key);
    subkeys.reverse();
    des(cipher, subkeys)
}

#[cfg(test)]
mod tests {
    use super::{decrypt, encrypt};
    use super::{e, p, pc1, pc2};

    #[test]
    fn test_e() {
        let result: [u64; 3] = [
            e(0b1111_0000_1010_1010_1111_0000_1010_1010),
            e(0b1111_0000_1010_1010_1111_0000_1010_1011),
            e(0b1111_1111_1111_1111_1111_1111_1111_1111),
        ];
        let expect: [u64; 3] = [
            0b011110_100001_010101_010101_011110_100001_010101_010101u64 << 16,
            0b111110_100001_010101_010101_011110_100001_010101_010111u64 << 16,
            0b111111_111111_111111_111111_111111_111111_111111_111111u64 << 16,
        ];
        for i in 0 .. 3 {
            assert_eq!(expect[i], result[i]);
        }
    }

    #[test]
    fn test_p() {
        let result: [u32; 2] = [
            p(0b1111_0000_0101_1010_1110_0111_1100_0011),
            p(0b1011_0111_0001_1000_0000_1011_0110_1010),
        ];
        let expect: [u32; 2] = [
            0b0000_0101_1111_0111_1010_1010_1100_1011,
            0b0101_1100_1011_0010_0110_0110_0101_0010,
        ];
        for i in 0 .. 2 {
            assert_eq!(expect[i], result[i]);
        }
    }

    #[test]
    fn test_pc1() {
        let result = pc1(0b00010011_00110100_01010111_01111001_10011011_10111100_11011111_11110001);
        assert_eq!(0b1111000_0110011_0010101_0101111_0101010_1011001_1001111_0001111 << 8, result);
    }

    #[test]
    fn test_pc2() {
        let result = pc2(0b1110000_1100110_0101010_1011111_1010101_0110011_0011110_0011110 << 8);
        assert_eq!(0b000110_110000_001011_101111_111111_000111_000001_110010 << 16, result);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let key = [0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1];

        let message = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let expected_cipher = vec![0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05];
        let cipher = encrypt(&message, &key);
        assert_eq!(cipher, expected_cipher);

        let cipher = expected_cipher;
        let expected_message = message;
        let message = decrypt(&cipher, &key);
        assert_eq!(message, expected_message);

        let message = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let expected_cipher = vec![0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05, 0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05];
        let cipher = encrypt(&message, &key);
        assert_eq!(cipher, expected_cipher);

        let cipher = expected_cipher;
        let expected_message = message;
        let message = decrypt(&cipher, &key);
        assert_eq!(message, expected_message);
    }
}
