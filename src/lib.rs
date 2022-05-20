// #![no_std]

const fn ROL64(a: u64, n: u64) -> u64 {
    (a >> (64 - (n % 64))) + (a << (n % 64))
}

const LANE_DIAM: usize = 5;
type Lanes = [[u64; LANE_DIAM]; LANE_DIAM];
const fn keccak_f1600_on_lanes(lanes: Lanes) -> Lanes {
    let mut lanes = lanes;
    let mut R = 1u32;
    let mut round = 0;
    while round < 24 {
        // θ
        let mut x = 0;
        let mut C = [0u64; LANE_DIAM];
        while x < LANE_DIAM {
            C[x] = lanes[x][0] ^ lanes[x][1] ^ lanes[x][2] ^ lanes[x][3] ^ lanes[x][4];
            x += 1;
        }

        let mut x = 0;
        let mut D = [064; LANE_DIAM];
        while x < LANE_DIAM {
            let mut y = 0;
            while y < LANE_DIAM {
                D[x] = C[(x + 4) % LANE_DIAM] ^ ROL64(C[(x + 1) % LANE_DIAM], 1);
                y += 1;
            }
            x += 1;
        }

        let mut x = 0;
        while x < LANE_DIAM {
            let mut y = 0;
            while y < LANE_DIAM {
                lanes[x][y] ^= D[x];
                y += 1;
            }
            x += 1;
        }

        // ρ and π
        let mut x = 1;
        let mut y = 0;
        let mut current = lanes[x][y];
        let mut t = 0;
        while t < 24 {
            (x, y) = (y, (2 * x + 3 * y) % LANE_DIAM);
            (current, lanes[x][y]) = (lanes[x][y], ROL64(current, (t + 1) * (t + 2) / 2));
            t += 1;
        }

        // χ
        let mut y = 0;
        while y < LANE_DIAM {
            let mut T = [0; LANE_DIAM];
            let mut x = 0;
            while x < LANE_DIAM {
                T[x] = lanes[x][y];
                x += 1;
            }
            let mut x = 0;
            while x < LANE_DIAM {
                lanes[x][y] = T[x] ^ (!T[(x + 1) % 5] & T[(x + 2) % 5]);
                x += 1;
            }
            y += 1;
        }

        // ι
        let mut j = 0;
        while j < 7 {
            R = ((R << 1) ^ ((R >> 7) * 0x71)) % 256;
            if R & 2 != 0 {
                lanes[0][0] ^= 1 << ((1 << j) - 1);
            }
            j += 1;
        }

        round += 1;
    }

    lanes
}

const STATE_WIDTH: usize = 200;
type State = [u8; STATE_WIDTH];
const fn keccak_f1600(state: State) -> State {
    let mut lanes = [[0; LANE_DIAM]; LANE_DIAM];
    let mut buffer = [0; 8];
    let mut x = 0;
    while x < LANE_DIAM {
        let mut y = 0;
        while y < LANE_DIAM {
            let start = 8 * (x + LANE_DIAM * y);
            let mut z = 0;
            while z < buffer.len() {
                buffer[z] = state[start + z];
                z += 1;
            }
            lanes[x][y] = u64::from_le_bytes(buffer);
            y += 1;
        }
        x += 1;
    }
    let lanes = keccak_f1600_on_lanes(lanes);
    let mut state = [0; STATE_WIDTH];
    let mut x = 0;
    while x < LANE_DIAM {
        let mut y = 0;
        while y < LANE_DIAM {
            let buffer = lanes[x][y].to_le_bytes();
            let start = 8 * (x + LANE_DIAM * y);
            let mut z = 0;
            while z < buffer.len() {
                state[start + z] = buffer[z];
                z += 1;
            }
            y += 1;
        }
        x += 1;
    }
    state
}

const fn min(a: usize, b: usize) -> usize {
    [a, b][(a > b) as usize]
}

const fn keccak<
    const RATE: usize,
    const CAPACITY: usize,
    const INPUT_LEN: usize,
    const OUTPUT_LEN: usize,
>(
    input: [u8; INPUT_LEN],
    delimited_suffix: u8,
) -> [u8; OUTPUT_LEN] {
    if RATE + CAPACITY != 1600 {
        panic!();
    }

    if RATE % 8 != 0 {
        panic!("Rate needs to be a multiple of 8");
    }

    let mut output = [0; OUTPUT_LEN];
    let mut state = [0; STATE_WIDTH];
    let rate_in_bytes = RATE / 8;
    let mut block_size = 0;
    let mut input_offset = 0;
    // absorb all the input blocks
    while input_offset < INPUT_LEN {
        block_size = min(INPUT_LEN - input_offset, rate_in_bytes);
        let mut i = 0;
        while i < block_size {
            state[i] ^= input[i + input_offset];
            i += 1;
        }
        input_offset += block_size;
        if block_size == rate_in_bytes {
            state = keccak_f1600(state);
            block_size = 0;
        }
    }
    // do the padding and switch to the squeezing phase
    state[block_size] ^= delimited_suffix;
    if delimited_suffix & 0x80 != 0 && block_size == rate_in_bytes - 1 {
        state = keccak_f1600(state);
    }
    state[rate_in_bytes - 1] ^= 0x80;
    state = keccak_f1600(state);
    // squeeze out all the output blocks
    let mut output_offset = 0;
    while output_offset < OUTPUT_LEN {
        block_size = min(OUTPUT_LEN - output_offset, rate_in_bytes);
        let mut j = 0;
        while j < block_size {
            output[j] += state[j];
            j += 1;
        }
        output_offset += block_size;
        if output_offset < OUTPUT_LEN {
            state = keccak_f1600(state);
        }
    }
    output
}

pub const fn SHAKE128<const INPUT_LEN: usize, const OUTPUT_LEN: usize>(
    input: [u8; INPUT_LEN],
) -> [u8; OUTPUT_LEN] {
    keccak::<1344, 256, INPUT_LEN, OUTPUT_LEN>(input, 0x1F)
}

pub const fn SHAKE256<const INPUT_LEN: usize, const OUTPUT_LEN: usize>(
    input: [u8; INPUT_LEN],
) -> [u8; OUTPUT_LEN] {
    keccak::<1088, 512, INPUT_LEN, OUTPUT_LEN>(input, 0x1F)
}

pub const fn SHA3_224<const INPUT_LEN: usize>(input: [u8; INPUT_LEN]) -> [u8; 28] {
    keccak::<1152, 448, INPUT_LEN, 28>(input, 0x06)
}

pub const fn SHA3_256<const INPUT_LEN: usize>(input: [u8; INPUT_LEN]) -> [u8; 32] {
    keccak::<1088, 512, INPUT_LEN, 32>(input, 0x06)
}

pub const fn SHA3_384<const INPUT_LEN: usize>(input: [u8; INPUT_LEN]) -> [u8; 48] {
    keccak::<832, 768, INPUT_LEN, 48>(input, 0x06)
}

pub const fn SHA3_512<const INPUT_LEN: usize>(input: [u8; INPUT_LEN]) -> [u8; 64] {
    keccak::<576, 1024, INPUT_LEN, 64>(input, 0x06)
}

#[cfg(test)]
mod tests {
    use super::SHAKE256;

    #[test]
    fn it_works() {
        let result = [192, 33, 251, 3, 222, 123, 6, 0, 132, 72];
        let input = b"Rescue-XLIX";
        let output: [u8; 10] = SHAKE256(*input);
        assert_eq!(result, output);
    }
}
