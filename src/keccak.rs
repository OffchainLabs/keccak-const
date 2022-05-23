const LANE_DIAM: usize = 5;

type Lanes = [[u64; LANE_DIAM]; LANE_DIAM];

const STATE_WIDTH: usize = 200;

type State = [u8; STATE_WIDTH];

pub struct XofReader {
    state: State,
    pos: usize,
    rate_in_bytes: usize,
}

impl XofReader {
    pub const fn read(&mut self, buffer: &mut [u8]) {
        let mut i = 0;
        while i < buffer.len() {
            buffer[i] += self.state[self.pos];
            i += 1;
            self.pos += 1;
            if self.pos == self.rate_in_bytes {
                keccak_f1600(&mut self.state);
                self.pos = 0;
            }
        }
    }
}

pub struct KeccakState {
    /// rate in bytes
    rate_in_bytes: usize,
    state: State,
    pos: usize,
    delimiter: u8,
}

impl KeccakState {
    pub const fn new(security_bits: usize, delimiter: u8) -> KeccakState {
        KeccakState {
            rate_in_bytes: STATE_WIDTH - security_bits / 4,
            delimiter,
            state: [0u8; STATE_WIDTH],
            pos: 0,
        }
    }

    /// Absorb additional input. Can be called multiple times.
    pub const fn update(&mut self, input: &[u8]) {
        let mut i = 0;
        while i < input.len() {
            self.state[self.pos] ^= input[i];
            self.pos += 1;
            i += 1;
            if self.pos == self.rate_in_bytes {
                keccak_f1600(&mut self.state);
                self.pos = 0;
            }
        }
    }

    /// Pad and squeeze the state to the output.
    pub const fn finalize(&self) -> XofReader {
        let Self {
            mut state,
            delimiter,
            pos,
            rate_in_bytes,
            ..
        } = *self;
        // pad and switch to the squeezing phase
        state[pos] ^= delimiter;
        if delimiter & 0x80 != 0 && pos % rate_in_bytes == rate_in_bytes - 1 {
            keccak_f1600(&mut state);
        }
        state[rate_in_bytes - 1] ^= 0x80;
        keccak_f1600(&mut state);
        XofReader {
            state,
            rate_in_bytes,
            pos: 0,
        }
    }
}

const fn keccak_f1600(state: &mut State) {
    let mut lanes = [[0; LANE_DIAM]; LANE_DIAM];
    let mut x = 0;
    while x < LANE_DIAM {
        let mut y = 0;
        while y < LANE_DIAM {
            let start = 8 * (x + LANE_DIAM * y);
            let mut buffer = [0; 8];
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
    keccak_f1600_on_lanes(&mut lanes);
    *state = [0; STATE_WIDTH];
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
}

const fn keccak_f1600_on_lanes(lanes: &mut Lanes) {
    let mut r = 1u32; // R
    let mut round = 0;
    while round < 24 {
        // θ
        let mut x = 0;
        let mut c = [0u64; LANE_DIAM]; // C
        while x < LANE_DIAM {
            c[x] = lanes[x][0] ^ lanes[x][1] ^ lanes[x][2] ^ lanes[x][3] ^ lanes[x][4];
            x += 1;
        }
        let mut x = 0;
        let mut d = [0u64; LANE_DIAM]; // D
        while x < LANE_DIAM {
            let mut y = 0;
            while y < LANE_DIAM {
                d[x] = c[(x + 4) % LANE_DIAM] ^ c[(x + 1) % LANE_DIAM].rotate_left(1);
                y += 1;
            }
            x += 1;
        }
        let mut x = 0;
        while x < LANE_DIAM {
            let mut y = 0;
            while y < LANE_DIAM {
                lanes[x][y] ^= d[x];
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
            (current, lanes[x][y]) = (lanes[x][y], current.rotate_left((t + 1) * (t + 2) / 2));
            t += 1;
        }
        // χ
        let mut y = 0;
        while y < LANE_DIAM {
            let mut t = [0; LANE_DIAM]; // T
            let mut x = 0;
            while x < LANE_DIAM {
                t[x] = lanes[x][y];
                x += 1;
            }
            let mut x = 0;
            while x < LANE_DIAM {
                lanes[x][y] = t[x] ^ (!t[(x + 1) % 5] & t[(x + 2) % 5]);
                x += 1;
            }
            y += 1;
        }
        // ι
        let mut j = 0;
        while j < 7 {
            r = ((r << 1) ^ ((r >> 7) * 0x71)) % 256;
            if r & 2 != 0 {
                lanes[0][0] ^= 1 << ((1 << j) - 1);
            }
            j += 1;
        }
        round += 1;
    }
}
