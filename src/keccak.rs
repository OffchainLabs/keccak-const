const LANE_DIAM: usize = 5;

type Lanes = [[u64; LANE_DIAM]; LANE_DIAM];

const STATE_WIDTH: usize = 200;

type State = [u8; STATE_WIDTH];

/// Extendable-output function reader
#[derive(Clone)]
pub struct XofReader {
    state: State,
    pos: usize,
    rate_in_bytes: usize,
}

impl XofReader {
    /// Reads output to a buffer
    pub const fn read<const N: usize>(&mut self) -> [u8; N] {
        let mut buf = [0; N];
        let _ = self.read_into(&mut buf);
        buf
    }
    /// Reads output to a buffer
    pub const fn read_into<const N: usize>(&mut self, output: &mut [u8; N]) -> &mut Self {
        let mut i = 0;
        while i < N {
            output[i] = self.state[self.pos];
            i += 1;
            self.pos += 1;
            if self.pos == self.rate_in_bytes {
                self.state = keccak_f1600(self.state);
                self.pos = 0;
            }
        }
        self
    }
    /// Reads output to a buffer
    pub const fn read_into_slice<const N: usize>(&mut self, output: &mut [u8]) -> &mut Self {
        let mut i = 0;
        while i < N {
            output[i] = self.state[self.pos];
            i += 1;
            self.pos += 1;
            if self.pos == self.rate_in_bytes {
                self.state = keccak_f1600(self.state);
                self.pos = 0;
            }
        }
        self
    }
}

#[derive(Clone)]
pub struct KeccakState {
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
    pub const fn new_custom(
        security_bits: usize,
        name: &[u8],
        custom_string: &[u8],
    ) -> KeccakState {
        if name.is_empty() && custom_string.is_empty() {
            // regular shake if both inputs are empty
            return KeccakState::new(security_bits, 0x1f);
        }
        let mut state = KeccakState::new(security_bits, 0x04);
        let rate = state.rate_in_bytes as u64;
        state = state.update_left_encoded(rate);
        state = state.update_left_encoded((name.len() * 8) as u64);
        state = state.update(name);
        state = state.update_left_encoded((custom_string.len() * 8) as u64);
        state = state.update(custom_string);
        state.fill_block()
    }

    /// Absorbs additional input
    ///
    /// Can be called multiple times
    pub const fn update(mut self, input: &[u8]) -> Self {
        let mut i = 0;
        while i < input.len() {
            self = self.update_byte(input[i]);
            i += 1;
        }
        self
    }

    #[inline(always)]
    const fn update_byte(mut self, b: u8) -> Self {
        self.state[self.pos] ^= b;
        self.pos += 1;
        if self.pos == self.rate_in_bytes {
            self.state = keccak_f1600(self.state);
            self.pos = 0;
        }
        self
    }

    const fn update_left_encoded(mut self, value: u64) -> Self {
        // the input is the value as big endian without leading zeros,
        // preceded by the count of those bytes.
        let input = value.to_be_bytes();
        // count leading zeros
        let mut n = 0;
        while n < 8 && input[n] == 0 {
            n += 1;
        }
        n = if n == 8 { 1 } else { 8 - n };
        self = self.update_byte(n as u8);
        n = 8 - n;
        while n < 8 {
            self = self.update_byte(input[n]);
            n += 1;
        }
        self
    }

    const fn fill_block(mut self) -> Self {
        if self.pos != 0 {
            self.state = keccak_f1600(self.state);
            self.pos = 0;
        }
        self
    }

    /// Pad and squeeze the state to the output
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
        if delimiter & 0x80 != 0 && pos == rate_in_bytes - 1 {
            state = keccak_f1600(state);
        }
        state[rate_in_bytes - 1] ^= 0x80;
        state = keccak_f1600(state);
        XofReader {
            state,
            rate_in_bytes,
            pos: 0,
        }
    }
}

const fn keccak_f1600(mut state: State) -> State {
    let mut lanes = [[0; LANE_DIAM]; LANE_DIAM];
    let mut x = 0;
    while x < LANE_DIAM {
        let mut y = 0;
        while y < LANE_DIAM {
            let start = 8 * (x + LANE_DIAM * y);
            let mut buf = [0; 8];
            let mut z = 0;
            while z < buf.len() {
                buf[z] = state[start + z];
                z += 1;
            }
            lanes[x][y] = u64::from_le_bytes(buf);
            y += 1;
        }
        x += 1;
    }
    lanes = keccak_f1600_on_lanes(lanes);
    state = [0; STATE_WIDTH];
    let mut x = 0;
    while x < LANE_DIAM {
        let mut y = 0;
        while y < LANE_DIAM {
            let buf = lanes[x][y].to_le_bytes();
            let start = 8 * (x + LANE_DIAM * y);
            let mut z = 0;
            while z < buf.len() {
                state[start + z] = buf[z];
                z += 1;
            }
            y += 1;
        }
        x += 1;
    }
    state
}

const fn keccak_f1600_on_lanes(mut lanes: Lanes) -> Lanes {
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
    lanes
}
