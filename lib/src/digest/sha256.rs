use bytes::{ByteOrder, BigEndian};
use super::{Digest, DigestAlgorithmConfig};

const K: [u32;64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];
#[derive(Clone)]
struct Sha256 {
    state: [u32;8],
    buffer: [u8;64],
    buffer_pos: usize,
    bytes_seen: u64,
}

impl Sha256 {
    fn new() -> Sha256 {
        Sha256 {
            state: [
                0x6a09e667,
                0xbb67ae85,
                0x3c6ef372,
                0xa54ff53a,
                0x510e527f,
                0x9b05688c,
                0x1f83d9ab,
                0x5be0cd19,
            ],
            buffer: [0;64],
            buffer_pos: 0,
            bytes_seen: 0,
        }
    }

    fn ch(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ ((!x) & z)
    }

    fn maj(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (x & z) ^ (y & z)
    }

    fn bsig0(x: u32) -> u32 {
        x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
    }

    fn bsig1(x: u32) -> u32 {
        x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
    }

    fn ssig0(x: u32) -> u32 {
        x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
    }

    fn ssig1(x: u32) -> u32 {
        x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
    }

    fn perform_round(&mut self) {

        assert_eq!(self.buffer_pos, self.buffer.len());
        let mut message_schedule: [u32;64] = [0;64]; // message_schedule is W in the RFC
        for t in 0..16 {
            message_schedule[t] = BigEndian::read_u32(&self.buffer[t*4..(t+1)*4]);
        }
        for t in 16..64 {
            message_schedule[t] = Sha256::ssig1(message_schedule[t-2])
                .wrapping_add(message_schedule[t-7])
                .wrapping_add(Sha256::ssig0(message_schedule[t-15]))
                .wrapping_add(message_schedule[t-16]);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for t in 0..64 {
            let t1 = h.wrapping_add(Sha256::bsig1(e))
                      .wrapping_add(Sha256::ch(e, f, g))
                      .wrapping_add(K[t])
                      .wrapping_add(message_schedule[t]);
            let t2 = Sha256::bsig0(a)
                        .wrapping_add(Sha256::maj(a,b,c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        self.state[0] = a.wrapping_add(self.state[0]);
        self.state[1] = b.wrapping_add(self.state[1]);
        self.state[2] = c.wrapping_add(self.state[2]);
        self.state[3] = d.wrapping_add(self.state[3]);
        self.state[4] = e.wrapping_add(self.state[4]);
        self.state[5] = f.wrapping_add(self.state[5]);
        self.state[6] = g.wrapping_add(self.state[6]);
        self.state[7] = h.wrapping_add(self.state[7]);
        self.buffer_pos = 0;
    } 
}

#[derive(Clone)]
pub struct Sha256AlgorithmConfig {
}


impl DigestAlgorithmConfig for Sha256AlgorithmConfig {
    fn block_size(&self) -> usize { 64 }
    fn result_size(&self) -> usize { 32 }
    fn create(&self) -> Box<dyn Digest> {
        Box::new(Sha256::new())
    }
}

impl Digest for Sha256 {
    fn update(&mut self, update_buf: &[u8]) {
        let mut update_buf_pos: usize = 0;
        while update_buf.len() - update_buf_pos >= self.buffer.len() - self.buffer_pos {
            let length_to_copy = self.buffer.len() - self.buffer_pos;
            self.buffer[self.buffer_pos..].copy_from_slice(&update_buf[update_buf_pos..(update_buf_pos + length_to_copy)]);
            self.buffer_pos += length_to_copy;
            self.perform_round();
            update_buf_pos += length_to_copy;
        }
        let end_buffer_pos = self.buffer_pos + (update_buf.len() - update_buf_pos);
        self.buffer[self.buffer_pos..end_buffer_pos]
            .copy_from_slice(&update_buf[update_buf_pos..]);
        self.buffer_pos = end_buffer_pos;
        self.bytes_seen = self.bytes_seen + (update_buf.len() as u64);
    }

    fn finalize(&mut self) -> Vec<u8> {
        let bit_length = 8 * self.bytes_seen;
        self.update(&[1<<7]);
        // Make sure our byte count is congruent to 56 mod 64
        let zero_count = if self.buffer_pos > 56 {
            56 + (64 - self.buffer_pos)
        } else {
            56 - self.buffer_pos
        };
        self.update(&vec![0;zero_count]);
        let mut size_buf: [u8;8] = [0;8];
        BigEndian::write_u64(&mut size_buf, bit_length);
        self.update(&size_buf);
        assert_eq!(self.buffer_pos, 0);
        let mut result: [u8;32] = [0;32];
        for t in 0..8 {
            BigEndian::write_u32(&mut result[4*t..4*(t+1)], self.state[t]);
        }
        result.to_vec()
    }

    fn finalize_copy(&self) -> Vec<u8> {
        self.clone().finalize()
    }
}


#[cfg(test)]
mod tests {
    use super::{Digest, Sha256};

    #[test]
    fn test_digest() {
        let message = b"abc";
        let expected_hex_digest = "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD";
        let mut sha = Sha256::new();
        sha.update(message);
        let data = sha.finalize();
        println!("data {:x?}", data);

        let actual_hex_digest = hex::encode_upper(data);
        assert_eq!(expected_hex_digest, actual_hex_digest);
    }

    #[test]
    fn test_long_digest() {
        let message = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let expected_hex_digest = "248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1";
        let mut sha = Sha256::new();
        sha.update(message);
        let data = sha.finalize();
        println!("data {:x?}", data);

        let actual_hex_digest = hex::encode_upper(data);
        assert_eq!(expected_hex_digest, actual_hex_digest);
    }

    #[test]
    fn test_longest_digest() {
        let message = b"a";
        let expected_hex_digest = "CDC76E5C9914FB9281A1C7E284D73E67F1809A48A497200E046D39CCC7112CD0";
        let mut sha = Sha256::new();
        for _ in 0..1000000 {
            sha.update(message);
        }
        let data = sha.finalize();
        println!("data {:x?}", data);

        let actual_hex_digest = hex::encode_upper(data);
        assert_eq!(expected_hex_digest, actual_hex_digest);
    }
}
