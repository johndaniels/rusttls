use bytes::{ByteOrder, BigEndian};
use super::{Digest, DigestAlgorithmConfig};

const K: [u64;80] = [
   0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
   0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
   0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
   0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
   0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
   0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
   0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
   0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
   0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
   0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
   0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
   0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
   0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
   0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
   0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
   0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
   0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
   0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
   0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
   0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

#[derive(Clone)]
struct Sha384 {
    state: [u64;8],
    buffer: [u8;128],
    buffer_pos: usize,
    bytes_seen: u128,
}

impl Sha384 {
    fn new() -> Sha384 {
        Sha384 {
            state: [
                0xcbbb9d5dc1059ed8,
                0x629a292a367cd507,
                0x9159015a3070dd17,
                0x152fecd8f70e5939,
                0x67332667ffc00b31,
                0x8eb44a8768581511,
                0xdb0c2e0d64f98fa7,
                0x47b5481dbefa4fa4,
            ],
            buffer: [0;128],
            buffer_pos: 0,
            bytes_seen: 0,
        }
    }

    fn ch(x: u64, y: u64, z: u64) -> u64 {
        (x & y) ^ ((!x) & z)
    }

    fn maj(x: u64, y: u64, z: u64) -> u64 {
        (x & y) ^ (x & z) ^ (y & z)
    }

    fn bsig0(x: u64) -> u64 {
        x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
    }

    fn bsig1(x: u64) -> u64 {
        x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41)
    }

    fn ssig0(x: u64) -> u64 {
        x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7)
    }

    fn ssig1(x: u64) -> u64 {
        x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6)
    }

    fn perform_round(&mut self) {

        assert_eq!(self.buffer_pos, self.buffer.len());
        let mut message_schedule: [u64;80] = [0;80];
        for t in 0..16 {
            message_schedule[t] = BigEndian::read_u64(&self.buffer[t*8..(t+1)*8]);
        }
        for t in 16..80 {
            message_schedule[t] = Sha384::ssig1(message_schedule[t-2])
                .wrapping_add(message_schedule[t-7])
                .wrapping_add(Sha384::ssig0(message_schedule[t-15]))
                .wrapping_add(message_schedule[t-16]);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for t in 0..80 {
            let t1 = h.wrapping_add(Sha384::bsig1(e))
                      .wrapping_add(Sha384::ch(e, f, g))
                      .wrapping_add(K[t])
                      .wrapping_add(message_schedule[t]);
            let t2 = Sha384::bsig0(a)
                        .wrapping_add(Sha384::maj(a,b,c));
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
pub struct Sha384AlgorithmConfig {

}

impl DigestAlgorithmConfig for Sha384AlgorithmConfig {
    fn block_size(&self) -> usize { 128 }
    fn result_size(&self) -> usize { 48 }
    fn create(&self) -> Box<dyn Digest> {
        Box::new(Sha384::new())
    }
}

impl Digest for Sha384 {
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
        self.bytes_seen = self.bytes_seen + (update_buf.len() as u128);
    }

    fn finalize(&mut self) -> Vec<u8> {
        let bit_length = 8 * self.bytes_seen;
        self.update(&[1<<7]);
        let zero_count = if self.buffer_pos > 112 {
            112 + (128 - self.buffer_pos)
        } else {
            112 - self.buffer_pos
        };
        self.update(&vec![0;zero_count]);
        let mut size_buf: [u8;16] = [0;16];
        BigEndian::write_u128(&mut size_buf, bit_length);
        self.update(&size_buf);
        assert_eq!(self.buffer_pos, 0);
        let mut result: [u8;48] = [0;48];
        for t in 0..6 {
            BigEndian::write_u64(&mut result[8*t..8*(t+1)], self.state[t]);
        }
        result.to_vec()
    }

    fn finalize_copy(&self) -> Vec<u8> {
        self.clone().finalize()
    }
}


#[cfg(test)]
mod tests {
    use super::{Digest, Sha384};

    #[test]
    fn test_digest() {
        let message = b"abc";
        let expected_hex_digest = "CB00753F45A35E8BB5A03D699AC65007272C32AB0EDED1631A8B605A43FF5BED8086072BA1E7CC2358BAECA134C825A7";
        let mut sha = Sha384::new();
        sha.update(message);
        let data = sha.finalize();
        println!("data {:x?}", data);

        let actual_hex_digest = hex::encode_upper(data);
        assert_eq!(expected_hex_digest, actual_hex_digest);
    }

    #[test]
    fn test_long_digest() {
        let message = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        let expected_hex_digest = "09330C33F71147E83D192FC782CD1B4753111B173B3B05D22FA08086E3B0F712FCC7C71A557E2DB966C3E9FA91746039";
        let mut sha = Sha384::new();
        sha.update(message);
        let data = sha.finalize();
        println!("data {:x?}", data);

        let actual_hex_digest = hex::encode_upper(data);
        assert_eq!(expected_hex_digest, actual_hex_digest);
    }

    #[test]
    fn test_longest_digest() {
        let message = b"a";
        let expected_hex_digest = "9D0E1809716474CB086E834E310A4A1CED149E9C00F248527972CEC5704C2A5B07B8B3DC38ECC4EBAE97DDD87F3D8985";
        let mut sha = Sha384::new();
        for _ in 0..1000000 {
            sha.update(message);
        }
        let data = sha.finalize();
        println!("data {:x?}", data);

        let actual_hex_digest = hex::encode_upper(data);
        assert_eq!(expected_hex_digest, actual_hex_digest);
    }
}
