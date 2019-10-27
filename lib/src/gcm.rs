use super::aes::Aes;
use bytes::BufMut;
use std::convert::TryInto;
use super::cipher_suite::{AeadResult};

const R: [u8; 16] = [0xe1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

fn shift_right(num: [u8;16]) -> [u8;16] {
    let mut result = [0u8;16];
    result[0] = num[0] >> 1;
    for i in 1..16 {
        result[i] = (num[i] >> 1) | ((num[i-1] & 1) << 7);
    }
    //println!("shift: {:x?} {:x?}", num, result);
    return result;
}

fn bit_set(num: [u8;16], bit: usize) -> bool {
    // The bits of a byte increase from left to right.
    let ret = (num[bit / 8] & (1 << ( 7 - bit % 8))) > 0;
    //println!("bitset: {:x?} {} {} {}", num, bit, (num[bit / 8] & (1 << ( 7 - bit % 8))), ret);
    ret
}

fn xor(a: [u8;16], b: [u8;16]) -> [u8;16] {
    let mut result = [0u8;16];
    for i in 0..16 {
        result[i] = a[i] ^ b[i];
    }
    return result;
}

fn multiply(x: [u8;16], y: [u8;16]) -> [u8;16] {
    let mut v = [0u8;16];
    v.copy_from_slice(&y);
    let mut z = [0u8;16];
    //println!("xmul: {:x?}", x);

    let result = vec![0u8;128];
    for i in 0..128 {
        if bit_set(x, i) {
            z = xor(z,v);
        }
        if bit_set(v, 127) {
            v = xor(shift_right(v), R);
            //println!("AAA {:x?}", v);
        } else {
            //println!("BBB {:x?}", v);
            v = shift_right(v);
        }
        //println!("{}: {:x?} {:x?}", i, z, v);
    }
    return z;
}

fn incr(number: [u8;16]) -> [u8;16] {
    let mut new_number = number;
    for i in (0..16).rev() {
        if new_number[i] == 255 {
            new_number[i] = 0;
        } else {
            new_number[i] += 1;
            return new_number;
        }
    }
    return new_number;
}

struct GHash {
    state: [u8;16],
    buffer: [u8;16],
    key: [u8;16],
    buffer_pos: usize,
    bytes_seen: u64,
}

impl GHash {
    fn new(key: [u8;16]) -> GHash {
        GHash {
            state: [0u8;16],
            buffer: [0u8;16],
            key: key,
            buffer_pos: 0,
            bytes_seen: 0,
        }
    }
    fn perform_round(&mut self) {
        self.state = multiply(xor(self.state, self.buffer), self.key);
        //println!("X: {:x?} {:x?}", self.state, self.buffer);

        self.buffer_pos = 0;
    }

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

    fn finalize(&self) -> [u8;16] {
        assert_eq!(0, self.buffer_pos);
        return self.state
    }
}


struct Gctr {
    aes: Aes,
    icb: [u8;16],
    cb: [u8;16],
    buffer: [u8;16],
    buffer_pos: usize,
    result: Vec<u8>,
}


impl Gctr {
    fn new(initial_counter: [u8;16], aes: Aes) -> Gctr {
        Gctr {
            aes: aes,
            icb: initial_counter,
            cb: initial_counter,
            buffer: [0u8;16],
            buffer_pos: 0,
            result: vec!(),
        }
    }

    fn perform_round(&mut self) {
        let mut counter_cipher = [0u8;16];
        self.aes.cipher(&self.cb, &mut counter_cipher);
        //println!("E: {:x?} {:x?}", counter_cipher, self.cb);
        let result = xor(counter_cipher, self.buffer);
        //fprintln!("C: {:x?}", result);
        self.result.extend(&result);
        self.cb = incr(self.cb);
        self.buffer_pos = 0;
    }

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
    }

    fn finalize(mut self) -> Vec<u8> {
        if self.buffer_pos != 0 {
            let mut counter_cipher = [0u8;16];
            self.aes.cipher(&self.cb, &mut counter_cipher);
            let result = xor(counter_cipher, self.buffer);
            self.result.extend(&result[0..self.buffer_pos]);
        }
        self.result
    }
}

fn gctr(initial_counter: [u8;16], aes: Aes, data: &[u8]) -> Vec<u8> {
    let mut gctr = Gctr::new(initial_counter, aes);
    gctr.update(data);
    gctr.finalize()
}

fn ghash(key: [u8;16], data: &[u8]) -> [u8;16] {
    let mut ghash = GHash::new(key);
    ghash.update(data);
    ghash.finalize()
}

fn gcm_decrypt(iv: &[u8], aes: Aes, authenticated_data: &[u8], ciphertext: &[u8], tag: &[u8]) -> Option<Vec<u8>> {
    assert_eq!(16, tag.len());
    assert_eq!(iv.len(), 12);
    let mut hash_subkey = [0u8;16];
    aes.cipher(&[0u8;16], &mut hash_subkey);
    let mut initial_counter = [0u8;16];
    initial_counter[0..12].copy_from_slice(iv);
    initial_counter[15] = 0x01;
    let tag: [u8;16] = tag.try_into().unwrap();
    let plaintext = gctr(incr(initial_counter), aes.clone(), ciphertext);
    let cipher_padding_len = 16*((ciphertext.len() + 15) / 16)-ciphertext.len();
    let authenticated_padding_len = 16*((authenticated_data.len() + 15) / 16)-authenticated_data.len();
    let mut s_data: Vec<u8> = Vec::with_capacity(
        ciphertext.len() + cipher_padding_len + authenticated_data.len() + authenticated_padding_len + 16
    );
    s_data.extend(authenticated_data);
    s_data.extend(vec![0u8;authenticated_padding_len]);
    s_data.extend(ciphertext);
    s_data.extend(vec![0u8;cipher_padding_len]);
    // Must multiply by 8 to get the bitlength
    s_data.put_u64_be(TryInto::<u64>::try_into(authenticated_data.len()).unwrap() * 8u64);
    s_data.put_u64_be(TryInto::<u64>::try_into(ciphertext.len()).unwrap() * 8u64);
    let s = ghash(hash_subkey, &s_data);
    //println!("GHASH: {:x?} {:x?}", s, s_data);
    let t = gctr(initial_counter, aes.clone(), &s);
    if t.as_slice() == tag {
        Some(plaintext)
    } else {
        None
    }
}

fn gcm(iv: &[u8], aes: Aes, authenticated_data: &[u8], plaintext: &[u8]) -> AeadResult {
    let mut hash_subkey = [0u8;16];
    aes.cipher(&[0u8;16], &mut hash_subkey);
    //println!("H: {:x?}", hash_subkey);
    assert_eq!(iv.len(), 12);
    let mut initial_counter = [0u8;16];
    initial_counter[0..12].copy_from_slice(iv);
    initial_counter[15] = 0x01;
    let ciphertext = gctr(incr(initial_counter), aes.clone(), plaintext);
    let cipher_padding_len = 16*((ciphertext.len() + 15) / 16)-ciphertext.len();
    let authenticated_padding_len = 16*((authenticated_data.len() + 15) / 16)-authenticated_data.len();
    let mut s_data: Vec<u8> = Vec::with_capacity(
        ciphertext.len() + cipher_padding_len + authenticated_data.len() + authenticated_padding_len + 16
    );
    //println!("Lengths: {} {} {} {}", ciphertext.len(), cipher_padding_len, authenticated_data.len(), authenticated_padding_len);
    s_data.extend(authenticated_data);
    s_data.extend(vec![0u8;authenticated_padding_len]);
    s_data.extend(&ciphertext);
    s_data.extend(vec![0u8;cipher_padding_len]);
    // Must multiply by 8 to get the bitlength
    s_data.put_u64_be(TryInto::<u64>::try_into(authenticated_data.len()).unwrap() * 8u64);
    s_data.put_u64_be(TryInto::<u64>::try_into(ciphertext.len()).unwrap() * 8u64);
    let s = ghash(hash_subkey, &s_data);
    //println!("GHASH: {:x?} {:x?}", s, s_data);
    let t = gctr(initial_counter, aes.clone(), &s);
    AeadResult {
        ciphertext: ciphertext,
        tag: t.as_slice().try_into().unwrap(),
    }
}

#[derive(Clone, Copy, Debug)]
pub enum GcmCipher {
    Aes128,
    Aes256,
}

impl GcmCipher {
    fn key_length(&self) -> usize {
        match self {
            GcmCipher::Aes128 => 16,
            GcmCipher::Aes256 => 32,
        }
    }

    fn iv_length(&self) -> usize {
        12
    }

    pub fn aead(&self, iv: &[u8], key: &[u8], authenticated_data: &[u8], plaintext: &[u8]) -> AeadResult {
        let aes = match self {
            GcmCipher::Aes128 => Aes::aes128(key),
            GcmCipher::Aes256 => Aes::aes256(key),
        };
        gcm(iv, aes, authenticated_data, plaintext)
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryInto;

    fn single_test(key_str: &str, iv_str: &str, additional_data_str: &str, plaintext_str: &str, expected_cipher_str: &str, expected_tag_str: &str) {
        let key: [u8;16] = hex::decode(key_str).unwrap().as_slice().try_into().unwrap();
        let iv: [u8;12] = hex::decode(iv_str).unwrap().as_slice().try_into().unwrap();
        let expected_cipher = hex::decode(expected_cipher_str).unwrap();
        let expected_tag: [u8;16] = hex::decode(expected_tag_str).unwrap().as_slice().try_into().unwrap();
        let additional_data = hex::decode(additional_data_str).unwrap();
        let plaintext = hex::decode(plaintext_str).unwrap();
        let aes = super::super::aes::Aes::aes128(&key);
        let result = super::gcm(&iv, aes.clone(), &additional_data, &plaintext);
        println!("Result: {:x?}", result);
        assert_eq!(expected_cipher, result.ciphertext);
        assert_eq!(expected_tag, result.tag);
        let decrypt_result = super::gcm_decrypt(&iv, aes.clone(), &additional_data, &result.ciphertext, &result.tag);
        assert_eq!(Some(plaintext.to_vec()), decrypt_result);
    }
    #[test]
    fn test_gcm_empty() {
        single_test(
            "00000000000000000000000000000000",
            "000000000000000000000000",
            "",
            "",
            "",
            "58e2fccefa7e3061367f1d57a4e7455a"
        );
    }

    #[test]
    fn test_gcm_simple() {
        single_test(
            "00000000000000000000000000000000",
            "000000000000000000000000",
            "",
            "00000000000000000000000000000000",
            "0388dace60b6a392f328c2b971b2fe78",
            "ab6e47d42cec13bdf53a67b21257bddf"
        );
    }

    #[test]
    fn test_gcm_complex() {
        single_test(
            "feffe9928665731c6d6a8f9467308308",
            "cafebabefacedbaddecaf888",
            "",
            concat!("d9313225f88406e5a55909c5aff5269a",
                    "86a7a9531534f7da2e4c303d8a318a72",
                    "1c3c0c95956809532fcf0e2449a6b525",
                    "b16aedf5aa0de657ba637b391aafd255"),
            concat!("42831ec2217774244b7221b784d0d49c",
                    "e3aa212f2c02a4e035c17e2329aca12e",
                    "21d514b25466931c7d8f6a5aac84aa05",
                    "1ba30b396a0aac973d58e091473f5985"),
            "4d5c2af327cd64a62cf35abd2ba6fab4"
        );
    }

    #[test]
    fn test_gcm_multiply() {
        let mut a = [0u8;16];
        a[0] = 0xc0;
        let mut b = [0u8;16];
        b[0] = 0x40;
        let mut c = [0u8;16];
        c[0] = 0x60;
        //println!("{:x?}", super::multiply(a,b));
        assert_eq!(c, super::multiply(a,b));
    }

    #[test]
    fn test_gcm_multiply2() {
        let mut a = [0u8;16];
        a[0] = 0xc0;
        let mut b = [0u8;16];
        b[0] = 0x03;
        let mut c = [0u8;16];
        c[0] = 0x02;
        c[1] = 0x80;
        //println!("{:x?}", super::multiply(a,b));
        assert_eq!(c, super::multiply(a,b));
    }

    #[test]
    fn test_gcm_multiply3() {
        let mut a = [0u8;16];
        a[0] = 0x40;
        let mut b = [0u8;16];
        b[15] = 0x01;
        let mut c = [0u8;16];
        c[0] = 0xe1;
        //c[15] = 0x01;
        //println!("{:x?}", super::multiply(a,b));
        assert_eq!(c, super::multiply(a,b));
    }
}