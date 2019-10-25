use std::convert::TryInto;

static SBOX: [u8;256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

static INV_SBOX: [u8;256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, 
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, 
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d, 
];

static RCON: [u8;11] = [
    0x00, //unused
    0x01,
    0x02,
    0x04,
    0x08,
    0x10,
    0x20,
    0x40,
    0x80,
    0x1b,
    0x36,
];

struct Aes {
    key_schedule: Vec<u8>,
    rounds: usize,
}

impl Aes {
    pub fn aes128(key: &[u8]) -> Aes {
        assert_eq!(key.len(), 16);
        Aes {
            key_schedule: expand_key(key, 4 * (10 +1), 4),
            rounds: 10,
        }
    }

    pub fn aes196(key: &[u8]) -> Aes {
        assert_eq!(key.len(), 24);
        Aes {
            key_schedule: expand_key(key, 4 * (12 +1), 6),
            rounds: 12,
        }
    }

     pub fn aes256(key: &[u8]) -> Aes {
        assert_eq!(key.len(), 32);
        Aes {
            key_schedule: expand_key(key, 4 * (14 +1), 8),
            rounds: 14,
        }
    }

    fn add_round_key(&self, state: &mut [u8;16], offset: usize) {
        for i in 0..16 {
            state[i] ^= self.key_schedule[offset + i];
        }
    }

    pub fn cipher(&self, input: &[u8], output: &mut [u8]) {
        assert_eq!(input.len(), 16);
        assert_eq!(output.len(), 16);
        let mut state: [u8;16] = input.try_into().unwrap();

        self.add_round_key(&mut state, 0);
        for round in 1..self.rounds {
            sub_bytes(&mut state);
            shift_rows(&mut state);
            mix_columns(&mut state);
            self.add_round_key(&mut state, round * 16);
        }
        sub_bytes(&mut state);
        shift_rows(&mut state);
        self.add_round_key(&mut state, self.rounds * 16);

        output.copy_from_slice(&state);
    }

    pub fn inv_cipher(&self, input: &[u8], output: &mut [u8]) {
        assert_eq!(input.len(), 16);
        assert_eq!(output.len(), 16);
        let mut state: [u8;16] = input.try_into().unwrap();

        self.add_round_key(&mut state, self.rounds * 16);
        for round in (1..self.rounds).rev() {
            inv_shift_rows(&mut state);
            inv_sub_bytes(&mut state);
            self.add_round_key(&mut state, round * 16);
            inv_mix_columns(&mut state);
        }
        inv_shift_rows(&mut state);
        inv_sub_bytes(&mut state);
        self.add_round_key(&mut state, 0);

        output.copy_from_slice(&state);
    }
}


fn inv_sub_bytes(state: &mut [u8;16]) {
    for i in 0..16 {
        state[i] = INV_SBOX[TryInto::<usize>::try_into(state[i]).unwrap()];
    }
}

fn sub_bytes(state: &mut [u8;16]) {
    for i in 0..16 {
        state[i] = SBOX[TryInto::<usize>::try_into(state[i]).unwrap()];
    }
}

fn inv_shift_rows(state: &mut [u8;16]) {
    let temp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = temp;
    let temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    let temp = state[6];
    state[6] = state[14];
    state[14] = temp;
    let temp = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = state[3];
    state[3] = temp;
}

fn shift_rows(state: &mut [u8;16]) {
    let temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;
    let temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    let temp = state[6];
    state[6] = state[14];
    state[14] = temp;
    let temp = state[3];
    state[3] = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = temp;
}

fn inv_mix_column(state: &mut [u8]) {
    let mut new_state = [0;4]; 
    new_state[0] = mul(state[0], 0x0e) ^ mul(state[1], 0x0b) ^ mul(state[2], 0x0d) ^ mul(state[3], 0x09);
    new_state[1] = mul(state[0], 0x09) ^ mul(state[1], 0x0e) ^ mul(state[2], 0x0b) ^ mul(state[3], 0x0d);
    new_state[2] = mul(state[0], 0x0d) ^ mul(state[1], 0x09) ^ mul(state[2], 0x0e) ^ mul(state[3], 0x0b);
    new_state[3] = mul(state[0], 0x0b) ^ mul(state[1], 0x0d) ^ mul(state[2], 0x09) ^ mul(state[3], 0x0e);
    state.copy_from_slice(&new_state);
}

fn inv_mix_columns(state: &mut [u8;16]) {
    inv_mix_column(&mut state[0..4]);
    inv_mix_column(&mut state[4..8]);
    inv_mix_column(&mut state[8..12]);
    inv_mix_column(&mut state[12..16]);
}

fn mix_column(state: &mut [u8]) {
    let mut new_state = [0;4]; 
    new_state[0] = mul(state[0], 2) ^ mul(state[1], 3) ^ state[2] ^ state[3];
    new_state[1] = state[0] ^ mul(state[1], 2) ^ mul(state[2], 3) ^ state[3];
    new_state[2] = state[0] ^ state[1] ^ mul(state[2], 2) ^ mul(state[3], 3);
    new_state[3] = mul(state[0], 3) ^ state[1] ^ state[2] ^ mul(state[3], 2);
    state.copy_from_slice(&new_state);
}

fn mix_columns(state: &mut [u8;16]) {
        mix_column(&mut state[0..4]);
        mix_column(&mut state[4..8]);
        mix_column(&mut state[8..12]);
        mix_column(&mut state[12..16]);
}

fn mul(num: u8, mut multiplier: u8) -> u8{
    let mut result = 0;
    let mut current = num;
    while multiplier != 0 {
        if (multiplier & 1) != 0 {
            result ^= current;
        }
        current = xtime(current);
        multiplier >>= 1;
    }
    return result;
}

fn xtime(num: u8) -> u8 {
    let mut result = num << 1;
    if (num & 0x80) != 0 {
        result = result ^ 0x1b;
    }
    return result;
}


fn sub_word(word: &mut [u8;4]) {
    word[0] = SBOX[TryInto::<usize>::try_into(word[0]).unwrap()];
    word[1] = SBOX[TryInto::<usize>::try_into(word[1]).unwrap()];
    word[2] = SBOX[TryInto::<usize>::try_into(word[2]).unwrap()];
    word[3] = SBOX[TryInto::<usize>::try_into(word[3]).unwrap()];

}

fn rot_word(word: &mut [u8;4]) {
    let temp = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = temp;
}

fn expand_key(key: &[u8], expanded_size: usize, key_words: usize) -> Vec<u8> {
    let mut expanded_key: Vec<u8> = vec![0;expanded_size*4];
    expanded_key[0..key.len()].copy_from_slice(&key);
    for i in key_words..expanded_size {
        let mut temp: [u8;4] = expanded_key[i*4-4..i*4].try_into().unwrap();
        if i % key_words == 0 {
            rot_word(&mut temp);
            sub_word(&mut temp);
            temp[0] ^= RCON[i/key_words];
        } else if key_words > 6 && i % key_words == 4 {
            sub_word(&mut temp);
        }
        expanded_key[i*4] = expanded_key[(i-key_words)*4] ^ temp[0];
        expanded_key[i*4 + 1] = expanded_key[(i-key_words)*4 + 1] ^ temp[1];
        expanded_key[i*4 + 2] = expanded_key[(i-key_words)*4 + 2] ^ temp[2];
        expanded_key[i*4 + 3] = expanded_key[(i-key_words)*4 + 3] ^ temp[3];
    }
    expanded_key
}

fn encrypt(data: &[u8], output: &mut [u8], key_schedule: &[u8]) {
    assert_eq!(data.len(), 16);
    assert_eq!(output.len(), 16);
    let state: [u8;16] = data.try_into().unwrap();
}

#[cfg(test)]
mod tests {

    #[test]
    fn cipher_test_128() {
        let input = hex::decode("00112233445566778899aabbccddeeff").unwrap();
        let key = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let aes = super::Aes::aes128(&key);
        let mut output = [0u8;16];
        aes.cipher(&input, &mut output);
        let expected_output = hex::decode("69c4e0d86a7b0430d8cdb78070b4c55a").unwrap();
        assert_eq!(expected_output, output);
        let mut inv_output = [0u8;16];
        aes.inv_cipher(&output, &mut inv_output);
        assert_eq!(input, inv_output);
    }

    #[test]
    fn cipher_test_196() {
        let input = hex::decode("00112233445566778899aabbccddeeff").unwrap();
        let key = hex::decode("000102030405060708090a0b0c0d0e0f1011121314151617").unwrap();
        let aes = super::Aes::aes196(&key);
        let mut output = [0u8;16];
        aes.cipher(&input, &mut output);
        let expected_output = hex::decode("dda97ca4864cdfe06eaf70a0ec0d7191").unwrap();
        assert_eq!(expected_output, output);
        let mut inv_output = [0u8;16];
        aes.inv_cipher(&output, &mut inv_output);
        assert_eq!(input, inv_output);
    }

    #[test]
    fn cipher_test_256() {
        let input = hex::decode("00112233445566778899aabbccddeeff").unwrap();
        let key = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
        let aes = super::Aes::aes256(&key);
        let mut output = [0u8;16];
        aes.cipher(&input, &mut output);
        let expected_output = hex::decode("8ea2b7ca516745bfeafc49904b496089").unwrap();
        assert_eq!(expected_output, output);
        let mut inv_output = [0u8;16];
        aes.inv_cipher(&output, &mut inv_output);
        assert_eq!(input, inv_output);
    }

    #[test]
    fn test_xtime() {
        assert_eq!(0xae, super::xtime(0x57));
        assert_eq!(0x47, super::xtime(0xae));
        assert_eq!(0x8e, super::xtime(0x47));
        assert_eq!(0x07, super::xtime(0x8e));
    }

    #[test]
    fn test_mul() {
        assert_eq!(0xfe, super::mul(0x57, 0x13))
    }

    #[test]
    fn test_expand_keys() {
        let key_128 = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let result_key_128 = super::expand_key(&key_128, 4 * (10 + 1), 4);
        let expected_128 = hex::decode(concat!(
            "2b7e151628aed2a6abf7158809cf4f3ca0fafe1788542cb123a339392a6c7605",
            "f2c295f27a96b9435935807a7359f67f3d80477d4716fe3e1e237e446d7a883b",
            "ef44a541a8525b7fb671253bdb0bad00d4d1c6f87c839d87caf2b8bc11f915bc",
            "6d88a37a110b3efddbf98641ca0093fd4e54f70e5f5fc9f384a64fb24ea6dc4f",
            "ead27321b58dbad2312bf5607f8d292fac7766f319fadc2128d12941575c006e",
            "d014f9a8c9ee2589e13f0cc8b6630ca6")).unwrap();

        assert_eq!(expected_128, result_key_128);

        let key_196 = hex::decode("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b").unwrap();
        let expected_196 = hex::decode(concat!(
            "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7bfe0c91f72402f5a5ec12068e6c827f6b0e7a95b95c56fec2",
            "4db7b4bd69b5411885a74796e92538fde75fad44bb095386485af05721efb14fa448f6d94d6dce24aa326360113b30e6",
            "a25e7ed583b1cf9a27f939436a94f767c0a69407d19da4e1ec1786eb6fa64971485f703222cb8755e26d135233f0b7b3",
            "40beeb282f18a2596747d26b458c553ea7e1466c9411f1df821f750aad07d753ca4005388fcc5006282d166abc3ce7b5",
            "e98ba06f448c773c8ecc720401002202"
        )).unwrap();
        let result_key_196 = super::expand_key(&key_196, 4 * (12 + 1), 6);
        assert_eq!(expected_196, result_key_196);

        let key_256 = hex::decode("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4").unwrap();
        let expected_256 = hex::decode(concat!(
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
            "9ba354118e6925afa51a8b5f2067fcdea8b09c1a93d194cdbe49846eb75d5b9a",
            "d59aecb85bf3c917fee94248de8ebe96b5a9328a2678a647983122292f6c79b3",
            "812c81addadf48ba24360af2fab8b46498c5bfc9bebd198e268c3ba709e04214",
            "68007bacb2df331696e939e46c518d80c814e20476a9fb8a5025c02d59c58239",
            "de1369676ccc5a71fa2563959674ee155886ca5d2e2f31d77e0af1fa27cf73c3",
            "749c47ab18501ddae2757e4f7401905acafaaae3e4d59b349adf6acebd10190d",
            "fe4890d1e6188d0b046df344706c631e"
        )).unwrap();
        let result_key_256 = super::expand_key(&key_256, 4 * (14 + 1), 8);
        assert_eq!(expected_256, result_key_256);

 
    }
}