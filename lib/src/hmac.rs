use super::digest::{Digest, DigestAlgorithm};
use std::convert::TryInto;

trait MessageAuthenticationCode {
    fn update(&mut self, update_buf: &[u8]);
    fn finalize(&mut self) -> Vec<u8>;
}

struct Hmac<Algorithm: DigestAlgorithm> {
    digest: Box<Algorithm::DigestType>,
    key: Vec<u8>,
}

fn pad_key(key: &[u8], size: usize, byte_xor: u8) -> Vec<u8> {
    let mut padded_key: Vec<u8> = Vec::with_capacity(size);
    padded_key.extend(key);
    while padded_key.len() < size {
        padded_key.push(0);
    }
    let mut xor_key = Vec::with_capacity(size);
    for b in padded_key {
        xor_key.push(b ^ byte_xor)
    }
    return xor_key;
}

impl <Algorithm: DigestAlgorithm> Hmac<Algorithm> {
    fn new(key: &[u8]) -> Hmac<Algorithm> {
        let mut final_key: Vec<u8>;
        if (key.len() > Algorithm::block_size()) {
            let mut hash = Algorithm::new();
            hash.update(key);
            final_key = hash.finalize();
        } else {
            final_key = key.to_vec();
        }
        let mut result = Hmac::<Algorithm> {
            digest: Algorithm::new(),
            key: final_key.clone(),
        };
        let ipad_key = pad_key(&final_key, Algorithm::block_size(), 0x36);
        result.update(&ipad_key);
        result
    }
}

impl<Algorithm: DigestAlgorithm> MessageAuthenticationCode for Hmac<Algorithm> {
    fn update(&mut self, update_buf: &[u8]) {
        self.digest.update(update_buf);
    }

    fn finalize(&mut self) -> Vec<u8> {
        let inner_digest_result = self.digest.finalize();

        let mut outer_digest = Algorithm::new();
        let opad_key = pad_key(&self.key, Algorithm::block_size(), 0x5C);
        outer_digest.update(&opad_key);
        outer_digest.update(&inner_digest_result);
        return outer_digest.finalize();
    }
}

fn hmac_hash<AlgorithmT: DigestAlgorithm>(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut hmac = Hmac::<AlgorithmT>::new(key);
    hmac.update(data);
    hmac.finalize()
}

pub fn hkdf_extract<AlgorithmT: DigestAlgorithm>(salt: &[u8], key_material: &[u8]) -> Vec<u8> {
    hmac_hash::<AlgorithmT>(salt, key_material)
}

pub fn hkdf_expand<AlgorithmT: DigestAlgorithm>(key: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let mut output = Vec::new();
    let mut current: Vec<u8> = vec!();
    for i in 1..((length + length - 1) / AlgorithmT::result_size()) + 1 {
        let mut hmac = Hmac::<AlgorithmT>::new(key);
        hmac.update(&current);
        hmac.update(info);
        hmac.update(&[i.try_into().unwrap()]);
        current = hmac.finalize();
        output.extend(&current);
    }
    return output[..length].to_vec();
}

#[cfg(test)]
mod tests {
    use super::{Hmac, MessageAuthenticationCode};
    use super::super::digest::sha384::Sha384;
    use super::super::digest::sha256::Sha256;

    #[test]
    fn test_hmac() {
        let key_hex = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
        let key = hex::decode(key_hex).unwrap();
        let data = b"Hi There";
        let mut hmac = Hmac::<Sha384>::new(&key);
        let expected_hex = concat!("afd03944d84895626b0825f4ab46907f",
                                   "15f9dadbe4101ec682aa034c7cebc59c",
                                   "faea9ea9076ede7f4af152e8b2fa9cb6");
        hmac.update(data);
        let actual = hmac.finalize();
        let actual_hex = hex::encode(actual);
        assert_eq!(expected_hex, actual_hex);
    }

    #[test]
    fn test_hkdf() {
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = vec!();
        let info = vec!();
        let length = 42;
        let prk = super::hkdf_extract::<Sha256>(&salt, &ikm);
        assert_eq!(hex::encode(&prk), "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04");
        let okm = super::hkdf_expand::<Sha256>(&prk, &info, length);
        assert_eq!(hex::encode(&okm), "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8");
    }

    #[test]
    fn test_hkdf2() {
        let ikm = hex::decode(concat!(
            "000102030405060708090a0b0c0d0e0f",
            "101112131415161718191a1b1c1d1e1f",
            "202122232425262728292a2b2c2d2e2f",
            "303132333435363738393a3b3c3d3e3f",
            "404142434445464748494a4b4c4d4e4f")).unwrap();
        let salt = hex::decode(concat!(
            "606162636465666768696a6b6c6d6e6f",
            "707172737475767778797a7b7c7d7e7f",
            "808182838485868788898a8b8c8d8e8f",
            "909192939495969798999a9b9c9d9e9f",
            "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf")).unwrap();
        let info = hex::decode(concat!(
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
            "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
            "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf",
            "e0e1e2e3e4e5e6e7e8e9eaebecedeeef",
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")).unwrap();
        let length = 82;
        let prk = super::hkdf_extract::<Sha256>(&salt, &ikm);
        assert_eq!(hex::encode(&prk), "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244");
        let okm = super::hkdf_expand::<Sha256>(&prk, &info, length);
        assert_eq!(hex::encode(&okm), concat!(
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045",
            "a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179e",
            "c3e87c14c01d5c1f3434f1d87"));
    }

    #[test]
    fn test_hkdf3() {
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let length = 42;
        let prk = super::hkdf_extract::<Sha256>(&salt, &ikm);
        assert_eq!(hex::encode(&prk), "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        let okm = super::hkdf_expand::<Sha256>(&prk, &info, length);
        assert_eq!(hex::encode(&okm), "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
    }
}
