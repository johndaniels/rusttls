use super::messages::ParseError;
use super::digest::DigestAlgorithm;

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum CipherSuite {
    TlsAes128GcmSha256,
    TlsAes256GcmSha384,
    TlsChacha20Poly1305Sha256,
    TlsAes128CcmSha256,
    TlsAes128Ccm8Sha256,
}

#[derive(Debug)]
pub struct AeadResult {
    pub ciphertext: Vec<u8>,
    pub tag: [u8;16],
}

impl CipherSuite {
    pub fn to_u16(&self) -> u16 {
        match self {
            CipherSuite::TlsAes128GcmSha256 => 0x1301,
            CipherSuite::TlsAes256GcmSha384 => 0x1302,
            CipherSuite::TlsChacha20Poly1305Sha256 => 0x1303,
            CipherSuite::TlsAes128CcmSha256 => 0x1304,
            CipherSuite::TlsAes128Ccm8Sha256 => 0x1305,
        }
    }

    pub fn try_from_u16(num: u16) -> Result<CipherSuite, ParseError> {
        match num {
            0x1301 => Ok(CipherSuite::TlsAes128GcmSha256),
            0x1302 => Ok(CipherSuite::TlsAes256GcmSha384),
            0x1303 => Ok(CipherSuite::TlsChacha20Poly1305Sha256),
            0x1304 => Ok(CipherSuite::TlsAes128CcmSha256),
            0x1305 => Ok(CipherSuite::TlsAes128Ccm8Sha256),

            _ => Err(ParseError::Error("Could not parse cipher suit from number".to_string()))
        }
    }

    pub fn get_digest_algorithm(&self) -> DigestAlgorithm {
        match self {
            CipherSuite::TlsAes128GcmSha256 => DigestAlgorithm::Sha256,
            CipherSuite::TlsAes256GcmSha384 => DigestAlgorithm::Sha384,
            CipherSuite::TlsChacha20Poly1305Sha256 => DigestAlgorithm::Sha256,
            CipherSuite::TlsAes128CcmSha256 => DigestAlgorithm::Sha256,
            CipherSuite::TlsAes128Ccm8Sha256 => DigestAlgorithm::Sha256,
        }
    }

    pub fn key_len(&self) -> usize {
        match self {
            CipherSuite::TlsAes128GcmSha256 => 16,
            CipherSuite::TlsAes256GcmSha384 => 32,
            CipherSuite::TlsChacha20Poly1305Sha256 => 32,
            CipherSuite::TlsAes128CcmSha256 => 16,
            CipherSuite::TlsAes128Ccm8Sha256 => 16,
        }
    }

    pub fn iv_len(&self) -> usize {
        match self {
            CipherSuite::TlsAes128GcmSha256 => 12,
            CipherSuite::TlsAes256GcmSha384 => 12,
            CipherSuite::TlsChacha20Poly1305Sha256 => 12,
            CipherSuite::TlsAes128CcmSha256 => 12,
            CipherSuite::TlsAes128Ccm8Sha256 => 12,
        }
    }

    pub fn aead(&self, iv: &[u8], key: &[u8], authenticated_data: &[u8], plaintext: &[u8]) -> AeadResult {
        match self {
            CipherSuite::TlsAes128GcmSha256 => super::gcm::GcmCipher::Aes128.aead(iv, key, authenticated_data, plaintext),
            CipherSuite::TlsAes256GcmSha384 => super::gcm::GcmCipher::Aes256.aead(iv, key, authenticated_data, plaintext),
            CipherSuite::TlsChacha20Poly1305Sha256 => unimplemented!(),
            CipherSuite::TlsAes128CcmSha256 => unimplemented!(),
            CipherSuite::TlsAes128Ccm8Sha256 => unimplemented!(),
        }
    }
}