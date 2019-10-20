use super::messages::ParseError;

#[derive(Debug, Copy, Clone)]
pub enum CipherSuite {
    TlsAes128GcmSha256,
    TlsAes256GcmSha384,
    TlsChacha20Poly1305Sha256,
    TlsAes128CcmSha256,
    TlsAes128Ccm8Sha256,
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
}