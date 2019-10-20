use super::messages::ParseError;

#[derive(Debug, Clone, Copy)]
pub enum SignatureScheme {
    /* RSASSA-PKCS1-v1_5 algorithms */
    RsaPkcs1Sha256,
    RsaPkcs1Sha384,
    RsaPkcs1Sha512,
    
    /* RSASSA-PKCS1-v1_5 algorithms */
    EcdsaSecp256r1Sha256,
    EcdsaSecp384r1Sha384,
    EcdsaSecp512r1Sha512,

    /* RSASSA-PSS algorithms with public key OID rsaEncryption */
    RsaPssRsaeSha256,
    RsaPssRsaeSha384,
    RsaPssRsaeSha512,
          
    /* EdDSA algorithms */
    Ed25519,
    Ed448,

    /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
    RsaPssPssSha256,
    RsaPssPssSha384,
    RsaPssPssSha512,

    /* Legacy algorithms */
    RsaPkcs1Sha1,
    EcdsaSha1,

    DsaSha1Reserved,
    DsaSha256Reserved,
    DsaSha384Reserved,
    DsaSha512Reserved,
}

impl SignatureScheme {
    pub fn to_u16(&self) -> u16 {
        match self {
            SignatureScheme::RsaPkcs1Sha256 => 0x0401,
            SignatureScheme::RsaPkcs1Sha384 => 0x0501,
            SignatureScheme::RsaPkcs1Sha512 => 0x0601,

            SignatureScheme::EcdsaSecp256r1Sha256 => 0x0403,
            SignatureScheme::EcdsaSecp384r1Sha384 => 0x0503,
            SignatureScheme::EcdsaSecp512r1Sha512 => 0x0603,

            SignatureScheme::RsaPssRsaeSha256 => 0x0804,
            SignatureScheme::RsaPssRsaeSha384 => 0x0805,
            SignatureScheme::RsaPssRsaeSha512 => 0x0806,

            SignatureScheme::Ed25519 => 0x0807,
            SignatureScheme::Ed448 => 0x0808,

            SignatureScheme::RsaPssPssSha256 => 0x0809,
            SignatureScheme::RsaPssPssSha384 => 0x080a,
            SignatureScheme::RsaPssPssSha512 => 0x080b,

            SignatureScheme::RsaPkcs1Sha1 => 0x0201,
            SignatureScheme::EcdsaSha1 => 0x0203,

            SignatureScheme::DsaSha1Reserved => 0x0202,
            SignatureScheme::DsaSha256Reserved => 0x0402,
            SignatureScheme::DsaSha384Reserved => 0x0502,
            SignatureScheme::DsaSha512Reserved => 0x0602,
        }
    }

    pub fn try_from_u16(num: u16) -> Result<SignatureScheme, ParseError> {
        match num {
            0x0401 => Ok(SignatureScheme::RsaPkcs1Sha256),
            0x0501 => Ok(SignatureScheme::RsaPkcs1Sha384),
            0x0601 => Ok(SignatureScheme::RsaPkcs1Sha512),

            0x0403 => Ok(SignatureScheme::EcdsaSecp256r1Sha256),
            0x0503 => Ok(SignatureScheme::EcdsaSecp384r1Sha384),
            0x0603 => Ok(SignatureScheme::EcdsaSecp512r1Sha512),

            0x0804 => Ok(SignatureScheme::RsaPssRsaeSha256),
            0x0805 => Ok(SignatureScheme::RsaPssRsaeSha384),
            0x0806 => Ok(SignatureScheme::RsaPssRsaeSha512),

            0x0807 => Ok(SignatureScheme::Ed25519),
            0x0808 => Ok(SignatureScheme::Ed448),

            0x0809 => Ok(SignatureScheme::RsaPssPssSha256),
            0x080a => Ok(SignatureScheme::RsaPssPssSha384),
            0x080b => Ok(SignatureScheme::RsaPssPssSha512),

            0x0202 => Ok(SignatureScheme::DsaSha1Reserved),
            0x0402 => Ok(SignatureScheme::DsaSha256Reserved),
            0x0502 => Ok(SignatureScheme::DsaSha384Reserved),
            0x0602 => Ok(SignatureScheme::DsaSha512Reserved),

            _ => Err(ParseError::Error("Error parsing Signature Scheme".to_string())),
        }
    }
}