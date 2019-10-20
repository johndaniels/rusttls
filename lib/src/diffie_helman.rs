use super::eliptic_curve::curve25519::{curve25519, curve25519_base};
use super::eliptic_curve::secp256r1::{secp256r1, secp256r1_base};
use super::messages::ParseError;

#[derive(Debug, Clone, Copy)]
pub enum DiffieHellmanGroup {
    /* Elliptic Curve Groups (ECDHE) */
    Secp256r1,
    Secp384r1,
    Secp521r1,
    X25519,
    X448,

    /* Finite Field Groups (DHE) */
    Ffdhe2048,
    Ffdhe3072,
    Ffdhe4096,
    Ffdhe6144,
    Ffdhe8192,
}

impl DiffieHellmanGroup {
    pub fn private_key_bytes(&self) -> usize {
        match &self {
            DiffieHellmanGroup::X25519 => 32,
            DiffieHellmanGroup::Secp256r1 => 32,
            _ => unimplemented!(),
        }
    }

    pub fn public_key_bytes(&self) -> usize {
        match &self {
            DiffieHellmanGroup::X25519 => 32,
            DiffieHellmanGroup::Secp256r1 => 65,
            _ => unimplemented!(),
        }
    }

    pub fn compute(&self, private_key: &[u8], public_key: &[u8]) -> Vec<u8> {
        assert_eq!(private_key.len(), self.private_key_bytes());
        assert_eq!(public_key.len(), self.public_key_bytes());
        match &self {
            DiffieHellmanGroup::X25519 => {
                return curve25519(private_key, public_key);
            },
            DiffieHellmanGroup::Secp256r1 => {
                return secp256r1(private_key, public_key);
            },
            _ => unimplemented!(),
        }
    }

    pub fn to_u16(&self) -> u16 {
        match self {
            DiffieHellmanGroup::Secp256r1 => 0x0017,
            DiffieHellmanGroup::Secp384r1 => 0x0018,
            DiffieHellmanGroup::Secp521r1 => 0x0019,
            DiffieHellmanGroup::X25519 => 0x001D,
            DiffieHellmanGroup::X448 => 0x001E,

            DiffieHellmanGroup::Ffdhe2048 => 0x100,
            DiffieHellmanGroup::Ffdhe3072 => 0x101,
            DiffieHellmanGroup::Ffdhe4096 => 0x102,
            DiffieHellmanGroup::Ffdhe6144 => 0x103,
            DiffieHellmanGroup::Ffdhe8192 => 0x104,
        }
    }

    pub fn try_from_u16(num: u16) -> Result<DiffieHellmanGroup, ParseError> {
        match num {
            0x0017 => Ok(DiffieHellmanGroup::Secp256r1),
            0x0018 => Ok(DiffieHellmanGroup::Secp384r1),
            0x0019 => Ok(DiffieHellmanGroup::Secp521r1),
            0x001D => Ok(DiffieHellmanGroup::X25519),
            0x001E => Ok(DiffieHellmanGroup::X448),

            0x100 => Ok(DiffieHellmanGroup::Ffdhe2048),
            0x101 => Ok(DiffieHellmanGroup::Ffdhe3072),
            0x102 => Ok(DiffieHellmanGroup::Ffdhe4096),
            0x103 => Ok(DiffieHellmanGroup::Ffdhe6144),
            0x104 => Ok(DiffieHellmanGroup::Ffdhe8192),
            _ => Err(ParseError::Error("Error parsing Diffie Hellman group".to_string()))
        }
    }

    pub fn base(&self) -> Vec<u8> {
        match &self {
            DiffieHellmanGroup::X25519 => {
                return curve25519_base()
            },
            DiffieHellmanGroup::Secp256r1 => {
                return secp256r1_base()
            },
            _ => unimplemented!(),
        }
    }

    pub fn generate_public(&self, private_key: &[u8]) -> Vec<u8> {
        self.compute(private_key, &self.base())
    }
}