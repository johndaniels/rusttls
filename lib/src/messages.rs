use bytes::{Buf, BufMut};
use std::io::{Write};
use std::convert::TryInto;
use super::client::BytesCursor;
use super::cipher_suite::CipherSuite;
use super::diffie_helman::DiffieHellmanGroup;
use super::signature::SignatureScheme;

macro_rules! parse_error {
    () => {ParseError::Error(format!("Parse Error on line {}", line!()))};
}

impl WriteToBuffer for DiffieHellmanGroup {
    fn write_to_buffer(&self, buffer: &mut dyn BufMut) {
        buffer.put_u16_be(self.to_u16());
    }
}

#[derive(Debug, Clone)]
pub enum Record {
    Invalid,
    ChangeCipherSpec,
    Alert,
    Handshake(Handshake),
    ApplicationData,
}

impl Record {
    fn r#type(&self) -> u8 {
        match self {
            Record::Invalid => 0,
            Record::ChangeCipherSpec => 20,
            Record::Alert => 21,
            Record::Handshake(_) => 22,
            Record::ApplicationData => 23,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result: Vec<u8> = vec!();
        self.write_to_buffer(&mut result);
        return result;
    }

    pub fn to_transcript_bytes(&self) -> Vec<u8> {
        let mut result: Vec<u8> = vec!();
        self.write_transcript_bytes(&mut result);
        result
    }

    fn write_transcript_bytes(&self, buffer: &mut dyn BufMut) {
        match &self {
            Record::Invalid => unimplemented!(),
            Record::ChangeCipherSpec => unimplemented!(),
            Record::Alert => unimplemented!(),
            Record::Handshake(handshake) => handshake.write_to_buffer(buffer),
            Record::ApplicationData => unimplemented!(),
        }
    }

    fn get_version(&self) -> u16 {
        match self {
            Record::Handshake(Handshake::ClientHello(_)) => 0x0301,
            _ => 0x0303,
        }
    }
}

impl WriteToBuffer for Record {
    fn write_to_buffer(&self, buffer: &mut dyn BufMut) {
        let mut inner_buffer: Vec<u8> = vec!();
        self.write_transcript_bytes(&mut inner_buffer);
        
        buffer.put_u8(self.r#type());
        buffer.put_u16_be(self.get_version());
        buffer.put_u16_be(inner_buffer.len().try_into().unwrap());
        buffer.writer().write_all(inner_buffer.as_slice()).unwrap();
    }
}

impl ReadFromBuffer for Record {
    type Item = Record;

    fn read_from_buffer(buffer: &mut BytesCursor) -> Result<Record, ParseError> {
        if buffer.remaining() < 5 {
            return Err(parse_error!());
        }
        let r#type = buffer.get_u8();
        let version = buffer.get_u16_be();
        if version != 0x0303 {
            return Err(parse_error!());
        }
        let length: usize = buffer.get_u16_be().try_into().unwrap();
        if buffer.remaining() != length {
            return Err(parse_error!());
        }
        match r#type {
            22 => {
                Ok(Record::Handshake(Handshake::read_from_buffer(buffer)?))
            }
            _ => {
                println!("Not a handshake: {:x?}", buffer);
                Err(parse_error!())
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum Handshake {
    ClientHello(ClientHello),
    ServerHello(ServerHello),
    NewSessionTicket(NewSessionTicket),
    EndOfEarlyData(EndOfEarlyData),
    EncryptedExtensions(EncryptedExtensions),
    Certificate(Certificate),
    CertificateRequest(CertificateRequest),
    CertificateVerify(CertificateVerify),
    Finished(Finished),
    KeyUpdate(KeyUpdate),
    MessageHash(MessageHash),
}

pub trait WriteToBuffer {
    fn write_to_buffer(&self, buffer: &mut dyn BufMut);
}

#[derive(Debug, Clone)]
pub enum ParseError {
    Error(String)
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "({:?})", self)
    }
}

impl std::error::Error for ParseError {

}

impl From<std::io::Error> for ParseError {
    fn from(_error: std::io::Error) -> Self {
        return ParseError::Error("Underlying I/O error".to_string());
    }
}


pub trait ReadFromBuffer {
    type Item;
    fn read_from_buffer(buffer: &mut BytesCursor) -> Result<Self::Item, ParseError>;
}

#[derive(Debug, Clone)]
pub struct ClientHello {
    pub random: Vec<u8>,
    pub legacy_session_id: Vec<u8>,
    pub cipher_suites: Vec<CipherSuite>,
    pub extensions: Vec<Extension>,
}

impl WriteToBuffer for ClientHello {
    fn write_to_buffer(&self, buffer: &mut dyn BufMut) {
        buffer.put_u16_be(0x0303); /* TLS v1.2 */
        buffer.put_slice(&self.random);
        buffer.put_u8(self.legacy_session_id.len().try_into().unwrap());
        buffer.writer().write_all(self.legacy_session_id.as_slice()).unwrap();
        buffer.put_u16_be((2 * self.cipher_suites.len()).try_into().unwrap());
        for cipher_suite in &self.cipher_suites {
            buffer.put_u16_be(cipher_suite.to_u16());
        }
        buffer.put_u8(1); // legacy compression methods length
        buffer.put_u8(0); // legacy compression method value (The single 0 for 'null' required by TLS 1.3)
        let mut extension_buffer = Vec::new();
        for extension in &self.extensions {
            extension.write_to_buffer(&mut extension_buffer);
        }
        buffer.put_u16_be(extension_buffer.len().try_into().unwrap());
        buffer.writer().write_all(extension_buffer.as_slice()).unwrap();
    }
}

#[derive(Debug, Clone)]
pub struct ServerHello {
    pub random: Vec<u8>,
    pub cipher_suite: CipherSuite,
    pub extensions: Vec<Extension>,
}

impl ReadFromBuffer for ServerHello {
    type Item = ServerHello;

    fn read_from_buffer(buffer: &mut BytesCursor) -> Result<ServerHello, ParseError> {
        if buffer.remaining() < 2 + 32 + 1 + 2 + 1 + 2 {
            return Err(parse_error!());
        }
        let legacy_version = buffer.get_u16_be();
        if legacy_version != 0x0303 {
            return Err(parse_error!());
        }
        let mut random: [u8;32] = [0;32];
        buffer.copy_to_slice(&mut random);
        let legacy_session_id_length = buffer.get_u8();
        if legacy_session_id_length != 0 {
            return Err(parse_error!());
        }
        let cipher_suite = CipherSuite::try_from_u16(buffer.get_u16_be())?;
        let legacy_compression_method = buffer.get_u8();
        if legacy_compression_method != 0 {
            return Err(parse_error!());
        }

        let extensions_length: usize = buffer.get_u16_be().try_into().unwrap();
        if buffer.remaining() < extensions_length {
            return Err(parse_error!());
        }
        let mut extensions_bytes = buffer.slice(0, extensions_length);
        let mut extensions: Vec<Extension> = vec!();
        while extensions_bytes.has_remaining() {
            extensions.push(Extension::read_from_buffer(ReadContext::ServerHello, &mut extensions_bytes)?)
        }

        buffer.advance(extensions_length);
        Ok(
            ServerHello {
                random: random.to_vec(),
                cipher_suite: cipher_suite,
                extensions: extensions,
            }
        )
    }
}

impl WriteToBuffer for ServerHello {
    fn write_to_buffer(&self, buffer: &mut dyn BufMut) {
        buffer.put_u16_be(0x0303); /* TLS v1.2 */
        buffer.put_slice(&self.random);
        buffer.put_u8(0); // legacy session id length
        buffer.put_u16_be(self.cipher_suite.to_u16());
        buffer.put_u8(0); // legacy compression method value (The single 0 for 'null' required by TLS 1.3)
        let mut extension_buffer = Vec::new();
        for extension in &self.extensions {
            extension.write_to_buffer(&mut extension_buffer);
        }
        buffer.put_u16_be(extension_buffer.len().try_into().unwrap());
        buffer.writer().write_all(extension_buffer.as_slice()).unwrap();
    }
}

#[derive(Debug, Clone)]
pub struct NewSessionTicket {

}

#[derive(Debug, Clone)]
pub struct EndOfEarlyData {

}

#[derive(Debug, Clone)]
pub struct EncryptedExtensions {
    pub extensions: Vec<Extension>,

}

#[derive(Debug, Clone)]
pub struct Certificate {

}

#[derive(Debug, Clone)]
pub struct CertificateRequest {

}

#[derive(Debug, Clone)]
pub struct CertificateVerify {

}

#[derive(Debug, Clone)]
pub struct Finished {

}

#[derive(Debug, Clone)]
pub struct KeyUpdate {

}

#[derive(Debug, Clone)]
pub struct MessageHash {

}

impl Handshake {
    fn msg_type(&self) -> u8{
        match self {
            Handshake::ClientHello(_) => 1,
            Handshake::ServerHello(_) => 2,
            Handshake::NewSessionTicket(_) => 4,
            Handshake::EndOfEarlyData(_) => 5,
            Handshake::EncryptedExtensions(_) => 8,
            Handshake::Certificate(_) => 11,
            Handshake::CertificateRequest(_) => 13,
            Handshake::CertificateVerify(_) => 15,
            Handshake::Finished(_) => 20,
            Handshake::KeyUpdate(_) => 24,
            Handshake::MessageHash(_) => 254,
        }
    }
}

impl WriteToBuffer for Handshake {
    fn write_to_buffer(&self, buffer: &mut dyn BufMut) {
        let mut result: Vec<u8> = Vec::new();
        result.put_u8(self.msg_type());
        let mut message_body: Vec<u8> = Vec::with_capacity(2048);

        match &self {
            Handshake::ClientHello(message) => message.write_to_buffer(&mut message_body),
            Handshake::ServerHello(message) => message.write_to_buffer(&mut message_body),
            Handshake::NewSessionTicket(_) => (),
            Handshake::EndOfEarlyData(_) => (),
            Handshake::EncryptedExtensions(_) => (),
            Handshake::Certificate(_) => (),
            Handshake::CertificateRequest(_) => (),
            Handshake::CertificateVerify(_) => (),
            Handshake::Finished(_) => (),
            Handshake::KeyUpdate(_) => (),
            Handshake::MessageHash(_) => (),
        }

        result.put_uint_be(message_body.len().try_into().unwrap(), 3);
        result.extend(message_body);
        for b in result {
            buffer.put_u8(b);
        }
    }
}

impl ReadFromBuffer for Handshake {
    type Item = Handshake;
    fn read_from_buffer(buffer: &mut BytesCursor) -> Result<Handshake, ParseError> {
        if buffer.remaining() < 4 {
            return Err(parse_error!());
        }
        
        let msg_type = buffer.get_u8();
        let length: usize = buffer.get_uint_be(3).try_into().unwrap();
        assert_eq!(length, buffer.remaining(), "Shouldn't be anything after handshake message");

        match msg_type {
            2 => {
                let server_hello = ServerHello::read_from_buffer(buffer)?;
                Ok(Handshake::ServerHello(server_hello))
            },
            _ => Err(parse_error!())
        }
    }
}

pub enum ReadContext {
    ServerHello,
    ClientHello,
    EncryptedExtensions,
}

#[derive(Debug, Clone)]
pub enum Extension {
    ServerName(ServerName),
    SupportedGroups(SupportedGroups),
    SignatureAlgorithms(SignatureAlgorithms),
    RecordSizeLimit(RecordSizeLimit),
    SupportedVersions(SupportedVersions),
    Cookie(Cookie),
    PskKeyExchangeModes(PskKeyExchangeModes),
    SignatureAlgorithmsCert(SignatureAlgorithmsCert),
    KeyShare(KeyShare),
    RenegotiationInfo(RenegotiationInfo),
    SessionTicket(SessionTicket),
}

impl Extension {
    fn extension_type(&self) -> u16 {
        match self {
            Extension::ServerName(_) => 0,
            Extension::SupportedGroups(_) => 10,
            Extension::SignatureAlgorithms(_) => 13,
            Extension::RecordSizeLimit(_) => 28,
            Extension::SessionTicket(_) => 35,
            Extension::SupportedVersions(_) => 43,
            Extension::Cookie(_) => 44,
            Extension::PskKeyExchangeModes(_) => 45,
            Extension::SignatureAlgorithmsCert(_) => 50,
            Extension::KeyShare(_) => 51,
            Extension::RenegotiationInfo(_) => 0xff01,
        }
    }

    fn read_from_buffer(context: ReadContext, buffer: &mut BytesCursor) -> Result<Extension, ParseError> {
        if buffer.remaining() < 4 {
            return Err(parse_error!());
        }
        let extension_type = buffer.get_u16_be();
        let length = buffer.get_u16_be();

        match extension_type {
            43 => {
                let supported_versions = SupportedVersions::read_from_buffer(context, buffer)?;
                return Ok(Extension::SupportedVersions(supported_versions));
            },
            51 => {
                let key_share = KeyShare::read_from_buffer(context, buffer)?;
                return Ok(Extension::KeyShare(key_share));
            }
            _ => Err(parse_error!()),
        }
    }

}

impl WriteToBuffer for Extension {
    fn write_to_buffer(&self, buffer: &mut dyn BufMut) {
        let mut extension_body: Vec<u8> = Vec::new();
        match self {
            Extension::ServerName(server_name) => {
                server_name.write_to_buffer(&mut extension_body);
            }
            Extension::SupportedGroups(supported_groups) => {
                supported_groups.write_to_buffer(&mut extension_body);
            }
            Extension::SupportedVersions(message) => {
                message.write_to_buffer(&mut extension_body);
            }
            Extension::Cookie(cookie) => {
                cookie.write_to_buffer(&mut extension_body);
            }
            Extension::PskKeyExchangeModes(psk_ke) => {
                psk_ke.write_to_buffer(&mut extension_body);
            }
            Extension::SignatureAlgorithms(algorithms) => {
                algorithms.write_to_buffer(&mut extension_body);
            }
            Extension::SignatureAlgorithmsCert(algorithms) => {
                algorithms.write_to_buffer(&mut extension_body);
            }
            Extension::RecordSizeLimit(record_size_limit) => {
                record_size_limit.write_to_buffer(&mut extension_body);
            }
            Extension::KeyShare(key_share) => {
                key_share.write_to_buffer(&mut extension_body);
            }
            Extension::RenegotiationInfo(renegotiation_info) => {
                renegotiation_info.write_to_buffer(&mut extension_body);
            }
            Extension::SessionTicket(session_ticket) => {
                session_ticket.write_to_buffer(&mut extension_body);
            }
        }
        buffer.put_u16_be(self.extension_type());
        buffer.put_u16_be(extension_body.len().try_into().unwrap());
        buffer.writer().write_all(extension_body.as_slice()).unwrap();
    }
}


#[derive(Debug, Clone)]
pub struct ServerName {
    pub hostname: Vec<u8>,
}
impl WriteToBuffer for ServerName {
    fn write_to_buffer(&self, buffer: &mut dyn BufMut) {
        let host_length: u16 = self.hostname.len().try_into().unwrap();
        buffer.put_u16_be(host_length + 3); //server_name_list length
        buffer.put_u8(0); // host_name NameType
        buffer.put_u16_be(host_length);
        buffer.writer().write_all(&self.hostname).unwrap();
    }    
}

#[derive(Debug, Clone)]
pub struct SupportedGroups {
    pub groups: Vec<DiffieHellmanGroup>
}

impl WriteToBuffer for SupportedGroups {
    fn write_to_buffer(&self, buffer: &mut dyn BufMut) {
        buffer.put_u16_be((2 * self.groups.len()).try_into().unwrap());
        for group in &self.groups {
            group.write_to_buffer(buffer);
        }
    }
}

#[derive(Debug, Clone)]
pub enum SupportedVersions {
    ServerHello,
    ClientHello
}


impl SupportedVersions {
    fn write_to_buffer(&self, buffer: &mut dyn BufMut) {
        match self {
            SupportedVersions::ClientHello => {
                buffer.put_u8(2); // 2 bytes for a single protocol version
                buffer.put_u16_be(0x0304); // TLS 1.3
            },
            SupportedVersions::ServerHello => {
                buffer.put_u16_be(0x0304); // TLS 1.3
            }
        }
        
    }

    fn read_from_buffer(context: ReadContext, buffer: &mut BytesCursor) -> Result<SupportedVersions, ParseError> {
        match context {
            ReadContext::ClientHello => {
                if buffer.remaining() < 2 {
                    return Err(parse_error!());
                }
                let length: usize = buffer.get_u16_be().try_into().unwrap();
                if buffer.remaining() < 2 * length {
                    return Err(parse_error!());
                }
                let mut versions: Vec<u16> = vec!();
                for _ in 0..length {
                    versions.push(buffer.get_u16_be());
                }
                Ok(SupportedVersions::ClientHello)
            },
            ReadContext::ServerHello => {
                if buffer.remaining() < 2 {
                    return Err(parse_error!());
                }

                let version = buffer.get_u16_be();
                if version != 0x0304 {
                    return Err(parse_error!());
                }
                Ok(SupportedVersions::ServerHello)
            },
            _ => Err(parse_error!())
        }
    }
}

#[derive(Debug, Clone)]
pub struct Cookie {
    cookie: Vec<u8>
}
impl WriteToBuffer for Cookie {
    fn write_to_buffer(&self, buffer: &mut dyn BufMut) {
        buffer.put_u16_be(self.cookie.len().try_into().unwrap());
        buffer.writer().write_all(self.cookie.as_slice()).unwrap();
    }
}

#[derive(Debug, Clone)]
pub struct SignatureAlgorithms {
    pub supported_signature_algorithms: Vec<SignatureScheme>
}
impl WriteToBuffer for SignatureAlgorithms {
    fn write_to_buffer(&self, buffer: &mut dyn BufMut) {
        buffer.put_u16_be((2 * self.supported_signature_algorithms.len()).try_into().unwrap());

        for algorithm in &self.supported_signature_algorithms {
            buffer.put_u16_be(algorithm.to_u16());
        }
    }
}

#[derive(Debug, Clone)]
pub struct SignatureAlgorithmsCert {
    pub supported_signature_algorithms: Vec<SignatureScheme>
}

impl WriteToBuffer for SignatureAlgorithmsCert {
    fn write_to_buffer(&self, buffer: &mut dyn BufMut) {
        buffer.put_u16_be((2 * self.supported_signature_algorithms.len()).try_into().unwrap());

        for algorithm in &self.supported_signature_algorithms {
            buffer.put_u16_be(algorithm.to_u16());
        }
    }
}

#[derive(Debug, Clone)]
pub enum KeyShare {
    ClientHello{
        client_shares: Vec<KeyShareEntry>
    },
    ServerHello {
        server_share: KeyShareEntry
    },
}

impl KeyShare {
    fn write_to_buffer(&self, buffer: &mut dyn BufMut) {
        match self {
            KeyShare::ClientHello { client_shares} => {
                let mut key_share_entries_data: Vec<u8> = Vec::new();
                for client_share in client_shares {
                    client_share.write_to_buffer(&mut key_share_entries_data);
                }
                buffer.put_u16_be(key_share_entries_data.len().try_into().unwrap());
                buffer.writer().write_all(key_share_entries_data.as_slice()).unwrap();
            },
            KeyShare::ServerHello { server_share } => {
                server_share.write_to_buffer(buffer);
            }
        }
    }

    fn read_from_buffer(context: ReadContext, buffer: &mut BytesCursor) -> Result<KeyShare, ParseError> {
        match context {
            ReadContext::ServerHello => {
                Ok(KeyShare::ServerHello {
                    server_share: KeyShareEntry::read_from_buffer(buffer)?
                })
            },
            _ => Err(parse_error!()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RenegotiationInfo {
    pub renegotiated_connection: Vec<u8>,
}

impl WriteToBuffer for RenegotiationInfo {
    fn write_to_buffer(&self, buffer: &mut dyn BufMut) {
        buffer.put_u8(self.renegotiated_connection.len().try_into().unwrap());
        buffer.put_slice(&self.renegotiated_connection);
    }
}

#[derive(Debug, Clone)]
pub struct SessionTicket {
    pub session_ticket: Vec<u8>,
}

impl WriteToBuffer for SessionTicket {
    fn write_to_buffer(&self, buffer: &mut dyn BufMut) {
        // Session ticket is special and doesn't write its length
        buffer.put_slice(&self.session_ticket);
    }
}

#[derive(Debug, Clone)]
pub struct KeyShareEntry {
    pub group: DiffieHellmanGroup,
    pub key_exchange: Vec<u8>,
}

impl WriteToBuffer for KeyShareEntry {
    fn write_to_buffer(&self, buffer: &mut dyn BufMut) {
        buffer.put_u16_be(self.group.to_u16());
        buffer.put_u16_be(self.key_exchange.len().try_into().unwrap());
        buffer.writer().write_all(self.key_exchange.as_slice()).unwrap();
    }
}

#[derive(Debug, Clone)]
pub enum PskKeyExchangeMode {
    PskKe,
    PskDheKe,
}

impl PskKeyExchangeMode {
    fn to_u8(&self) -> u8 {
        match self {
            PskKeyExchangeMode::PskKe => 0x00,
            PskKeyExchangeMode::PskDheKe => 0x01,
        }
    }

    fn try_from_u8(num: u8) -> Result<PskKeyExchangeMode, ParseError> {
        match num {
            0x00 => Ok(PskKeyExchangeMode::PskKe),
            0x01 => Ok(PskKeyExchangeMode::PskDheKe),
            _ => Err(parse_error!()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PskKeyExchangeModes {
    pub ke_modes: Vec<PskKeyExchangeMode>,
}

impl WriteToBuffer for PskKeyExchangeModes {
    fn write_to_buffer(&self, buffer: &mut dyn BufMut) {
        buffer.put_u8(self.ke_modes.len().try_into().unwrap());
        for ke_mode in &self.ke_modes {
            buffer.put_u8(ke_mode.to_u8());
        }
    }
}

#[derive(Debug, Clone)]
pub struct RecordSizeLimit {
    pub record_size_limit: u16,
}

impl WriteToBuffer for RecordSizeLimit {
    fn write_to_buffer(&self, buffer: &mut dyn BufMut) {
        buffer.put_u16_be(self.record_size_limit);
    }
}

impl ReadFromBuffer for KeyShareEntry {
    type Item = KeyShareEntry;
    fn read_from_buffer(buffer: &mut BytesCursor) -> Result<KeyShareEntry, ParseError> {
        if buffer.remaining() < 4 {
            return Err(parse_error!());
        }

        let group = DiffieHellmanGroup::try_from_u16(buffer.get_u16_be())?;
        let key_exchange_len: usize = buffer.get_u16_be().try_into().unwrap();
        if buffer.remaining() < key_exchange_len {
            return Err(parse_error!());
        }
        let mut key_exchange: Vec<u8> = vec![0; key_exchange_len];
        buffer.copy_to_slice(&mut key_exchange);

        Ok(KeyShareEntry {
            group: group,
            key_exchange: key_exchange,
        })
    }
}

#[cfg(test)]
mod tests {
    use num_bigint::BigInt;
    use super::super::eliptic_curve::secp256r1::ElipticCurve;
    use super::CipherSuite;
    use super::ReadFromBuffer;
    use bytes::{ BytesMut};


    #[test]
    fn test_handshake_serialization() {

        let curve = ElipticCurve::secp256r1();
        let ecdhe_private_key = BigInt::parse_bytes(b"1234FFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16).unwrap();
        let ecdhe_public_key = curve.multiply(&ecdhe_private_key, &curve.g);
        
        let message = super::Record::Handshake(
            super::Handshake::ClientHello(
                super::ClientHello {
                    random: [
                        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
                        0x1d, 0x1e, 0x1f, 0x20].to_vec(),
                    legacy_session_id: vec!(),
                    cipher_suites: vec!(CipherSuite::TlsAes128GcmSha256, CipherSuite::TlsAes256GcmSha384),
                    extensions: vec!(
                        super::Extension::SupportedVersions(
                            super::SupportedVersions::ClientHello {}
                        ),
                        super::Extension::ServerName(
                            super::ServerName {
                                hostname: b"www.google.com".to_vec()
                            }
                        ),
                        super::Extension::SignatureAlgorithms(
                            super::SignatureAlgorithms {
                                supported_signature_algorithms: vec! {
                                    super::SignatureScheme::RsaPkcs1Sha256,
                                    super::SignatureScheme::RsaPssRsaeSha256,
                                    super::SignatureScheme::EcdsaSecp256r1Sha256,
                                }
                            }
                        ),
                        super::Extension::SignatureAlgorithmsCert(
                            super::SignatureAlgorithmsCert {
                                supported_signature_algorithms: vec! {
                                    super::SignatureScheme::RsaPkcs1Sha256,
                                    super::SignatureScheme::RsaPssRsaeSha256,
                                    super::SignatureScheme::EcdsaSecp256r1Sha256,
                                }
                            }
                        ),
                        super::Extension::SupportedGroups(
                            super::SupportedGroups {
                                groups: vec! {
                                    super::DiffieHellmanGroup::Secp256r1
                                }
                            }
                        ),
                        super::Extension::KeyShare(
                            super::KeyShare::ClientHello {
                                client_shares: vec!(
                                    super::KeyShareEntry {
                                        group: super::DiffieHellmanGroup::Secp256r1,
                                        key_exchange: curve.point_to_bytes(&ecdhe_public_key),
                                    }
                                )
                            }
                        )
                    )
                }
            )
        );
        let bytes = message.to_bytes();

        assert_eq!(bytes, vec!(
            0x16, // TLS Handshake Protocol
            0x03, 0x01, // SSL Version 3.1 (for backwards compatibility)
            0x00, 0xba, // Length

            /* The ClientHello Handshake Message */
            0x01, // Handshake Type of ClientHello
            0, 0, 0xb6, // ClientHello Length
            0x03, 0x03, //SSL Version 3.3 (TLS 1.2) for backwards compatibility
            
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, // Random bytes         
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, // Random bytes
            0x1d, 0x1e, 0x1f, 0x20, // Random bytes
            0x0, // Session ID Length
            // Session ID (no bytes)
            0x0, 0x4, // Length of Cipher Suites
            0x13, 0x01, // AES_128_GCM_SHA256
            0x13, 0x02, // AES_256_GCM_SHA384
            0x01, // Compression Methods Length
            0x00, // Compression Methods Value (null)
            0x00, 0x89, // Length of Extensions
            
            0x00, 0x2b, // Supported Versions
            0x00, 0x03, // length
            0x02, // Length for the versions array
            0x03, 0x04, // TLS 1.3 (SSL 3.4)

            0x00, 0x00, // Server Name Indication
            0x00, 0x13, // Plugin Length
            0x00, 0x11, // Server Name List Length
            0x00, // name_type (host_name)
            0x00, 0x0e, // HostName length
            0x77, 0x77, 0x77, 0x2e, // "www."
            0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, // "google."
            0x63, 0x6f, 0x6d, // "com"

            0x00, 0x0d, //signature algorithms
            0x00, 0x08, // Plugin Length
            0x00, 0x06, // Signature Algorithms length
            0x04, 0x01, // RSA_PKCS1_SHA256
            0x08, 0x04, // RSA_PSS_RSAE_SHA256
            0x04, 0x03, // ECDSA_SECP256R1_SHA256
            
            0x00, 0x32, // Signature Algorithms Cert
            0x00, 0x08, // Plugin Length
            0x00, 0x06, // Signature Algorithms length
            0x04, 0x01, // RSA_PKCS1_SHA256
            0x08, 0x04, // RSA_PSS_RSAE_SHA256
            0x04, 0x03, // ECDSA_SECP256R1_SHA256

            0x00, 0x0a, // Supported Groups
            0x00, 0x04, // Plugin Length
            0x00, 0x02, // Supported Groups Length
            0x00, 0x17, // secp256r1,

            0x00, 0x33, // Key Share
            0x00, 0x47, // Plugin Length
            0x00, 0x45, // Key Share Length
            0x00, 0x17, // secp256r1
            0x00, 0x41, // Key share data length
            0x04, // Uncompressed point format
            0xab, 0x1d, 0x24, 0x9f, 0x95, 0x1c, 0x6e, 0x05, 0xe5, 0x10, 0x2f, 0xa8, 0xd9, 0xe5, 0xbc, 0xef, // x coords
            0xea, 0xcc, 0x51, 0xcb, 0x48, 0x5a, 0x0b, 0xd1, 0x6a, 0xc8, 0xa2, 0x57, 0x92, 0xe8, 0xdc, 0xdf, // x coords
            0x8b, 0xd9, 0x14, 0x52, 0x7d, 0xe3, 0xe9, 0xcd, 0xb0, 0x2d, 0x13, 0xc8, 0xc8, 0x16, 0xdf, 0x54, // y coords
            0xa2, 0x12, 0x72, 0x79, 0x4c, 0x12, 0x55, 0x0c, 0xd2, 0xc8, 0x14, 0x50, 0xfd, 0xa9, 0xd8, 0xb2, // y coords
        ));
    }

    #[test] 
    fn test_handshake_deserialization() {
        let bytes_array = [
            0x16, // TLS Handshake
            0x03, 0x03, // SSL Version 3.3 (TLS 1.2, for compatibility) 
            0x00, 0x7b, // Message Length
            0x02, // Server Hello Handshake Type
            0x00, 0x00, 0x77, // ServerHello Length
            0x03, 0x03, // SSL Version 3.3 (TLS 1.2, for compatibility
            0xc7, 0xb0, 0x46, 0x42, 0xbd, 0x5b, 0x39, 0xb1,
            0xcf, 0x33, 0x97, 0x4c, 0x41, 0x09, 0x44, 0xfe,
            0x53, 0x1b, 0xec, 0x4c, 0x47, 0xa2, 0x1e, 0x28,
            0x18, 0xb8, 0xfb, 0x28, 0x99, 0xf8, 0x1e, 0xdc,
            0x00, // legacy session id echo length (0 bytes)
            // session id echo (empty)
            0x13, 0x02, // Cipher Suite (AES_256_GCM_SHA384)
            0x00, // Legacy Compression Method
            0x00, 0x4f, // Extensions Length
            0x00, 0x2b, // Supported Versions
            0x00, 0x02, // Supported Versions Length
            0x03, 0x04, // TLS Version 1.3 (SSL 3.4)
            0x00, 0x33, // Key Share 
            0x00, 0x45, // Key Share Plugin Length
            0x00, 0x17, // Named Group secp256r1 
            0x00, 0x41, // Key share data length
            0x04, // Uncompressed point format
            0x82, 0xc5, 0x3e, 0x18, 0x80, 0x41, 0x66, 0x34, // x coords
            0xc7, 0x8d, 0x25, 0x75, 0x97, 0xdc, 0xa2, 0x46, // x coords
            0x33, 0x61, 0xed, 0x67, 0x84, 0xb7, 0x82, 0x07, // x coords
            0x8c, 0x44, 0x51, 0xc5, 0xe3, 0xe8, 0xb3, 0x8c, // x coords
            0xf6, 0x71, 0x56, 0xa3, 0x64, 0xca, 0xaa, 0x70, // y coords
            0xd3, 0x93, 0xe7, 0x46, 0x18, 0xf7, 0x32, 0x6a, // y coords
            0xd0, 0xd4, 0xda, 0x5b, 0xbe, 0x5f, 0x75, 0x12, // y coords
            0x4f, 0x62, 0x7f, 0x44, 0xf0, 0x34, 0xfd, 0xc6 // y coords
        ];
        let bytes = BytesMut::from(&bytes_array[..]);
        let record = super::Record::read_from_buffer(&mut super::BytesCursor::from_bytes_mut(&bytes));
        println!("RECORD: {:x?}", record)
    }
}