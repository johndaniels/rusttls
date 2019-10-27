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

#[derive(Debug, Clone, PartialEq)]
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

    pub fn write_to_buffer(&self, buffer: &mut dyn BufMut) {
        let mut inner_buffer: Vec<u8> = vec!();
        self.write_transcript_bytes(&mut inner_buffer);
        
        buffer.put_u8(self.r#type());
        buffer.put_u16_be(self.get_version());
        buffer.put_u16_be(inner_buffer.len().try_into().unwrap());
        buffer.writer().write_all(inner_buffer.as_slice()).unwrap();
    }

    pub fn read_from_buffer(buffer: &mut BytesCursor) -> Result<Record, ParseError> {
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

#[derive(Debug, Clone, PartialEq)]
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

fn write_list_u16<T: WriteToBuffer>(buffer: &mut dyn BufMut, list: &Vec<T>) {
    let mut item_buffer = Vec::new();
    for item in list {
        item.write_to_buffer(&mut item_buffer);
    }
    buffer.put_u16_be(item_buffer.len().try_into().unwrap());
    buffer.put_slice(item_buffer.as_slice());
}

fn write_list_u24<T: WriteToBuffer>(buffer: &mut dyn BufMut, list: &Vec<T>) {
    let mut item_buffer = Vec::new();
    for item in list {
        item.write_to_buffer(&mut item_buffer);
    }
    buffer.put_uint_be(item_buffer.len().try_into().unwrap(), 3);
    buffer.put_slice(item_buffer.as_slice());
}

fn read_list_items<T: ReadFromBuffer>(items_length: usize, context: ReadContext, buffer: &mut BytesCursor) -> Result<Vec<T>, ParseError> {
    if buffer.remaining() < items_length {
        return Err(parse_error!());
    }
    let mut items_bytes = buffer.slice(0, items_length);
    let mut items: Vec<T> = vec!();
    while items_bytes.has_remaining() {
        items.push(T::read_from_buffer(context, &mut items_bytes)?)
    }
    buffer.advance(items_length);
    return Ok(items);
}

fn read_list_u24<T: ReadFromBuffer>(context: ReadContext, buffer: &mut BytesCursor) -> Result<Vec<T>, ParseError> {
    if buffer.remaining() < 3 {
        return Err(parse_error!());
    }
    let items_length: usize = buffer.get_uint_be(3).try_into().unwrap();
    read_list_items(items_length, context, buffer)
}

fn read_list_u16<T: ReadFromBuffer>(context: ReadContext, buffer: &mut BytesCursor) -> Result<Vec<T>, ParseError> {
    if buffer.remaining() < 2 {
        return Err(parse_error!());
    }
    let items_length: usize = buffer.get_u16_be().into();
    read_list_items(items_length, context, buffer)    
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


pub trait ReadFromBuffer: Sized {
    fn read_from_buffer(context: ReadContext, buffer: &mut BytesCursor) -> Result<Self, ParseError>;
}

#[derive(Debug, Clone, PartialEq)]
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
        write_list_u16(buffer, &self.extensions);
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ServerHello {
    pub random: Vec<u8>,
    pub cipher_suite: CipherSuite,
    pub extensions: Vec<Extension>,
}

impl ServerHello {
    pub fn read_from_buffer(buffer: &mut BytesCursor) -> Result<ServerHello, ParseError> {
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

        let extensions = read_list_u16(ReadContext::ServerHello, buffer)?;
        Ok(
            ServerHello {
                random: random.to_vec(),
                cipher_suite: cipher_suite,
                extensions: extensions,
            }
        )
    }

    pub fn write_to_buffer(&self, buffer: &mut dyn BufMut) {
        buffer.put_u16_be(0x0303); /* TLS v1.2 */
        buffer.put_slice(&self.random);
        buffer.put_u8(0); // legacy session id length
        buffer.put_u16_be(self.cipher_suite.to_u16());
        buffer.put_u8(0); // legacy compression method value (The single 0 for 'null' required by TLS 1.3)
        write_list_u16(buffer, &self.extensions);
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct NewSessionTicket {

}

#[derive(Debug, Clone, PartialEq)]
pub struct EndOfEarlyData {

}

#[derive(Debug, Clone, PartialEq)]
pub struct EncryptedExtensions {
    pub extensions: Vec<Extension>,
}

impl EncryptedExtensions {
    fn read_from_buffer(buffer: &mut BytesCursor) -> Result<EncryptedExtensions, ParseError> {
        if buffer.remaining() < 2 {
            return Err(parse_error!());
        }
        
        let extensions = read_list_u16(ReadContext::EncryptedExtensions, buffer)?;
        Ok(EncryptedExtensions {
            extensions: extensions
        })
    }

    fn write_to_buffer(&self, buffer: &mut dyn BufMut) {
        write_list_u16(buffer, &self.extensions)
    }    
}

#[derive(Debug, Clone, PartialEq)]
pub struct CertificateEntry {
    cert_data: Vec<u8>,
    extensions: Vec<Extension>
}

impl ReadFromBuffer for CertificateEntry {
    fn read_from_buffer(context: ReadContext, buffer: &mut BytesCursor) -> Result<CertificateEntry, ParseError> {
        if buffer.remaining() < 2 {
            return Err(parse_error!());
        }
        let cert_data_len: usize = buffer.get_uint_be(3).try_into().unwrap();
        if buffer.remaining() < cert_data_len {
            return Err(parse_error!());
        }
        let cert_data: Vec<u8> = buffer.slice(0, cert_data_len).collect();
        buffer.advance(cert_data_len);
        let extensions = read_list_u16(context, buffer)?;
        Ok(
            CertificateEntry {
                cert_data: cert_data,
                extensions: extensions,
            }
        )
    }
}

impl WriteToBuffer for CertificateEntry {
    fn write_to_buffer(&self, buffer: &mut dyn BufMut) {
        buffer.put_uint_be(self.cert_data.len().try_into().unwrap(), 3);
        buffer.put_slice(&self.cert_data);
        write_list_u16(buffer, &self.extensions)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Certificate {
    certificate_request_context: Vec<u8>,
    certificate_list: Vec<CertificateEntry>,
}

impl Certificate {
    pub fn read_from_buffer(buffer: &mut BytesCursor) -> Result<Certificate, ParseError> {
        if buffer.remaining() < 1 {
            return Err(parse_error!())
        }
        let request_context_len: usize = buffer.get_u8().into();
        if buffer.remaining() < request_context_len {
            return Err(parse_error!())
        }
        let request_context: Vec<u8> = buffer.slice(0, request_context_len).collect();

        let certificate_list = read_list_u24(ReadContext::Certificate, buffer)?;

        return Ok(
            Certificate {
                certificate_request_context: request_context,
                certificate_list: certificate_list,
            }
        );
    }

    pub fn write_to_buffer(&self, buffer: &mut dyn BufMut) {
        buffer.put_u8(self.certificate_request_context.len().try_into().unwrap());
        buffer.put_slice(&self.certificate_request_context);
        write_list_u24(buffer, &self.certificate_list);
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CertificateRequest {

}

#[derive(Debug, Clone, PartialEq)]
pub struct CertificateVerify {
    signature_scheme: SignatureScheme,
    signature: Vec<u8>,
}

impl CertificateVerify {
    pub fn read_from_buffer(buffer: &mut BytesCursor) -> Result<CertificateVerify, ParseError> {
        if buffer.remaining() < 4 {
            return Err(parse_error!());
        }
        let signature_scheme = SignatureScheme::try_from_u16(buffer.get_u16_be())?;
        let signature_length: usize = buffer.get_u16_be().into();
        if buffer.remaining() < signature_length {
            return Err(parse_error!());
        }
        let signature: Vec<u8> = buffer.slice(0, signature_length).collect();
        buffer.advance(signature_length);
        Ok(
            CertificateVerify {
                signature_scheme: signature_scheme,
                signature: signature,
            }
        )
    }

    pub fn write_to_buffer(&self, buffer: &mut dyn BufMut) {
        buffer.put_u16_be(self.signature_scheme.to_u16());
        buffer.put_u16_be(self.signature.len().try_into().unwrap());
        buffer.put_slice(&self.signature);
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Finished {
    verify_data: Vec<u8>,
}

impl Finished {
    pub fn read_from_buffer(buffer: &mut BytesCursor, length: usize) -> Result<Finished, ParseError> {
        if buffer.remaining() < length {
            return Err(parse_error!());
        }
        let verify_data: Vec<u8> = buffer.slice(0, length).collect();
        buffer.advance(length);
        Ok(
            Finished {
                verify_data: verify_data,
            }
        )
    }

    pub fn write_to_buffer(&self, buffer: &mut dyn BufMut) {
        buffer.put_slice(&self.verify_data);
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct KeyUpdate {

}

#[derive(Debug, Clone, PartialEq)]
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

    pub fn write_to_buffer(&self, buffer: &mut dyn BufMut) {
        let mut result: Vec<u8> = Vec::new();
        result.put_u8(self.msg_type());
        let mut message_body: Vec<u8> = Vec::with_capacity(2048);

        match &self {
            Handshake::ClientHello(message) => message.write_to_buffer(&mut message_body),
            Handshake::ServerHello(message) => message.write_to_buffer(&mut message_body),
            Handshake::NewSessionTicket(_) => (),
            Handshake::EndOfEarlyData(_) => (),
            Handshake::EncryptedExtensions(message) => message.write_to_buffer(&mut message_body),
            Handshake::Certificate(message) => message.write_to_buffer(&mut message_body),
            Handshake::CertificateVerify(message) => message.write_to_buffer(&mut message_body),
            Handshake::CertificateRequest(_) => (),
            Handshake::Finished(message) => message.write_to_buffer(&mut message_body),
            Handshake::KeyUpdate(_) => (),
            Handshake::MessageHash(_) => (),
        }

        result.put_uint_be(message_body.len().try_into().unwrap(), 3);
        result.extend(message_body);
        for b in result {
            buffer.put_u8(b);
        }
    }

    pub fn read_from_buffer(buffer: &mut BytesCursor) -> Result<Handshake, ParseError> {
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
            8 => {
                Ok(Handshake::EncryptedExtensions(EncryptedExtensions::read_from_buffer(buffer)?))
            },
            11 => {
                Ok(Handshake::Certificate(Certificate::read_from_buffer(buffer)?))
            },
            15 => {
                Ok(Handshake::CertificateVerify(CertificateVerify::read_from_buffer(buffer)?))
            },
            20 => {
                Ok(Handshake::Finished(Finished::read_from_buffer(buffer, length)?))
            },
            _ => Err(parse_error!())
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ReadContext {
    ServerHello,
    ClientHello,
    EncryptedExtensions,
    Certificate,
}

#[derive(Debug, Clone, PartialEq)]
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
}

impl ReadFromBuffer for Extension {
    fn read_from_buffer(context: ReadContext, buffer: &mut BytesCursor) -> Result<Extension, ParseError> {
        if buffer.remaining() < 4 {
            return Err(parse_error!());
        }
        let extension_type = buffer.get_u16_be();
        let length = buffer.get_u16_be();

        match extension_type {
            0 => {
                if length == 0 {
                    return Ok(Extension::ServerName(ServerName {
                        hostname: None
                    }))
                }
                return Ok(Extension::ServerName(ServerName::read_from_buffer(context, buffer)?))
            },
            10 => {
                return Ok(Extension::SupportedGroups(SupportedGroups::read_from_buffer(context, buffer)?))
            },
            28 => {
                return Ok(Extension::RecordSizeLimit(RecordSizeLimit::read_from_buffer(context, buffer)?))
            },
            43 => {
                let supported_versions = SupportedVersions::read_from_buffer(context, buffer)?;
                return Ok(Extension::SupportedVersions(supported_versions));
            },
            51 => {
                let key_share = KeyShare::read_from_buffer(context, buffer)?;
                return Ok(Extension::KeyShare(key_share));
            },
            any => {
                println!("Invalid extension type: {:?}", any);
                Err(parse_error!())
            }
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


#[derive(Debug, Clone, PartialEq)]
pub struct ServerName {
    pub hostname: Option<Vec<u8>>,
}
impl WriteToBuffer for ServerName {
    fn write_to_buffer(&self, buffer: &mut dyn BufMut) {
        match &self.hostname {
            Some(hostname) => {
                let host_length: u16 = hostname.len().try_into().unwrap();
                buffer.put_u16_be(host_length + 3); //server_name_list length
                buffer.put_u8(0); // host_name NameType
                buffer.put_u16_be(host_length);
                buffer.writer().write_all(&hostname).unwrap();
            },
            None => {
            }
        }
        
    }    
}

impl ReadFromBuffer for ServerName {
    fn read_from_buffer(context: ReadContext, buffer: &mut BytesCursor) -> Result<ServerName, ParseError> {
        Err(parse_error!())
    }
}

#[derive(Debug, Clone, PartialEq)]
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

impl ReadFromBuffer for DiffieHellmanGroup {
    fn read_from_buffer(context: ReadContext, buffer: &mut BytesCursor) -> Result<DiffieHellmanGroup, ParseError> {
        DiffieHellmanGroup::try_from_u16(buffer.get_u16_be())
    }
}

impl ReadFromBuffer for SupportedGroups {
    fn read_from_buffer(context: ReadContext, buffer: &mut BytesCursor) -> Result<SupportedGroups, ParseError> {
        if buffer.remaining() < 2 {
            return Err(parse_error!());
        }
        let groups = read_list_u16(context, buffer)?;
        Ok(
            SupportedGroups {
                groups: groups,
            }
        )
    }
}

#[derive(Debug, Clone, PartialEq)]
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

#[derive(Debug, Clone, PartialEq)]
pub struct Cookie {
    cookie: Vec<u8>
}
impl WriteToBuffer for Cookie {
    fn write_to_buffer(&self, buffer: &mut dyn BufMut) {
        buffer.put_u16_be(self.cookie.len().try_into().unwrap());
        buffer.writer().write_all(self.cookie.as_slice()).unwrap();
    }
}

#[derive(Debug, Clone, PartialEq)]
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

#[derive(Debug, Clone, PartialEq)]
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

#[derive(Debug, Clone, PartialEq)]
pub enum KeyShare {
    ClientHello{
        client_shares: Vec<KeyShareEntry>
    },
    ServerHello {
        server_share: KeyShareEntry
    },
}

impl WriteToBuffer for KeyShare {
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
}

impl ReadFromBuffer for KeyShare {
    fn read_from_buffer(context: ReadContext, buffer: &mut BytesCursor) -> Result<KeyShare, ParseError> {
        match context {
            ReadContext::ServerHello => {
                Ok(KeyShare::ServerHello {
                    server_share: KeyShareEntry::read_from_buffer(context, buffer)?
                })
            },
            _ => Err(parse_error!()),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct RenegotiationInfo {
    pub renegotiated_connection: Vec<u8>,
}

impl WriteToBuffer for RenegotiationInfo {
    fn write_to_buffer(&self, buffer: &mut dyn BufMut) {
        buffer.put_u8(self.renegotiated_connection.len().try_into().unwrap());
        buffer.put_slice(&self.renegotiated_connection);
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SessionTicket {
    pub session_ticket: Vec<u8>,
}

impl WriteToBuffer for SessionTicket {
    fn write_to_buffer(&self, buffer: &mut dyn BufMut) {
        // Session ticket is special and doesn't write its length
        buffer.put_slice(&self.session_ticket);
    }
}

#[derive(Debug, Clone, PartialEq)]
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

#[derive(Debug, Clone, PartialEq)]
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

#[derive(Debug, Clone, PartialEq)]
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

#[derive(Debug, Clone, PartialEq)]
pub struct RecordSizeLimit {
    pub record_size_limit: u16,
}

impl WriteToBuffer for RecordSizeLimit {
    fn write_to_buffer(&self, buffer: &mut dyn BufMut) {
        buffer.put_u16_be(self.record_size_limit);
    }
}

impl ReadFromBuffer for RecordSizeLimit {
    fn read_from_buffer(context: ReadContext, buffer: &mut BytesCursor) -> Result<RecordSizeLimit, ParseError> {
        if buffer.remaining() < 2 {
            Err(parse_error!())
        } else {
            Ok(
                RecordSizeLimit {
                    record_size_limit: buffer.get_u16_be()
                }
            )
        }
    }
}

impl ReadFromBuffer for KeyShareEntry {
    fn read_from_buffer(context: ReadContext, buffer: &mut BytesCursor) -> Result<KeyShareEntry, ParseError> {
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
pub mod tests {
    use bytes::{ BytesMut};
    use super::*;
    use num_bigint::BigInt;
    use super::super::eliptic_curve::secp256r1::ElipticCurve;

    #[test]
    fn test_handshake_serialization() {
        let message = serialization_client_hello();
        let bytes = message.to_bytes();

        assert_eq!(bytes, serialization_client_hello_bytes());
    }

    #[test] 
    fn test_handshake_deserialization() {
        let bytes_array = deserialization_server_hello();
        let bytes = BytesMut::from(&bytes_array[..]);
        let record = super::Record::read_from_buffer(&mut super::BytesCursor::from_bytes_mut(&bytes));
        println!("RECORD: {:x?}", record)
    }

    #[test]
    fn test_encrypted_extensions_serdes() {
        let extensions = server_encrypted_extensions();
        let extensions_bytes = server_encrypted_extensions_bytes();
        let mut actual_bytes: Vec<u8> = vec!();
        extensions.write_to_buffer(&mut actual_bytes);
        assert_eq!(extensions_bytes, actual_bytes);
        let actual_record = Handshake::read_from_buffer(&mut BytesCursor::from_bytes_mut(&BytesMut::from(&extensions_bytes[..])));
        assert_eq!(extensions, actual_record.unwrap());
    }

    #[test]
    fn test_certificate_serdes() {
        let certificate = server_certificate();
        let certificate_bytes = server_certificate_bytes();
        let mut actual_bytes: Vec<u8> = vec!();
        certificate.write_to_buffer(&mut actual_bytes);
        assert_eq!(certificate_bytes, actual_bytes);
        let actual_record = Handshake::read_from_buffer(&mut BytesCursor::from_bytes_mut(&BytesMut::from(&certificate_bytes[..])));
        assert_eq!(certificate, actual_record.unwrap());
    }

    #[test]
    fn test_certificate_verify_serdes() {
        let certificate_verify = server_certificate_verify();
        let certificate_verify_bytes = server_certificate_verify_bytes();
        let mut actual_bytes: Vec<u8> = vec!();
        certificate_verify.write_to_buffer(&mut actual_bytes);
        assert_eq!(certificate_verify_bytes, actual_bytes);
        let actual_record = Handshake::read_from_buffer(&mut BytesCursor::from_bytes_mut(&BytesMut::from(&certificate_verify_bytes[..])));
        assert_eq!(certificate_verify, actual_record.unwrap());
    }

    #[test]
    fn test_finished_serdes() {
        let finished = server_finished();
        let finished_bytes = server_finished_bytes();
        let mut actual_bytes: Vec<u8> = vec!();
        finished.write_to_buffer(&mut actual_bytes);
        assert_eq!(finished_bytes, actual_bytes);
        let actual_record = Handshake::read_from_buffer(&mut BytesCursor::from_bytes_mut(&BytesMut::from(&finished_bytes[..])));
        assert_eq!(finished, actual_record.unwrap());
    }

    #[test]
    fn test_client_hello_serdes() {
        let hello = client_hello();
        let hello_bytes = client_hello_bytes();
        let mut actual_bytes: Vec<u8> = vec!();
        hello.write_to_buffer(&mut actual_bytes);
        assert_eq!(hello_bytes, actual_bytes);
        let actual_record = Record::read_from_buffer(&mut BytesCursor::from_bytes_mut(&BytesMut::from(&hello_bytes[..])));
        assert_eq!(hello, actual_record.unwrap());
    }

    pub fn deserialization_server_hello() -> Vec<u8> {
        vec!(
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
        )
    }

    pub fn serialization_client_hello() -> Record {
        let curve = ElipticCurve::secp256r1();
        let ecdhe_private_key = BigInt::parse_bytes(b"1234FFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16).unwrap();
        let ecdhe_public_key = curve.multiply(&ecdhe_private_key, &curve.g);

        super::Record::Handshake(
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
                                hostname: Some(b"www.google.com".to_vec())
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
        )
    }

    pub fn serialization_client_hello_bytes() -> Vec<u8> {
        vec!(
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
        )
    }

    pub fn server_hello() -> Record {
        Record::Handshake(Handshake::ServerHello(
            ServerHello {
                cipher_suite: CipherSuite::TlsAes128GcmSha256,
                random: vec!(
                    0xa6, 0xaf, 0x06, 0xa4, 0x12, 0x18, 0x60, 0xdc, 
                    0x5e, 0x6e, 0x60, 0x24, 0x9c, 0xd3, 0x4c, 0x95,
                    0x93, 0x0c, 0x8a, 0xc5, 0xcb, 0x14, 0x34, 0xda,
                    0xc1, 0x55, 0x77, 0x2e, 0xd3, 0xe2, 0x69, 0x28,
                ),
                extensions: vec!(
                    Extension::KeyShare(
                        KeyShare::ServerHello{
                            server_share: KeyShareEntry {
                                group: DiffieHellmanGroup::X25519,
                                key_exchange: vec!(
                                    0xc9, 0x82, 0x88, 0x76, 0x11, 0x20, 0x95, 0xfe, // Key Exchange 
                                    0x66, 0x76, 0x2b, 0xdb, 0xf7, 0xc6, 0x72, 0xe1, // Key Exchange 
                                    0x56, 0xd6, 0xcc, 0x25, 0x3b, 0x83, 0x3d, 0xf1, // Key Exchange 
                                    0xdd, 0x69, 0xb1, 0xb0, 0x4e, 0x75, 0x1f, 0x0f, // Key Exchange 
                                )
                            }
                        }
                    ),
                    Extension::SupportedVersions(
                        SupportedVersions::ServerHello
                    )
                )
            }
        ))
    }

    pub fn server_hello_bytes() -> Vec<u8> {
        vec!(
            0x16, // Handshake Protocol
            0x03, 0x03, // Version Number (SSL 3.3 for backwards compatibility)
            0x00, 0x5a, // mdessage length
            0x02,  // Server Hello
            0x00, 0x00, 0x56, // Handshake Length
            0x03, 0x03, // Version Number (SSL 3.3 for backwards compatibility)
            0xa6, 0xaf, 0x06, 0xa4, 0x12, 0x18, 0x60, 0xdc, 
            0x5e, 0x6e, 0x60, 0x24, 0x9c, 0xd3, 0x4c, 0x95,
            0x93, 0x0c, 0x8a, 0xc5, 0xcb, 0x14, 0x34, 0xda,
            0xc1, 0x55, 0x77, 0x2e, 0xd3, 0xe2, 0x69, 0x28,
            0x00, // Legacy Session ID Echo Length
            // Empty Legacy Session ID Echo

            0x13, 0x01, // Cipher (AES_128_GCM_SHA256)


            0x00, // Legacy Compression Method
            0x00, 0x2e, // Extensions Length
            0x00, 0x33, // Key Share
            0x00, 0x24, // Extension Length 
            0x00, 0x1d, // Chosen Group: x25519
            0x00, 0x20, // Key Exchange Length
            0xc9, 0x82, 0x88, 0x76, 0x11, 0x20, 0x95, 0xfe, // Key Exchange 
            0x66, 0x76, 0x2b, 0xdb, 0xf7, 0xc6, 0x72, 0xe1, // Key Exchange 
            0x56, 0xd6, 0xcc, 0x25, 0x3b, 0x83, 0x3d, 0xf1, // Key Exchange 
            0xdd, 0x69, 0xb1, 0xb0, 0x4e, 0x75, 0x1f, 0x0f, // Key Exchange 
            0x00, 0x2b, // Supported Versions
            0x00, 0x02, // Extension Length
            0x03, 0x04, // TLS 1.3 (SSL 3.4)
        )
    }

    pub fn client_hello() -> Record {
        Record::Handshake(Handshake::ClientHello(
            ClientHello {
                random: vec!(
                    0xcb, 0x34, 0xec, 0xb1, 0xe7, 0x81, 0x63, 0xba, // Random bytes
                    0x1c, 0x38, 0xc6, 0xda, 0xcb, 0x19, 0x6a, 0x6d, // Random bytes
                    0xff, 0xa2, 0x1a, 0x8d, 0x99, 0x12, 0xec, 0x18, // Random bytes
                    0xa2, 0xef, 0x62, 0x83, 0x02, 0x4d, 0xec, 0xe7, // Random bytes
                ),
                legacy_session_id: vec!(),
                cipher_suites: vec!(
                    CipherSuite::TlsAes128GcmSha256,
                    CipherSuite::TlsChacha20Poly1305Sha256,
                    CipherSuite::TlsAes256GcmSha384,
                ),
                extensions: vec!(
                    Extension::ServerName(
                        ServerName {
                            hostname: Some(b"server".to_vec())
                        }
                    ),
                    Extension::RenegotiationInfo(
                        RenegotiationInfo {
                            renegotiated_connection: vec!(),
                        }
                    ),
                    Extension::SupportedGroups(
                        SupportedGroups {
                            groups: vec!(
                                DiffieHellmanGroup::X25519,
                                DiffieHellmanGroup::Secp256r1,
                                DiffieHellmanGroup::Secp384r1,
                                DiffieHellmanGroup::Secp521r1,
                                DiffieHellmanGroup::Ffdhe2048,
                                DiffieHellmanGroup::Ffdhe3072,
                                DiffieHellmanGroup::Ffdhe4096,
                                DiffieHellmanGroup::Ffdhe6144,
                                DiffieHellmanGroup::Ffdhe8192,
                            )
                        }
                    ),
                    Extension::SessionTicket(
                        SessionTicket {
                            session_ticket: vec!(),
                        }
                    ),
                    Extension::KeyShare(
                        KeyShare::ClientHello {
                            client_shares: vec!(
                                KeyShareEntry {
                                    group: DiffieHellmanGroup::X25519,
                                    key_exchange: vec!(
                                        0x99, 0x38, 0x1d, 0xe5, 0x60, 0xe4, 0xbd, 0x43, // Key Share
                                        0xd2, 0x3d, 0x8e, 0x43, 0x5a, 0x7d, 0xba, 0xfe, // Key Share
                                        0xb3, 0xc0, 0x6e, 0x51, 0xc1, 0x3c, 0xae, 0x4d, // Key Share
                                        0x54, 0x13, 0x69, 0x1e, 0x52, 0x9a, 0xaf, 0x2c, // Key Share
                                    )
                                }
                            )
                        }
                    ),
                    Extension::SupportedVersions(
                        SupportedVersions::ClientHello
                    ),
                    Extension::SignatureAlgorithms(
                        SignatureAlgorithms {
                            supported_signature_algorithms: vec!(
                                SignatureScheme::EcdsaSecp256r1Sha256,
                                SignatureScheme::EcdsaSecp384r1Sha384,
                                SignatureScheme::EcdsaSecp512r1Sha512,
                                SignatureScheme::EcdsaSha1,
                                SignatureScheme::RsaPssRsaeSha256,
                                SignatureScheme::RsaPssRsaeSha384,
                                SignatureScheme::RsaPssRsaeSha512,
                                SignatureScheme::RsaPkcs1Sha256,
                                SignatureScheme::RsaPkcs1Sha384,
                                SignatureScheme::RsaPkcs1Sha512,
                                SignatureScheme::RsaPkcs1Sha1,
                                SignatureScheme::DsaSha256Reserved,
                                SignatureScheme::DsaSha384Reserved,
                                SignatureScheme::DsaSha512Reserved,
                                SignatureScheme::DsaSha1Reserved,
                            )
                        }
                    ),
                    Extension::PskKeyExchangeModes(PskKeyExchangeModes {
                        ke_modes: vec!(
                            PskKeyExchangeMode::PskDheKe,
                        )
                    }),
                    Extension::RecordSizeLimit(RecordSizeLimit {
                        record_size_limit: 0x4001,
                    })
                )
            }
        ))
    }

    pub fn client_hello_bytes() -> Vec<u8> {
        vec!(
            0x16, // TLS Handshake Protocol
            0x03, 0x01, // SSL Version 3.1 (for backwards compatibility)
            0x00, 0xc4, // Length

            /* The ClientHello Handshake Message */
            0x01, // Handshake Type of ClientHello
            0, 0, 0xc0, // ClientHello Length
            0x03, 0x03, //SSL Version 3.3 (TLS 1.2) for backwards compatibility
            
            0xcb, 0x34, 0xec, 0xb1, 0xe7, 0x81, 0x63, 0xba, // Random bytes
            0x1c, 0x38, 0xc6, 0xda, 0xcb, 0x19, 0x6a, 0x6d, // Random bytes
            0xff, 0xa2, 0x1a, 0x8d, 0x99, 0x12, 0xec, 0x18, // Random bytes
            0xa2, 0xef, 0x62, 0x83, 0x02, 0x4d, 0xec, 0xe7, // Random bytes

            0x0, // Session ID Length
            // Session ID (no bytes)
            0x0, 0x6, // Length of Cipher Suites
            0x13, 0x01, // AES_128_GCM_SHA256
            0x13, 0x03, // TLS_CHACHA20_POLY1305_SHA256
            0x13, 0x02, // AES_256_GCM_SHA384

            0x01, // Compression Methods Length
            0x00, // Compression Methods Value (null)

            0x00, 0x91, // Length of Extensions

            0x00, 0x00, // Server Name Indication
            0x00, 0x0b, // Extension Length
            0x00, 0x09, // Server Name List Length
            0x00, // name_type (host_name)
            0x00, 0x06, // HostName length
            0x73, 0x65, 0x72, 0x76, 0x65, 0x72, // "server"

            0xff, 0x01, // Renegotiated Connection
            0x00, 0x01, // Extension Length
            0x00,       // Renegotiated Connection Length
                        // Renegotiated Connection Data (empty)

            0x00, 0x0a, // Supported Groups
            0x00, 0x14, // Extension Length
            0x00, 0x12, // Supported Groups Length
            0x00, 0x1d, // x25519
            0x00, 0x17, // secp256r1
            0x00, 0x18, // secp384r1
            0x00, 0x19, // secp521r1
            0x01, 0x00, // ffdhe2048
            0x01, 0x01, // ffdhe3072
            0x01, 0x02, // ffdhe4096
            0x01, 0x03, // ffdhe6144
            0x01, 0x04, // ffdhe8192

            0x00, 0x23, // Session Ticket
            0x00, 0x00, // Session Ticket Length

            0x00, 0x33, // Key Share
            0x00, 0x26, // Extension Length
            0x00, 0x24, // Key Share Length
            0x00, 0x1d, // x25519
            0x00, 0x20, // Key share data length

            0x99, 0x38, 0x1d, 0xe5, 0x60, 0xe4, 0xbd, 0x43, // Key Share
            0xd2, 0x3d, 0x8e, 0x43, 0x5a, 0x7d, 0xba, 0xfe, // Key Share
            0xb3, 0xc0, 0x6e, 0x51, 0xc1, 0x3c, 0xae, 0x4d, // Key Share
            0x54, 0x13, 0x69, 0x1e, 0x52, 0x9a, 0xaf, 0x2c, // Key Share

            0x00, 0x2b, // Supported Versions
            0x00, 0x03, // length
            0x02, // Length for the versions array
            0x03, 0x04, // TLS 1.3 (SSL 3.4)

            0x00, 0x0d, //signature algorithms
            0x00, 0x20, // Extension Length
            0x00, 0x1e, // Signature Algorithms length
            0x04, 0x03, // ecdsa_secp256r1_sha256
            0x05, 0x03, // ecdsa_secp384r1_sha384
            0x06, 0x03, // ecdsa_secp521r1_sha512
            0x02, 0x03, // ecdsa_sha1
            0x08, 0x04, // rsa_pss_rsae_sha256
            0x08, 0x05, // rsa_pss_rsae_sha384
            0x08, 0x06, // rsa_pss_rsae_sha512
            0x04, 0x01, // rsa_pkcs1_sha256
            0x05, 0x01, // rsa_pkcs1_sha384
            0x06, 0x01, // rsa_pkcs1_sha512
            0x02, 0x01, // rsa_pkcs1_sha1
            0x04, 0x02, // dsa_sha256_RESERVED
            0x05, 0x02, // dsa_sha384_RESERVED
            0x06, 0x02, // dsa_sha512_RESERVED
            0x02, 0x02, // dsa_sha1_RESERVED

            0x00, 0x2d, // PSK Key Exchange Modes
            0x00, 0x02, // Extension Length
            0x01, // PSK Key Exchange Modes Length
            0x01, // psk_dhe_ke

            0x00, 0x1c, // Record Size Limit
            0x00, 0x02, // Extension Length
            0x40, 0x01, // 16385
        )
    }

    pub fn server_finished() -> Handshake {
        Handshake::Finished(
            Finished {
                verify_data: vec!(
                    0x9b, 0x9b, 0x14, 0x1d, 0x90, 0x63, 0x37, 0xfb, 0xd2, 0xcb, 0xdc, 0xe7, 0x1d, 0xf4, 0xde, 0xda,
                    0x4a, 0xb4, 0x2c, 0x30, 0x95, 0x72, 0xcb, 0x7f, 0xff, 0xee, 0x54, 0x54, 0xb7, 0x8f, 0x07, 0x18
                )
            }
        )
    }

    pub fn server_finished_bytes() -> Vec<u8> {
        vec!(
            0x14, // Finished type
            0x00, 0x00, 0x20, // Message Length
            0x9b, 0x9b, 0x14, 0x1d, 0x90, 0x63, 0x37, 0xfb, 0xd2, 0xcb, 0xdc, 0xe7, 0x1d, 0xf4, 0xde, 0xda, // verify bytes
            0x4a, 0xb4, 0x2c, 0x30, 0x95, 0x72, 0xcb, 0x7f, 0xff, 0xee, 0x54, 0x54, 0xb7, 0x8f, 0x07, 0x18
        )
    }

    pub fn server_certificate_verify() -> Handshake {
        Handshake::CertificateVerify(
            CertificateVerify {
                signature_scheme: SignatureScheme::RsaPssRsaeSha256,
                signature: vec!(
                    0x5a, 0x74, 0x7c, 0x5d, 0x88, 0xfa, 0x9b, 0xd2, 0xe5, 0x5a, 0xb0, 0x85, 0xa6, 0x10, 0x15, 0xb7,
                    0x21, 0x1f, 0x82, 0x4c, 0xd4, 0x84, 0x14, 0x5a, 0xb3, 0xff, 0x52, 0xf1, 0xfd, 0xa8, 0x47, 0x7b,
                    0x0b, 0x7a, 0xbc, 0x90, 0xdb, 0x78, 0xe2, 0xd3, 0x3a, 0x5c, 0x14, 0x1a, 0x07, 0x86, 0x53, 0xfa,
                    0x6b, 0xef, 0x78, 0x0c, 0x5e, 0xa2, 0x48, 0xee, 0xaa, 0xa7, 0x85, 0xc4, 0xf3, 0x94, 0xca, 0xb6, 
                    0xd3, 0x0b, 0xbe, 0x8d, 0x48, 0x59, 0xee, 0x51, 0x1f, 0x60, 0x29, 0x57, 0xb1, 0x54, 0x11, 0xac,
                    0x02, 0x76, 0x71, 0x45, 0x9e, 0x46, 0x44, 0x5c, 0x9e, 0xa5, 0x8c, 0x18, 0x1e, 0x81, 0x8e, 0x95,
                    0xb8, 0xc3, 0xfb, 0x0b, 0xf3, 0x27, 0x84, 0x09, 0xd3, 0xbe, 0x15, 0x2a, 0x3d, 0xa5, 0x04, 0x3e,
                    0x06, 0x3d, 0xda, 0x65, 0xcd, 0xf5, 0xae, 0xa2, 0x0d, 0x53, 0xdf, 0xac, 0xd4, 0x2f, 0x74, 0xf3,
                )
            }
        )
    }

    pub fn server_certificate_verify_bytes() -> Vec<u8> {
        vec!(
            0x0f, // Certificate Verify Message
            0x00, 0x00, 0x84, // Message Length
            0x08, 0x04, // Algorithm (RSA_PSS_RSAE_SHA256)
            0x00, 0x80, // Signature Length
            0x5a, 0x74, 0x7c, 0x5d, 0x88, 0xfa, 0x9b, 0xd2, 0xe5, 0x5a, 0xb0, 0x85, 0xa6, 0x10, 0x15, 0xb7,
            0x21, 0x1f, 0x82, 0x4c, 0xd4, 0x84, 0x14, 0x5a, 0xb3, 0xff, 0x52, 0xf1, 0xfd, 0xa8, 0x47, 0x7b,
            0x0b, 0x7a, 0xbc, 0x90, 0xdb, 0x78, 0xe2, 0xd3, 0x3a, 0x5c, 0x14, 0x1a, 0x07, 0x86, 0x53, 0xfa,
            0x6b, 0xef, 0x78, 0x0c, 0x5e, 0xa2, 0x48, 0xee, 0xaa, 0xa7, 0x85, 0xc4, 0xf3, 0x94, 0xca, 0xb6, 
            0xd3, 0x0b, 0xbe, 0x8d, 0x48, 0x59, 0xee, 0x51, 0x1f, 0x60, 0x29, 0x57, 0xb1, 0x54, 0x11, 0xac,
            0x02, 0x76, 0x71, 0x45, 0x9e, 0x46, 0x44, 0x5c, 0x9e, 0xa5, 0x8c, 0x18, 0x1e, 0x81, 0x8e, 0x95,
            0xb8, 0xc3, 0xfb, 0x0b, 0xf3, 0x27, 0x84, 0x09, 0xd3, 0xbe, 0x15, 0x2a, 0x3d, 0xa5, 0x04, 0x3e,
            0x06, 0x3d, 0xda, 0x65, 0xcd, 0xf5, 0xae, 0xa2, 0x0d, 0x53, 0xdf, 0xac, 0xd4, 0x2f, 0x74, 0xf3,
        )
    }

    pub fn server_certificate() -> Handshake {
        Handshake::Certificate(
            Certificate {
                certificate_request_context: vec!(),
                certificate_list: vec!(
                    CertificateEntry {
                        cert_data: vec!(
                            0x30, 0x82, 0x01, 0xac, 0x30, 0x82, 0x01, 0x15, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x02,
                            0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30,
                            0x0e, 0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x03, 0x72, 0x73, 0x61, 0x30,
                            0x1e, 0x17, 0x0d, 0x31, 0x36, 0x30, 0x37, 0x33, 0x30, 0x30, 0x31, 0x32, 0x33, 0x35, 0x39, 0x5a, 
                            0x17, 0x0d, 0x32, 0x36, 0x30, 0x37, 0x33, 0x30, 0x30, 0x31, 0x32, 0x33, 0x35, 0x39, 0x5a, 0x30,
                            0x0e, 0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x03, 0x72, 0x73, 0x61, 0x30,
                            0x81, 0x9f, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05,
                            0x00, 0x03, 0x81, 0x8d, 0x00, 0x30, 0x81, 0x89, 0x02, 0x81, 0x81, 0x00, 0xb4, 0xbb, 0x49, 0x8f,
                            0x82, 0x79, 0x30, 0x3d, 0x98, 0x08, 0x36, 0x39, 0x9b, 0x36, 0xc6, 0x98, 0x8c, 0x0c, 0x68, 0xde,
                            0x55, 0xe1, 0xbd, 0xb8, 0x26, 0xd3, 0x90, 0x1a, 0x24, 0x61, 0xea, 0xfd, 0x2d, 0xe4, 0x9a, 0x91,
                            0xd0, 0x15, 0xab, 0xbc, 0x9a, 0x95, 0x13, 0x7a, 0xce, 0x6c, 0x1a, 0xf1, 0x9e, 0xaa, 0x6a, 0xf9,
                            0x8c, 0x7c, 0xed, 0x43, 0x12, 0x09, 0x98, 0xe1, 0x87, 0xa8, 0x0e, 0xe0, 0xcc, 0xb0, 0x52, 0x4b,
                            0x1b, 0x01, 0x8c, 0x3e, 0x0b, 0x63, 0x26, 0x4d, 0x44, 0x9a, 0x6d, 0x38, 0xe2, 0x2a, 0x5f, 0xda,
                            0x43, 0x08, 0x46, 0x74, 0x80, 0x30, 0x53, 0x0e, 0xf0, 0x46, 0x1c, 0x8c, 0xa9, 0xd9, 0xef, 0xbf,
                            0xae, 0x8e, 0xa6, 0xd1, 0xd0, 0x3e, 0x2b, 0xd1, 0x93, 0xef, 0xf0, 0xab, 0x9a, 0x80, 0x02, 0xc4,
                            0x74, 0x28, 0xa6, 0xd3, 0x5a, 0x8d, 0x88, 0xd7, 0x9f, 0x7f, 0x1e, 0x3f, 0x02, 0x03, 0x01, 0x00,
                            0x01, 0xa3, 0x1a, 0x30, 0x18, 0x30, 0x09, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x02, 0x30, 0x00,
                            0x30, 0x0b, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x04, 0x04, 0x03, 0x02, 0x05, 0xa0, 0x30, 0x0d, 0x06,
                            0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x81, 0x81, 0x00, 
                            0x85, 0xaa, 0xd2, 0xa0, 0xe5, 0xb9, 0x27, 0x6b, 0x90, 0x8c, 0x65, 0xf7, 0x3a, 0x72, 0x67, 0x17,
                            0x06, 0x18, 0xa5, 0x4c, 0x5f, 0x8a, 0x7b, 0x33, 0x7d, 0x2d, 0xf7, 0xa5, 0x94, 0x36, 0x54, 0x17,
                            0xf2, 0xea, 0xe8, 0xf8, 0xa5, 0x8c, 0x8f, 0x81, 0x72, 0xf9, 0x31, 0x9c, 0xf3, 0x6b, 0x7f, 0xd6,
                            0xc5, 0x5b, 0x80, 0xf2, 0x1a, 0x03, 0x01, 0x51, 0x56, 0x72, 0x60, 0x96, 0xfd, 0x33, 0x5e, 0x5e,
                            0x67, 0xf2, 0xdb, 0xf1, 0x02, 0x70, 0x2e, 0x60, 0x8c, 0xca, 0xe6, 0xbe, 0xc1, 0xfc, 0x63, 0xa4,
                            0x2a, 0x99, 0xbe, 0x5c, 0x3e, 0xb7, 0x10, 0x7c, 0x3c, 0x54, 0xe9, 0xb9, 0xeb, 0x2b, 0xd5, 0x20,
                            0x3b, 0x1c, 0x3b, 0x84, 0xe0, 0xa8, 0xb2, 0xf7, 0x59, 0x40, 0x9b, 0xa3, 0xea, 0xc9, 0xd9, 0x1d,
                            0x40, 0x2d, 0xcc, 0x0c, 0xc8, 0xf8, 0x96, 0x12, 0x29, 0xac, 0x91, 0x87, 0xb4, 0x2b, 0x4d, 0xe1,
                        ),
                        extensions: vec!(),
                    }
                )
            }
        )
    }

    pub fn server_certificate_bytes() -> Vec<u8> {
        vec!(
            0x0b, // Certificate Message
            0x00, 0x01, 0xb9, // Message Length
            0x00, // Certificate Request Context Bytes
            0x00, 0x01, 0xb5, // Certificate Entry List Length
            0x00, 0x01, 0xb0, // X509 cert_data legth
            0x30, 0x82, 0x01, 0xac, 0x30, 0x82, 0x01, 0x15, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x02,
            0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30,
            0x0e, 0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x03, 0x72, 0x73, 0x61, 0x30,
            0x1e, 0x17, 0x0d, 0x31, 0x36, 0x30, 0x37, 0x33, 0x30, 0x30, 0x31, 0x32, 0x33, 0x35, 0x39, 0x5a, 
            0x17, 0x0d, 0x32, 0x36, 0x30, 0x37, 0x33, 0x30, 0x30, 0x31, 0x32, 0x33, 0x35, 0x39, 0x5a, 0x30,
            0x0e, 0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x03, 0x72, 0x73, 0x61, 0x30,
            0x81, 0x9f, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05,
            0x00, 0x03, 0x81, 0x8d, 0x00, 0x30, 0x81, 0x89, 0x02, 0x81, 0x81, 0x00, 0xb4, 0xbb, 0x49, 0x8f,
            0x82, 0x79, 0x30, 0x3d, 0x98, 0x08, 0x36, 0x39, 0x9b, 0x36, 0xc6, 0x98, 0x8c, 0x0c, 0x68, 0xde,
            0x55, 0xe1, 0xbd, 0xb8, 0x26, 0xd3, 0x90, 0x1a, 0x24, 0x61, 0xea, 0xfd, 0x2d, 0xe4, 0x9a, 0x91,
            0xd0, 0x15, 0xab, 0xbc, 0x9a, 0x95, 0x13, 0x7a, 0xce, 0x6c, 0x1a, 0xf1, 0x9e, 0xaa, 0x6a, 0xf9,
            0x8c, 0x7c, 0xed, 0x43, 0x12, 0x09, 0x98, 0xe1, 0x87, 0xa8, 0x0e, 0xe0, 0xcc, 0xb0, 0x52, 0x4b,
            0x1b, 0x01, 0x8c, 0x3e, 0x0b, 0x63, 0x26, 0x4d, 0x44, 0x9a, 0x6d, 0x38, 0xe2, 0x2a, 0x5f, 0xda,
            0x43, 0x08, 0x46, 0x74, 0x80, 0x30, 0x53, 0x0e, 0xf0, 0x46, 0x1c, 0x8c, 0xa9, 0xd9, 0xef, 0xbf,
            0xae, 0x8e, 0xa6, 0xd1, 0xd0, 0x3e, 0x2b, 0xd1, 0x93, 0xef, 0xf0, 0xab, 0x9a, 0x80, 0x02, 0xc4,
            0x74, 0x28, 0xa6, 0xd3, 0x5a, 0x8d, 0x88, 0xd7, 0x9f, 0x7f, 0x1e, 0x3f, 0x02, 0x03, 0x01, 0x00,
            0x01, 0xa3, 0x1a, 0x30, 0x18, 0x30, 0x09, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x02, 0x30, 0x00,
            0x30, 0x0b, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x04, 0x04, 0x03, 0x02, 0x05, 0xa0, 0x30, 0x0d, 0x06,
            0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x81, 0x81, 0x00, 
            0x85, 0xaa, 0xd2, 0xa0, 0xe5, 0xb9, 0x27, 0x6b, 0x90, 0x8c, 0x65, 0xf7, 0x3a, 0x72, 0x67, 0x17,
            0x06, 0x18, 0xa5, 0x4c, 0x5f, 0x8a, 0x7b, 0x33, 0x7d, 0x2d, 0xf7, 0xa5, 0x94, 0x36, 0x54, 0x17,
            0xf2, 0xea, 0xe8, 0xf8, 0xa5, 0x8c, 0x8f, 0x81, 0x72, 0xf9, 0x31, 0x9c, 0xf3, 0x6b, 0x7f, 0xd6,
            0xc5, 0x5b, 0x80, 0xf2, 0x1a, 0x03, 0x01, 0x51, 0x56, 0x72, 0x60, 0x96, 0xfd, 0x33, 0x5e, 0x5e,
            0x67, 0xf2, 0xdb, 0xf1, 0x02, 0x70, 0x2e, 0x60, 0x8c, 0xca, 0xe6, 0xbe, 0xc1, 0xfc, 0x63, 0xa4,
            0x2a, 0x99, 0xbe, 0x5c, 0x3e, 0xb7, 0x10, 0x7c, 0x3c, 0x54, 0xe9, 0xb9, 0xeb, 0x2b, 0xd5, 0x20,
            0x3b, 0x1c, 0x3b, 0x84, 0xe0, 0xa8, 0xb2, 0xf7, 0x59, 0x40, 0x9b, 0xa3, 0xea, 0xc9, 0xd9, 0x1d,
            0x40, 0x2d, 0xcc, 0x0c, 0xc8, 0xf8, 0x96, 0x12, 0x29, 0xac, 0x91, 0x87, 0xb4, 0x2b, 0x4d, 0xe1,
            0x00, 0x00 // Extensions Length
        )
    }

    pub fn server_encrypted_extensions() -> Handshake  {
        Handshake::EncryptedExtensions(
            EncryptedExtensions {
                extensions: vec!(
                    Extension::SupportedGroups(SupportedGroups {
                        groups: vec! {
                            DiffieHellmanGroup::X25519,
                            DiffieHellmanGroup::Secp256r1,
                            DiffieHellmanGroup::Secp384r1,
                            DiffieHellmanGroup::Secp521r1,
                            DiffieHellmanGroup::Ffdhe2048,
                            DiffieHellmanGroup::Ffdhe3072,
                            DiffieHellmanGroup::Ffdhe4096,
                            DiffieHellmanGroup::Ffdhe6144,
                            DiffieHellmanGroup::Ffdhe8192,
                        }
                    }),
                    Extension::RecordSizeLimit(
                        RecordSizeLimit {
                            record_size_limit: 0x4001,
                        }
                    ),
                    Extension::ServerName(
                        ServerName {
                            hostname:None,
                        }
                    )
                )
            }
        )
    }

    pub fn server_encrypted_extensions_bytes() -> Vec<u8> {
        vec!(
            0x08, // Encrypted Extensions
            0x00, 0x00, 0x24, // Length
            0x00, 0x22, // Length
            0x00, 0x0a, // Supported Groups
            0x00, 0x14, // Extension Length
            0x00, 0x12, // Named Group List
            0x00, 0x1d, // X25519
            0x00, 0x17, //Secp256r1
            0x00, 0x18, //Secp384r1
            0x00, 0x19,  //Secp521r1
            0x01, 0x00, //Ffdhe2048 
            0x01, 0x01, //Ffdhe3072
            0x01, 0x02, //Ffdhe4096
            0x01, 0x03, //Ffdhe6144
            0x01, 0x04, //Ffdhe8192
            0x00, 0x1c, // Record Size Limit
            0x00, 0x02, // Plugin Length
            0x40, 0x01, // Record Size 0x4001.
            0x00, 0x00, // Server Name
            0x00, 0x00, // Server Name Plugin Length
        )
    }
}