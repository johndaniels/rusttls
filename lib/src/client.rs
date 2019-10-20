use tokio::net::TcpStream;
use tokio::prelude::*;
use trust_dns_resolver::Resolver;
use trust_dns_resolver::config::*;
use rand::prelude::*;
use std::net::{SocketAddr};
use super::messages::*;
use super::signature::SignatureScheme;
use super::cipher::CipherSuite;
use num_bigint::{Sign, BigInt};
use bytes::{Buf, BufMut, BytesMut};
use std::convert::TryInto;
use super::codec::TlsRecordCodec;
use super::diffie_helman::DiffieHellmanGroup;

use tokio::codec::Framed;
use super::hmac::{hkdf_expand, hkdf_extract};
use super::digest::{Digest, DigestAlgorithm};
use tokio::stream::{Stream};
use std::pin::Pin;


#[derive(Debug, Clone)]
pub struct BytesCursor<'a> {
    pub pos: usize,
    pub end: usize,
    bytes: &'a BytesMut,
}

impl<'a> Buf for BytesCursor<'a> {
    fn advance(&mut self, cnt: usize) {
        if self.pos + cnt > self.end {
            panic!("Cannot advance past end");
        }
        self.pos += cnt;
    }

    fn remaining(&self) -> usize {
        return self.end - self.pos;
    }

    fn bytes(&self) -> &[u8] {
        return &self.bytes.as_ref()[self.pos..self.end];
    }
}

impl<'a> BytesCursor<'a> {
    pub fn from_bytes_mut(bytes: &'a BytesMut) -> BytesCursor<'a>{
        BytesCursor {
            pos: 0,
            end: bytes.len(),
            bytes: bytes,
        }
    }

    pub fn slice(&self, start: usize, end: usize) -> BytesCursor<'a> {
        assert!(self.pos + start <= self.end, "cannot set start past end of cursor");
        assert!(self.pos + end <= self.end, "cannot set end past end of cursor");
        assert!(start <= end, "Cannot set end before start");
        BytesCursor {
            pos: self.pos + start,
            end: self.pos + end,
            bytes: self.bytes,
        }
    }
}

trait RecordStream : Stream<Item=Result<Record, ParseError>> + Sink<Record, Error=std::io::Error> {}

impl RecordStream for Framed<TcpStream, TlsRecordCodec> {}

fn hkdf_expand_label(digest_algorithm: DigestAlgorithm, secret: &[u8], label: &[u8], context: &[u8], length: usize) -> Vec<u8> {
    let mut hkdf_label: Vec<u8> = vec!();
    let mut final_label = b"tls13 ".to_vec();
    final_label.extend(label);
    hkdf_label.put_u16_be(length.try_into().unwrap());
    hkdf_label.put_u8(final_label.len().try_into().unwrap());
    hkdf_label.put_slice(&final_label);
    hkdf_label.put_u8(context.len().try_into().unwrap());
    hkdf_label.put_slice(context);
    hkdf_expand(digest_algorithm, secret, &hkdf_label, length)
}

fn derive_secret(digest_algorithm: DigestAlgorithm, secret: &[u8], label: &[u8], transcript_hash_or_empty: &[u8], length: usize) -> Vec<u8> {
    hkdf_expand_label(digest_algorithm, secret, label, transcript_hash_or_empty, length)
}

trait TlsGenerator {
    fn generate_bytes(&self) -> Vec<u8>;
    fn generate_dh_key(&self, dh_algorithm: &DiffieHellmanGroup) -> Vec<u8>;
}

struct RandomTlsGenerator {
}

fn generate_num(num: usize) -> Vec<u8> {
    let mut rng = thread_rng();
    let mut result = vec![0;num];
    rng.fill_bytes(&mut result);
    return result
}

impl TlsGenerator for RandomTlsGenerator {
    fn generate_bytes(&self) -> Vec<u8> {
        generate_num(32)
    }

    fn generate_dh_key(&self, dh_algorithm: &DiffieHellmanGroup) -> Vec<u8> {
        generate_num(dh_algorithm.private_key_bytes())
    }
}

struct TlsClientConfig {
    dh_groups: Vec<DiffieHellmanGroup>,
    cipher_suites: Vec<CipherSuite>,
    signature_algorithms: Vec<SignatureScheme>,

    keyshare_dh_groups: Option<Vec<DiffieHellmanGroup>>,
    cookie: Option<Vec<u8>>,
    signature_algorithms_cert: Option<Vec<SignatureScheme>>,
    psk_key_exchange_modes: Option<Vec<PskKeyExchangeMode>>,
    server_name: Option<Vec<u8>>,
    session_ticket: Option<Vec<u8>>,
    send_renegotiation_info: bool,
    record_size_limit: Option<u16>,
}

enum TlsState {
    Initial,
    ServerHelloReceived
}

struct TlsClient {
    config: TlsClientConfig,
    framed: Pin<Box<dyn RecordStream>>,
    transcript_hash: Option<Box<dyn Digest>>,
    secret: Option<Vec<u8>>,
    dh_private: Option<Vec<u8>>,
    random_gen: Box<dyn TlsGenerator>,
}

impl TlsClient {
    pub fn new(config: TlsClientConfig, stream: Pin<Box<dyn RecordStream>>) -> TlsClient {
        let mut random_gen = thread_rng();
        let mut random_bytes: [u8; 32] = [0;32];
        random_gen.fill_bytes(&mut random_bytes);
        TlsClient {
            config: config,
            framed: stream,
            transcript_hash: None,
            secret: None,
            dh_private: None,
            random_gen: Box::new(RandomTlsGenerator {}),
        }
    }

    #[cfg(test)]
    pub fn update_random_gen(&mut self, random_gen: Box<dyn TlsGenerator>) {
        self.random_gen = random_gen;
    }

    pub async fn send_client_hello(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let mut random_gen = thread_rng();
        let mut random_bytes: [u8; 32] = [0;32];
        random_gen.fill_bytes(&mut random_bytes);
        let dh = self.config.keyshare_dh_groups.as_ref().unwrap()[0];
        self.dh_private = Some(self.random_gen.generate_dh_key(&dh));
        let ecdhe_public_key = dh.generate_public(&self.dh_private.as_ref().unwrap());

        let mut extensions: Vec<ClientHelloExtension> = vec!();

        if self.config.server_name.is_some() {
            extensions.push(ClientHelloExtension::ServerName(
                ServerName {
                    hostname: self.config.server_name.as_ref().unwrap().clone()
                }
            ));
        }
        if self.config.send_renegotiation_info {
            extensions.push(ClientHelloExtension::RenegotiationInfo(RenegotiationInfo {
                renegotiated_connection: vec!(),
            }));
        }
        extensions.push(ClientHelloExtension::SupportedGroups(
            SupportedGroups {
                groups: self.config.dh_groups.clone(),
            }
        ));
        if self.config.session_ticket.is_some() {
            extensions.push(ClientHelloExtension::SessionTicket(SessionTicket {
                session_ticket: self.config.session_ticket.as_ref().unwrap().clone(),
            }));
        }
        if self.config.keyshare_dh_groups.is_some() {
            extensions.push(ClientHelloExtension::KeyShare(KeyShareClientHello {
                client_shares: self.config.keyshare_dh_groups.as_ref().unwrap().iter().map(|dh_group| {
                    let private_key = self.random_gen.generate_dh_key(dh_group);
                    let public_key = dh_group.generate_public(&private_key);
                    KeyShareEntry {
                        group: *dh_group,
                        key_exchange: public_key,
                    }
                }).collect()
            }))
        }
        extensions.push(ClientHelloExtension::SupportedVersions(SupportedVersionsClientHello {}));
        extensions.push(ClientHelloExtension::SignatureAlgorithms(SignatureAlgorithms {
            supported_signature_algorithms: self.config.signature_algorithms.clone()
        }));
        if self.config.signature_algorithms_cert.is_some() {
            extensions.push(ClientHelloExtension::SignatureAlgorithmsCert(SignatureAlgorithmsCert {
                supported_signature_algorithms: self.config.signature_algorithms_cert.as_ref().unwrap().clone(),
            }));
        }
        if self.config.psk_key_exchange_modes.is_some() {
            extensions.push(ClientHelloExtension::PskKeyExchangeModes(PskKeyExchangeModes {
                ke_modes: self.config.psk_key_exchange_modes.as_ref().unwrap().clone(),
            }))
        }
        if self.config.record_size_limit.is_some() {
            extensions.push(ClientHelloExtension::RecordSizeLimit(RecordSizeLimit {
                record_size_limit: self.config.record_size_limit.unwrap(),
            }))
        }
        

        let client_hello = Record::Handshake(
            Handshake::ClientHello(
                ClientHello {
                    random: random_bytes,
                    legacy_session_id: vec!(),
                    cipher_suites: self.config.cipher_suites.clone(),
                    extensions: extensions,
                }
            )
        );

        println!("HELLO: {:?}", client_hello);

        //self.transcript_hash.update(&client_hello.to_transcript_bytes());

        Ok(self.framed.send(client_hello).await?)
    }

    pub async fn process_server_hello(&mut self) -> Result<ServerHello, Box<dyn std::error::Error>> {
        let message = self.framed.next().await;
        match message {
            Some(Ok(record)) => {
                println!("Success: {:x?}", record);
                //self.transcript_hash.update(&record.to_transcript_bytes());
                match record {
                    Record::Handshake(Handshake::ServerHello(server_hello)) => {
                        return Ok(server_hello);
                    },
                    _ => {
                        let tmp: Result<ServerHello, Box<dyn std::error::Error>> = 
                            Err(Box::new(ParseError::Error("Unknown Error in process_server_hello".to_string())));

                        return tmp;
                    }
                }
            },
            Some(Err(error)) => println!("Error: {:?}", error),
            None => println!("NONE!"),
        };
        let tmp: Result<ServerHello, Box<dyn std::error::Error>> = Err(Box::new(ParseError::Error("Unknown Error in process_server_hello".to_string())));
        return tmp;
    }

    async fn run(&mut self) {
        //self.secret = hkdf_extract(self.digest_algorithm, &self.secret, &vec![0;self.digest_algorithm.result_size()]); // Early Secret

        self.send_client_hello().await.unwrap();
        let server_hello = self.process_server_hello().await.unwrap();

        //let handshake_salt = derive_secret(self.digest_algorithm, &self.secret, b"derived", b"", self.digest_algorithm.result_size());
        let mut keyshare: Option<KeyShareServerHello> = None;
        for extension in server_hello.extensions {
            match extension {
                ServerHelloExtension::KeyShare(ks) => {
                    keyshare = Some(ks);
                },
                _ => {
                    return;
                }
            }
        }
        // let curve = ElipticCurve::secp256r1();
        // let server_public_point = curve.try_point_from_bytes(&keyshare.unwrap().server_share.key_exchange).unwrap();
        // let ecdhe_private_key = BigInt::from_bytes_be(Sign::Plus, &tls_client.dh_private);
        // let shared_point = curve.multiply(&ecdhe_private_key, &server_public_point);
        // tls_client.secret = hkdf_extract::<Sha384>(&tls_client.secret.clone(), &shared_point.x.to_bytes_be().1);

    }
}

async fn run() {
    let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default()).unwrap();
    let response = resolver.lookup_ip("www.example.com.").unwrap();
    let address = response.iter().next().expect("no addresses returned!");
    let socket_address = SocketAddr::new(address, 443);
    let client = TcpStream::connect(&socket_address).await.unwrap();
    let framed = super::codec::tls_framed(client);
    let config = TlsClientConfig {
        cipher_suites: vec!(CipherSuite::TlsAes128GcmSha256, CipherSuite::TlsAes256GcmSha384),
        dh_groups: vec!(
            DiffieHellmanGroup::Secp256r1
        ),
        keyshare_dh_groups: Some(vec!(
            DiffieHellmanGroup::Secp256r1,
        )),
        signature_algorithms: vec!(
            SignatureScheme::RsaPkcs1Sha256,
            SignatureScheme::RsaPssRsaeSha256,
            SignatureScheme::EcdsaSecp256r1Sha256,
        ),
        signature_algorithms_cert: Some(vec!(
            SignatureScheme::RsaPkcs1Sha256,
            SignatureScheme::RsaPssRsaeSha256,
            SignatureScheme::EcdsaSecp256r1Sha256,
        )),
        cookie: None,
        psk_key_exchange_modes: None,
        record_size_limit: None,
        send_renegotiation_info: false,
        server_name: Some(b"www.google.com".to_vec()),
        session_ticket: None,
    };
    let mut tls_client = TlsClient::new(config, Box::pin(framed));
    tls_client.run().await;
}

pub fn connect() -> Result<(), tokio::io::Error> {

    tokio::runtime::Runtime::new().unwrap().block_on(run());
    // Write some data.
    // stream.write_all(b"hello world!").await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use tokio::prelude::*;
    use std::pin::Pin;
    use core::task::{Context, Poll};
    use std::collections::VecDeque;
    use super::super::messages::*;
    use super::super::cipher::CipherSuite;
    use super::super::eliptic_curve::secp256r1::ElipticCurve;
    use super::super::signature::SignatureScheme;
    use super::DiffieHellmanGroup;
    use num_bigint::{Sign, BigInt};
    

    struct RecordStreamMock {
        outbound_messages: VecDeque<Record>,
        inbound_messages: VecDeque<Record>
    }

    impl Sink<Record> for RecordStreamMock {
        type Error=std::io::Error;
        fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
        fn start_send(self: Pin<&mut Self>, item: Record) -> Result<(), Self::Error> {
            self.get_mut().outbound_messages.push_back(item);
            Ok(())
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    impl Stream for RecordStreamMock {
        type Item=Result<Record, ParseError>;
        fn poll_next(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Self::Item>> {
            let front = self.get_mut().inbound_messages.pop_front();
            match front {
                Some(item) => Poll::Ready(Some(Ok(item))),
                None => Poll::Pending,
            }
        }
    }

    impl super::RecordStream for RecordStreamMock {
        
    }

    struct MockTlsGenerator {
        
    }

    impl super::TlsGenerator for MockTlsGenerator {
        fn generate_bytes(&self) -> Vec<u8> {
            vec!(
                0xcb, 0x34, 0xec, 0xb1, 0xe7, 0x81, 0x63, 0xba, // Random bytes
                0x1c, 0x38, 0xc6, 0xda, 0xcb, 0x19, 0x6a, 0x6d, // Random bytes
                0xff, 0xa2, 0x1a, 0x8d, 0x99, 0x12, 0xec, 0x18, // Random bytes
                0xa2, 0xef, 0x62, 0x83, 0x02, 0x4d, 0xec, 0xe7, // Random bytes
            )
        }

        fn generate_dh_key(&self, _dh_algorithm: &DiffieHellmanGroup) -> Vec<u8> {
            vec!(
                0x49, 0xaf, 0x42, 0xba, 0x7f, 0x79, 0x94, 0x85,
                0x2d, 0x71, 0x3e, 0xf2, 0x78, 0x4b, 0xcb, 0xca,
                0xa7, 0x91, 0x1d, 0xe2, 0x6a, 0xdc, 0x56, 0x42,
                0xcb, 0x63, 0x45, 0x40, 0xe7, 0xea, 0x50, 0x05,
            )
        }
    }

    #[test]
    fn test_initial_connection() {
        let message = Record::Handshake(
            Handshake::ClientHello(
                ClientHello {
                    random: [
                        0xcb, 0x34, 0xec, 0xb1, 0xe7, 0x81, 0x63, 0xba, // Random bytes
                        0x1c, 0x38, 0xc6, 0xda, 0xcb, 0x19, 0x6a, 0x6d, // Random bytes
                        0xff, 0xa2, 0x1a, 0x8d, 0x99, 0x12, 0xec, 0x18, // Random bytes
                        0xa2, 0xef, 0x62, 0x83, 0x02, 0x4d, 0xec, 0xe7, // Random bytes
                    ],
                    legacy_session_id: vec!(),
                    cipher_suites: vec!(
                        CipherSuite::TlsAes128GcmSha256,
                        CipherSuite::TlsChacha20Poly1305Sha256,
                        CipherSuite::TlsAes256GcmSha384
                    ),
                    extensions: vec!(
                        ClientHelloExtension::ServerName(
                            ServerName {
                                hostname: b"server".to_vec()
                            }
                        ),
                        ClientHelloExtension::RenegotiationInfo(
                            RenegotiationInfo {
                                renegotiated_connection: vec!(),
                            }
                        ),
                        ClientHelloExtension::SupportedGroups(
                            SupportedGroups {
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
                            }
                        ),
                        ClientHelloExtension::SessionTicket(
                            SessionTicket {
                                session_ticket: vec!(),
                            }
                        ),
                        ClientHelloExtension::KeyShare(
                            KeyShareClientHello {
                                client_shares: vec!(
                                    KeyShareEntry {
                                        group: DiffieHellmanGroup::X25519,
                                        key_exchange: vec!(
                                            0x99, 0x38, 0x1d, 0xe5, 0x60, 0xe4, 0xbd, 0x43, // Key Share
                                            0xd2, 0x3d, 0x8e, 0x43, 0x5a, 0x7d, 0xba, 0xfe, // Key Share
                                            0xb3, 0xc0, 0x6e, 0x51, 0xc1, 0x3c, 0xae, 0x4d, // Key Share
                                            0x54, 0x13, 0x69, 0x1e, 0x52, 0x9a, 0xaf, 0x2c, // Key Share
                                        ),
                                    }
                                )
                            }
                        ),
                        ClientHelloExtension::SupportedVersions(
                            SupportedVersionsClientHello {}
                        ),
                        ClientHelloExtension::SignatureAlgorithms(
                            SignatureAlgorithms {
                                supported_signature_algorithms: vec! {
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
                                }
                            }
                        ),
                        ClientHelloExtension::PskKeyExchangeModes(
                            PskKeyExchangeModes {
                                ke_modes: vec!(PskKeyExchangeMode::PskDheKe),
                            }
                        ),
                        ClientHelloExtension::RecordSizeLimit(
                            RecordSizeLimit {
                                record_size_limit: 0x4001,
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
            0x00, 0x0b, // Plugin Length
            0x00, 0x09, // Server Name List Length
            0x00, // name_type (host_name)
            0x00, 0x06, // HostName length
            0x73, 0x65, 0x72, 0x76, 0x65, 0x72, // "server"

            0xff, 0x01, // Renegotiated Connection
            0x00, 0x01, // Plugin Length
            0x00,       // Renegotiated Connection Length
                        // Renegotiated Connection Data (empty)

            0x00, 0x0a, // Supported Groups
            0x00, 0x14, // Plugin Length
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
            0x00, 0x26, // Plugin Length
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
            0x00, 0x20, // Plugin Length
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
            0x00, 0x02, // Plugin Length
            0x01, // PSK Key Exchange Modes Length
            0x01, // psk_dhe_ke

            0x00, 0x1c, // Record Size Limit
            0x00, 0x02, // Plugin Length
            0x40, 0x01, // 16385
        ));
    }
}