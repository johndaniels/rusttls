use tokio::net::TcpStream;
use tokio::prelude::*;
use trust_dns_resolver::Resolver;
use trust_dns_resolver::config::*;
use rand::prelude::*;
use std::net::{SocketAddr};
use super::messages::*;
use super::signature::SignatureScheme;
use super::cipher_suite::{CipherSuite};
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

#[derive(Debug, Clone)]
struct TlsSecrets {
    master_secret: Option<Vec<u8>>,
    client_traffic_secret: Option<Vec<u8>>,
    server_traffic_secret: Option<Vec<u8>>,
    client_write_iv: Option<Vec<u8>>,
    server_write_iv: Option<Vec<u8>>,
    client_write_key: Option<Vec<u8>>,
    server_write_key: Option<Vec<u8>>,
    client_sequence_number: Option<u64>,
    server_sequence_number: Option<u64>,

    
    exporter_master_secret: Option<Vec<u8>>,
    resumption_master_secret: Option<Vec<u8>>,
    
}

impl TlsSecrets {
    fn new() -> TlsSecrets {
        TlsSecrets {
            master_secret: None,
            client_traffic_secret: None,
            server_traffic_secret: None,
            exporter_master_secret: None,
            resumption_master_secret: None,
            client_write_iv: None,
            server_write_iv: None,
            client_write_key: None,
            server_write_key: None,
            client_sequence_number: None,
            server_sequence_number: None,
        }
    }
}

struct TlsClient {
    config: TlsClientConfig,
    framed: Pin<Box<dyn RecordStream>>,
    /// Used before we know what our hash algorithm is
    transcript_bytes: Vec<u8>,
    /// Used after we know what our hash algorithm is
    transcript_hash: Option<Box<dyn Digest>>,
    cipher_suite: Option<CipherSuite>,
    dh_private: Option<Vec<u8>>,
    random_gen: Box<dyn TlsGenerator>,
    secrets: Option<TlsSecrets>
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
            dh_private: None,
            random_gen: Box::new(RandomTlsGenerator {}),
            cipher_suite: None,
            transcript_bytes: vec!(),
            secrets: None,
        }
    }

    #[cfg(test)]
    pub fn set_random_gen(&mut self, random_gen: Box<dyn TlsGenerator>) {
        self.random_gen = random_gen;
    }

    pub async fn send_client_hello(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let random_bytes = self.random_gen.generate_bytes();
        let dh = self.config.keyshare_dh_groups.as_ref().unwrap()[0];
        self.dh_private = Some(self.random_gen.generate_dh_key(&dh));
        let ecdhe_public_key = dh.generate_public(&self.dh_private.as_ref().unwrap());

        let mut extensions: Vec<Extension> = vec!();

        if self.config.server_name.is_some() {
            extensions.push(Extension::ServerName(
                ServerName {
                    hostname: self.config.server_name.as_ref().unwrap().clone()
                }
            ));
        }
        if self.config.send_renegotiation_info {
            extensions.push(Extension::RenegotiationInfo(RenegotiationInfo {
                renegotiated_connection: vec!(),
            }));
        }
        extensions.push(Extension::SupportedGroups(
            SupportedGroups {
                groups: self.config.dh_groups.clone(),
            }
        ));
        if self.config.session_ticket.is_some() {
            extensions.push(Extension::SessionTicket(SessionTicket {
                session_ticket: self.config.session_ticket.as_ref().unwrap().clone(),
            }));
        }
        if self.config.keyshare_dh_groups.is_some() {
            extensions.push(Extension::KeyShare(KeyShare::ClientHello {
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
        extensions.push(Extension::SupportedVersions(SupportedVersions::ClientHello));
        extensions.push(Extension::SignatureAlgorithms(SignatureAlgorithms {
            supported_signature_algorithms: self.config.signature_algorithms.clone()
        }));
        if self.config.signature_algorithms_cert.is_some() {
            extensions.push(Extension::SignatureAlgorithmsCert(SignatureAlgorithmsCert {
                supported_signature_algorithms: self.config.signature_algorithms_cert.as_ref().unwrap().clone(),
            }));
        }
        if self.config.psk_key_exchange_modes.is_some() {
            extensions.push(Extension::PskKeyExchangeModes(PskKeyExchangeModes {
                ke_modes: self.config.psk_key_exchange_modes.as_ref().unwrap().clone(),
            }))
        }
        if self.config.record_size_limit.is_some() {
            extensions.push(Extension::RecordSizeLimit(RecordSizeLimit {
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

        self.transcript_bytes.extend(&client_hello.to_transcript_bytes());
        //self.transcript_hash.update(&client_hello.to_transcript_bytes());

        Ok(self.framed.send(client_hello).await?)
    }

    pub async fn parse_server_hello(&mut self) -> Result<ServerHello, Box<dyn std::error::Error>> {

        let message = self.framed.next().await;
        println!("HELLO!!!");

        match message {
            Some(Ok(record)) => {
                println!("Success: {:x?}", record);
                let temp_bytes = &record.to_transcript_bytes();
                match record {
                    Record::Handshake(Handshake::ServerHello(server_hello)) => {
                        self.transcript_bytes.extend(temp_bytes);
                        return Ok(server_hello);
                    },
                    _ => {
                        let tmp: Result<ServerHello, Box<dyn std::error::Error>> = 
                            Err(Box::new(ParseError::Error("Unknown Error in parse_server_hello".to_string())));

                        return tmp;
                    }
                }
            },
            Some(Err(error)) => println!("Error: {:?}", error),
            None => println!("NONE!"),
        };
        let tmp: Result<ServerHello, Box<dyn std::error::Error>> = Err(Box::new(ParseError::Error("Unknown Error in parse_server_hello".to_string())));
        return tmp;
    }

    fn create_handshake_secret(&mut self, shared_key: &[u8]) {
        println!("Shared key: {:x?}", shared_key);
        let digest_algorithm = self.cipher_suite.as_ref().unwrap().get_digest_algorithm();
        let salt = vec![0;digest_algorithm.result_size()];
        let psk = vec![0;digest_algorithm.result_size()];
        let early_secret = hkdf_extract(digest_algorithm, &salt, &psk);
        println!("Early Secret: {:x?}", early_secret);
        let mut digest = digest_algorithm.create();
        let empty_hash = digest.finalize();
        let derived = derive_secret(digest_algorithm, &early_secret, b"derived", &empty_hash, digest_algorithm.result_size());
        println!("Derived Secret: {:x?}", derived);
        let master_secret = hkdf_extract(digest_algorithm, &derived, shared_key);
        println!("Master Secret: {:x?}", master_secret);
        let transcript_hash = self.transcript_hash.as_ref().unwrap().finalize_copy();
        println!("Transcript Hash: {:x?}", transcript_hash);
        let client_handshake_secret = derive_secret(digest_algorithm, &master_secret, b"c hs traffic", &transcript_hash, digest_algorithm.result_size());
        println!("Client Secret: {:x?}", client_handshake_secret);
        let server_handshake_secret = derive_secret(digest_algorithm, &master_secret, b"s hs traffic", &transcript_hash, digest_algorithm.result_size());
        println!("Server Secret: {:x?}", server_handshake_secret);
        let cipher_suite = self.cipher_suite.as_ref().unwrap();
        let client_write_key = hkdf_expand_label(digest_algorithm, &client_handshake_secret, b"key", b"", cipher_suite.key_len());
        println!("Client Write Key: {:x?}", client_write_key);
        let client_write_iv = hkdf_expand_label(digest_algorithm, &client_handshake_secret, b"iv", b"", cipher_suite.iv_len());
        println!("Client Write IV: {:x?}", client_write_iv);
        let server_write_key = hkdf_expand_label(digest_algorithm, &server_handshake_secret, b"key", b"", cipher_suite.key_len());
        println!("Server Write Key: {:x?}", server_write_key);
        let server_write_iv = hkdf_expand_label(digest_algorithm, &server_handshake_secret, b"iv", b"", cipher_suite.iv_len());
        println!("Server Write Iv: {:x?}", server_write_iv);
        let secrets = TlsSecrets {
            master_secret: Some(master_secret),
            client_traffic_secret: Some(client_handshake_secret),
            server_traffic_secret: Some(server_handshake_secret),
            exporter_master_secret: None,
            resumption_master_secret: None,
            client_write_key: Some(client_write_key),
            client_write_iv: Some(client_write_iv),
            server_write_key: Some(server_write_key),
            server_write_iv: Some(server_write_iv),
            client_sequence_number: Some(0),
            server_sequence_number: Some(0),
        };
        self.secrets = Some(secrets);
    }

    fn process_server_hello(&mut self, server_hello: ServerHello) {
        let mut key_exchange = None;
        for extension in server_hello.extensions {
            match extension {
                Extension::KeyShare(KeyShare::ServerHello{server_share}) => {
                    key_exchange = Some(server_share);
                },
                _ => {}
            }
        }
        let key_exchange = key_exchange.unwrap();
        let shared_key = key_exchange.group.compute(&self.dh_private.as_ref().unwrap(), &key_exchange.key_exchange);
        self.cipher_suite = Some(server_hello.cipher_suite);
        self.transcript_hash = Some(self.cipher_suite.unwrap().get_digest_algorithm().create());
        self.transcript_hash.as_mut().unwrap().update(&self.transcript_bytes);
        self.transcript_bytes.clear();
        self.create_handshake_secret(&shared_key);
    }

    async fn run(&mut self) {
        //self.secret = hkdf_extract(self.digest_algorithm, &self.secret, &vec![0;self.digest_algorithm.result_size()]); // Early Secret

        self.send_client_hello().await.unwrap();
        let server_hello = self.parse_server_hello().await.unwrap();
        self.process_server_hello(server_hello);
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
    use core::task::{Context, Poll, Waker};
    use std::collections::VecDeque;
    use super::*;
    use super::super::signature::SignatureScheme;
    use super::DiffieHellmanGroup;
    use futures::task::{LocalSpawnExt};
    use std::rc::Rc;
    use std::cell::RefCell;

    #[derive(Clone)]
    struct RecordStreamMock {
        outbound_messages: Rc<RefCell<VecDeque<Record>>>,
        inbound_messages: Rc<RefCell<VecDeque<Record>>>,
        waker: Rc<RefCell<Option<Waker>>>,
    }

    impl Sink<Record> for RecordStreamMock {
        type Error=std::io::Error;
        fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
        fn start_send(self: Pin<&mut Self>, item: Record) -> Result<(), Self::Error> {
            self.get_mut().outbound_messages.borrow_mut().push_back(item);
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
            println!("POLL NEXT");
            let me = self.get_mut();
            let front = me.inbound_messages.borrow_mut().pop_front();
            match front {
                Some(item) => Poll::Ready(Some(Ok(item))),
                None => {
                    let mut test = me.waker.borrow_mut();
                    *test = Some(cx.waker().clone());
                    return Poll::Pending;
                },
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

        let random_gen = Box::new(MockTlsGenerator {});
        let config = TlsClientConfig {
            cipher_suites: vec!(
                CipherSuite::TlsAes128GcmSha256,
                CipherSuite::TlsChacha20Poly1305Sha256,
                CipherSuite::TlsAes256GcmSha384
            ),
            dh_groups: vec!(
                DiffieHellmanGroup::X25519,
                DiffieHellmanGroup::Secp256r1,
                DiffieHellmanGroup::Secp384r1,
                DiffieHellmanGroup::Secp521r1,
                DiffieHellmanGroup::Ffdhe2048,
                DiffieHellmanGroup::Ffdhe3072,
                DiffieHellmanGroup::Ffdhe4096,
                DiffieHellmanGroup::Ffdhe6144,
                DiffieHellmanGroup::Ffdhe8192,
            ),
            keyshare_dh_groups: Some(vec!(
                DiffieHellmanGroup::X25519,
            )),
            signature_algorithms: vec!(
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
            ),
            signature_algorithms_cert: None,
            cookie: None,
            psk_key_exchange_modes: Some(vec!(PskKeyExchangeMode::PskDheKe)),
            record_size_limit: Some(0x4001),
            send_renegotiation_info: true,
            server_name: Some(b"server".to_vec()),
            session_ticket: Some(vec!()),
        };

        let internal_mock = RecordStreamMock {
            inbound_messages: Rc::new(RefCell::new(VecDeque::new())),
            outbound_messages: Rc::new(RefCell::new(VecDeque::new())),
            waker: Rc::new(RefCell::new(None)),
        };

        let stream_mock = Box::pin(internal_mock.clone());

        let client = Rc::new(RefCell::new(TlsClient::new(config, stream_mock.clone())));
        let tls_client = client.clone();
        let future = async move {
            tls_client.borrow_mut().set_random_gen(Box::new(MockTlsGenerator {}));
            tls_client.borrow_mut().run().await;
        };
        //futures::pin_mut!(future);
        //futures::executor::block_on(future);
        let mut pool = futures::executor::LocalPool::new();
        let mut spawner = pool.spawner();
        spawner.spawn_local(future).unwrap();
        pool.try_run_one();

        let server_message = Record::Handshake(Handshake::ServerHello(
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
        ));

        let server_bytes: Vec<u8> = server_hello_bytes();

        assert_eq!(server_bytes, server_message.to_bytes());
        stream_mock.inbound_messages.borrow_mut().push_back(server_message);
        stream_mock.waker.borrow_mut().as_ref().unwrap().wake_by_ref();

        let client_message = internal_mock.outbound_messages.borrow_mut().pop_front();
        println!("Client Message: {:?}", client_message);
        pool.run_until_stalled();

        let test = client.as_ptr();
        unsafe {
            println!("secrets: {:x?}", (*test).secrets);
        }

        let bytes = client_message.unwrap().to_bytes();

        assert_eq!(bytes, client_hello_bytes());
    }

    fn server_hello_bytes() -> Vec<u8> {
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

    fn client_hello_bytes() -> Vec<u8> {
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

    fn server_encrypted_extensions()  {

    }

    fn server_encrypted_extensions_bytes() -> Vec<u8> {
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