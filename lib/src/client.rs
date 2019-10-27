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

    server_finished_key: Option<Vec<u8>>,    
    client_finished_key: Option<Vec<u8>>,    
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
            server_finished_key: None,
            client_finished_key: None,
        }
    }

    fn create_for_handshake(shared_key: &[u8], transcript_digest: &dyn Digest, cipher_suite: &CipherSuite) -> TlsSecrets {
        println!("Shared key: {:x?}", shared_key);
        let digest_algorithm = cipher_suite.get_digest_algorithm();
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
        let transcript_hash = transcript_digest.finalize_copy();
        println!("Transcript Hash: {:x?}", transcript_hash);
        let client_handshake_secret = derive_secret(digest_algorithm, &master_secret, b"c hs traffic", &transcript_hash, digest_algorithm.result_size());
        println!("Client Secret: {:x?}", client_handshake_secret);
        let server_handshake_secret = derive_secret(digest_algorithm, &master_secret, b"s hs traffic", &transcript_hash, digest_algorithm.result_size());
        println!("Server Secret: {:x?}", server_handshake_secret);
        let client_write_key = hkdf_expand_label(digest_algorithm, &client_handshake_secret, b"key", b"", cipher_suite.key_len());
        println!("Client Write Key: {:x?}", client_write_key);
        let client_write_iv = hkdf_expand_label(digest_algorithm, &client_handshake_secret, b"iv", b"", cipher_suite.iv_len());
        println!("Client Write IV: {:x?}", client_write_iv);
        let server_write_key = hkdf_expand_label(digest_algorithm, &server_handshake_secret, b"key", b"", cipher_suite.key_len());
        println!("Server Write Key: {:x?}", server_write_key);
        let server_write_iv = hkdf_expand_label(digest_algorithm, &server_handshake_secret, b"iv", b"", cipher_suite.iv_len());
        println!("Server Write Iv: {:x?}", server_write_iv);
        let server_finished_key = hkdf_expand_label(digest_algorithm, &server_handshake_secret, b"finished", b"", digest_algorithm.result_size());
        println!("Server Finished Key : {:x?}", server_finished_key);
        let client_finished_key = hkdf_expand_label(digest_algorithm, &client_handshake_secret, b"finished", b"", digest_algorithm.result_size());
        println!("Client Finished Key : {:x?}", client_finished_key);
        TlsSecrets {
            master_secret: Some(master_secret),
            client_traffic_secret: Some(client_handshake_secret),
            server_traffic_secret: Some(server_handshake_secret),
            exporter_master_secret: None,
            resumption_master_secret: None,
            client_write_key: Some(client_write_key),
            client_write_iv: Some(client_write_iv),
            server_write_key: Some(server_write_key),
            server_write_iv: Some(server_write_iv),
            server_finished_key: Some(server_finished_key),
            client_finished_key: Some(client_finished_key),
            client_sequence_number: Some(0),
            server_sequence_number: Some(0),
            
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
                    hostname: Some(self.config.server_name.as_ref().unwrap().clone())
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
        let secrets = TlsSecrets::create_for_handshake(shared_key, self.transcript_hash.as_ref().unwrap().as_ref(), self.cipher_suite.as_ref().unwrap());
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
    use bytes::{Buf, BufMut};
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
    use super::super::messages::tests::{
        server_hello, client_hello, client_hello_bytes, server_hello_bytes,
        server_encrypted_extensions, server_finished, server_certificate, server_certificate_verify,
    };

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

        let server_message = server_hello();

        let server_bytes: Vec<u8> = server_hello_bytes();

        assert_eq!(server_bytes, server_message.to_bytes());
        stream_mock.inbound_messages.borrow_mut().push_back(server_message);
        stream_mock.waker.borrow_mut().as_ref().unwrap().wake_by_ref();

        let client_message = internal_mock.outbound_messages.borrow_mut().pop_front().unwrap();
        println!("Client Message: {:?}", client_message);
        pool.run_until_stalled();
        
        let private_key = vec!(
            0xb1, 0x58, 0x0e, 0xea, 0xdf, 0x6d, 0xd5, 0x89,
            0xb8, 0xef, 0x4f, 0x2d, 0x56, 0x52, 0x57, 0x8c,
            0xc8, 0x10, 0xe9, 0x98, 0x01, 0x91, 0xec, 0x8d,
            0x05, 0x83, 0x08, 0xce, 0xa2, 0x16, 0xa2, 0x1e,
        );
        let key_share = vec!(
            0x99, 0x38, 0x1d, 0xe5, 0x60, 0xe4, 0xbd, 0x43, // Key Share
            0xd2, 0x3d, 0x8e, 0x43, 0x5a, 0x7d, 0xba, 0xfe, // Key Share
            0xb3, 0xc0, 0x6e, 0x51, 0xc1, 0x3c, 0xae, 0x4d, // Key Share
            0x54, 0x13, 0x69, 0x1e, 0x52, 0x9a, 0xaf, 0x2c, // Key Share
        );
        let shared_key = DiffieHellmanGroup::X25519.compute(&private_key, &key_share);

        let mut transcript_hash = super::super::digest::sha256::Sha256::new();
        transcript_hash.update(&client_hello().to_transcript_bytes());
        transcript_hash.update(&server_hello().to_transcript_bytes());

        let server_secrets = TlsSecrets::create_for_handshake(&shared_key, &transcript_hash, &CipherSuite::TlsAes128GcmSha256);
        let encrypted_extensions: Handshake  = server_encrypted_extensions();
        let certificate: Handshake = server_certificate();
        let certificate_verify: Handshake = server_certificate_verify();
        let finished = server_finished();

        let mut transcript_bytes: Vec<u8> = vec!();
        encrypted_extensions.write_to_buffer(&mut transcript_bytes);
        certificate.write_to_buffer(&mut transcript_bytes);
        certificate_verify.write_to_buffer(&mut transcript_bytes);
        transcript_hash.update(&transcript_bytes);
        let transcript_hash_result = transcript_hash.finalize();
        println!("Transcript Hash: {:x?}", transcript_hash_result);
        let finished_bytes = super::super::hmac::hmac_hash(DigestAlgorithm::Sha256, &server_secrets.server_finished_key.unwrap(), &transcript_hash_result);
        println!("Finished Bytes: {:x?}", finished_bytes);
        
        let mut plaintext = transcript_bytes.clone();
        finished.write_to_buffer(&mut plaintext);
        plaintext.push(0x16);
        println!("Transcript Bytes Len: {:?}", plaintext.len());
        let mut additional_data = vec!(0x17, 0x03, 0x03);
        additional_data.put_u16_be((plaintext.len() + 16).try_into().unwrap());
        let result = CipherSuite::TlsAes128GcmSha256.aead(
            &server_secrets.server_write_iv.unwrap(),
            &server_secrets.server_write_key.unwrap(),
            &additional_data,
            &plaintext);
        let mut full_message: Vec<u8> = vec!();
        full_message.put_slice(&additional_data);
        full_message.put_slice(&result.ciphertext);
        println!("Tag: {:x?}", result.tag);
        println!("Full message: {:?} {:x?}", full_message.len(), full_message);


        let test = client.as_ptr();
        unsafe {
            //println!("secrets: {:x?}", (*test).secrets);
        }

        let bytes = client_message.to_bytes();

        assert_eq!(bytes, client_hello_bytes());
    }

    

    
}