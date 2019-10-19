use tokio::net::TcpStream;
use tokio::prelude::*;
use trust_dns_resolver::Resolver;
use trust_dns_resolver::config::*;
use rand::prelude::*;
use std::net::{SocketAddr};
use messages::*;
use super::eliptic_curve::ElipticCurve;
use num_bigint::{Sign, BigInt};
use bytes::{Buf, BufMut, BytesMut};
use std::convert::TryInto;

use tokio::codec::Framed;
use super::hmac::{hkdf_expand, hkdf_extract};
use super::digest::sha384::Sha384;
use super::digest::{Digest, DigestAlgorithm};

mod messages;
mod codec;

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
    fn from_bytes_mut(bytes: &'a BytesMut) -> BytesCursor<'a>{
        BytesCursor {
            pos: 0,
            end: bytes.len(),
            bytes: bytes,
        }
    }

    fn slice(&self, start: usize, end: usize) -> BytesCursor<'a> {
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

fn hkdf_expand_label(secret: &[u8], label: &[u8], context: &[u8], length: usize) -> Vec<u8> {
    let mut hkdf_label: Vec<u8> = vec!();
    let mut final_label = b"tls13 ".to_vec();
    final_label.extend(label);
    hkdf_label.put_u16_be(length.try_into().unwrap());
    hkdf_label.put_u8(final_label.len().try_into().unwrap());
    hkdf_label.put_slice(&final_label);
    hkdf_label.put_u8(context.len().try_into().unwrap());
    hkdf_label.put_slice(context);
    hkdf_expand::<Sha384>(secret, &hkdf_label, length)
}

fn derive_secret(secret: &[u8], label: &[u8], transcript_hash_or_empty: &[u8], length: usize) -> Vec<u8> {
    hkdf_expand_label(secret, label, transcript_hash_or_empty, length)
}


enum TlsState {
    Initial,
    ServerHelloReceived
}

struct TlsClient {
    framed: Framed<TcpStream, codec::TlsRecordCodec>,
    transcript_hash: Box<dyn Digest>,
    secret: Vec<u8>,
    dh_private: Vec<u8>
}

impl TlsClient {
    pub async fn send_client_hello(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let mut random_gen = thread_rng();
        let mut random_bytes: [u8; 32] = [0;32];
        random_gen.fill_bytes(&mut random_bytes);
        let curve = ElipticCurve::secp256r1();
        let ecdhe_private_key = BigInt::from_bytes_be(Sign::Plus, &self.dh_private);
        let ecdhe_public_key = curve.multiply(ecdhe_private_key, &curve.g);

        let client_hello = Record::Handshake(
            Handshake::ClientHello(
                ClientHello {
                    random: random_bytes,
                    legacy_session_id: vec!(),
                    cipher_suites: vec!(CipherSuite::TlsAes128GcmSha256, CipherSuite::TlsAes256GcmSha384),
                    extensions: vec!(
                        ClientHelloExtension::SupportedVersions(
                            SupportedVersionsClientHello {}
                        ),
                        ClientHelloExtension::ServerName(
                            ServerName {
                                hostname: b"www.google.com".to_vec()
                            }
                        ),
                        ClientHelloExtension::SignatureAlgorithms(
                            SignatureAlgorithms {
                                supported_signature_algorithms: vec! {
                                    SignatureScheme::RsaPkcs1Sha256,
                                    SignatureScheme::RsaPssRsaeSha256,
                                    SignatureScheme::EcdsaSecp256r1Sha256,
                                }
                            }
                        ),
                        ClientHelloExtension::SignatureAlgorithmsCert(
                            SignatureAlgorithmsCert {
                                supported_signature_algorithms: vec! {
                                    SignatureScheme::RsaPkcs1Sha256,
                                    SignatureScheme::RsaPssRsaeSha256,
                                    SignatureScheme::EcdsaSecp256r1Sha256,
                                }
                            }
                        ),
                        ClientHelloExtension::SupportedGroups(
                            SupportedGroups {
                                groups: vec! {
                                    NamedGroup::Secp256r1
                                }
                            }
                        ),
                        ClientHelloExtension::KeyShare(
                            KeyShareClientHello {
                                client_shares: vec!(
                                    KeyShareEntry {
                                        group: NamedGroup::Secp256r1,
                                        key_exchange: curve.point_to_bytes(&ecdhe_public_key),
                                    }
                                )
                            }
                        )
                    )
                }
            )
        );

        self.transcript_hash.update(&client_hello.to_transcript_bytes());

        Ok(self.framed.send(client_hello).await?)
    }

    pub async fn process_server_hello(&mut self) -> Result<ServerHello, Box<dyn std::error::Error>> {
        let message = self.framed.next().await;
        match message {
            Some(Ok(record)) => {
                println!("Success: {:x?}", record);
                self.transcript_hash.update(&record.to_transcript_bytes());
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
}

async fn run() {
    let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default()).unwrap();
    let response = resolver.lookup_ip("www.example.com.").unwrap();
    let address = response.iter().next().expect("no addresses returned!");
    let socket_address = SocketAddr::new(address, 443);
    let client = TcpStream::connect(&socket_address).await.unwrap();
    let framed = codec::tls_framed(client);
    let dh_private = hex::decode("1234FFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551").unwrap();
    let mut tls_client = TlsClient {
        framed: framed,
        transcript_hash: Sha384::new(),
        secret: vec![0;Sha384::result_size()],
        dh_private: dh_private,
    };
    
    tls_client.secret = hkdf_extract::<Sha384>(&tls_client.secret.clone(), &vec![0;Sha384::result_size()]); // Early Secret

    tls_client.send_client_hello().await.unwrap();
    let server_hello = tls_client.process_server_hello().await.unwrap();
    let handshake_salt = derive_secret(&tls_client.secret.clone(), b"derived", b"", Sha384::result_size());
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
    let curve = ElipticCurve::secp256r1();
    let server_public_point = curve.try_point_from_bytes(&keyshare.unwrap().server_share.key_exchange).unwrap();
    let ecdhe_private_key = BigInt::from_bytes_be(Sign::Plus, &tls_client.dh_private);
    let shared_point = curve.multiply(ecdhe_private_key, &server_public_point);
    tls_client.secret = hkdf_extract::<Sha384>(&tls_client.secret.clone(), &shared_point.x.to_bytes_be().1);
}

pub fn connect() -> Result<(), tokio::io::Error> {

    tokio::runtime::Runtime::new().unwrap().block_on(run());
    // Write some data.
    // stream.write_all(b"hello world!").await?;
    Ok(())
}