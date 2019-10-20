use bytes::{BufMut, BytesMut, Buf};
use tokio::codec::{Encoder, Decoder, Framed};
use tokio::io::{AsyncRead, AsyncWrite};
use std::convert::TryInto;
use super::messages::{ParseError, Record, ReadFromBuffer, WriteToBuffer};
use super::client::BytesCursor;

pub fn tls_framed<T: AsyncRead + AsyncWrite>(io: T) -> Framed<T, TlsRecordCodec> {
    Framed::new(io, TlsRecordCodec {})
}

#[derive(Default)]
pub struct TlsRecordCodec {
}

impl Decoder for TlsRecordCodec {
    type Item = Record;
    type Error = super::messages::ParseError;
    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Record>, ParseError> {
        if src.remaining_mut() < 5 {
            return Ok(None);
        }
        let mut cursor = BytesCursor::from_bytes_mut(src);
        let message_type = cursor.get_u8();
        let tls_version = cursor.get_u16_be();
        if tls_version != 0x0303 {
            return Err(ParseError::Error("Invalid TLS Version when Parsing record".to_string()));
        }
        let length = cursor.get_u16_be();
        if cursor.remaining() < length.try_into().unwrap() {
            return Ok(None);
        }
        let end_position = 5 + length;
        let mut record_parse_cursor = BytesCursor::from_bytes_mut(src).slice(0, end_position.try_into().unwrap());
        let parsed = Record::read_from_buffer(&mut record_parse_cursor)?;
        src.advance(record_parse_cursor.pos);
        return Ok(Some(parsed));
    }
}

impl Encoder for TlsRecordCodec {
    type Item = Record;
    type Error = std::io::Error;
    fn encode(&mut self, item: Record, dst: &mut BytesMut) -> std::io::Result<()> {
        item.write_to_buffer(dst);
        return Ok(());
    }
}