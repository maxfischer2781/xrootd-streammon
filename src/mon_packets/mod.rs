use crate::mon_packets::mon_head::PacketPayload;
use binread::{BinReaderExt, BinResult, Error};

pub mod mon_head;
pub mod mon_map;
pub mod mon_trace;

enum Packet {
    Trace(mon_trace::XrdXrootdMonBuff),
}

impl Packet {
    /// Load a packet from binary data provided by a `reader`
    fn from_data<R: BinReaderExt>(reader: &mut R) -> BinResult<Self> {
        let header: mon_head::Header = reader.read_be()?;
        match header.code {
            mon_head::Code::FileIOTrace => Ok(Self::Trace(
                mon_trace::XrdXrootdMonBuff::digest_payload(header, reader)?,
            )),
            _ => Err(Error::AssertFail {
                pos: 0,
                message: format!("Unimplemented packet Code {:?}", header.code),
            }),
        }
    }
}
