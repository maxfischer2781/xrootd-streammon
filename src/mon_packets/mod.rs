use binread::BinReaderExt;

use crate::mon_packets::mon_head::{Code, PacketPayload, ParseError, XrdParseResult};

pub mod mon_head;
pub mod mon_map;
pub mod mon_trace;

enum Packet {
    Trace(mon_trace::XrdXrootdMonBuff),
    Map(mon_map::XrdXrootdMonMap),
}

impl Packet {
    /// Load a packet from binary data provided by a `reader`
    fn from_data<R: BinReaderExt>(reader: &mut R) -> XrdParseResult<Self> {
        let header: mon_head::Header = reader.read_be()?;
        match header.code {
            Code::FileIOTrace => Ok(Self::Trace(mon_trace::XrdXrootdMonBuff::digest_payload(
                header, reader,
            )?)),
            Code::ServerId
            | Code::PathDictId
            | Code::FileTransfer
            | Code::AppDictId
            | Code::FilePurge
            | Code::UserDictId => Ok(Self::Map(mon_map::XrdXrootdMonMap::digest_payload(
                header, reader,
            )?)),
            _ => Err(ParseError::Generic(format!(
                "Unimplemented packet Code {:?}",
                header.code
            ))),
        }
    }
}
