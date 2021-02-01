use binread::{BinRead, BinReaderExt, BinResult, Error};
/// Contents of the XrdXrootdMonTrace struct
///
/// See https://xrootd.slac.stanford.edu/doc/dev44/xrd_monitoring.htm#_Toc449036999
use std::io::SeekFrom;

use crate::mon_packets::mon_head::{Code, Header, PacketPayload};

/// XROOTD_MON_XXX constants
#[derive(Debug, BinRead, PartialEq)]
#[repr(u8)]
pub enum XrootdMon {
    /// File has been opened
    OPEN = 0x80,
    /// Details for a kXR_readv request
    READV = 0x90,
    /// Unpacked details for kXR_readv
    READU = 0x91,
    /// Application provided marker
    APPID = 0xa0,
    /// File has been closed
    CLOSE = 0xc0,
    /// Client has disconnected
    DISC = 0xd0,
    /// Window timing mark
    WINDOW = 0xe0,
    /// Read or write request
    READWRITE = 0x00,
}

#[derive(Debug, BinRead, PartialEq)]
#[repr(u8)]
pub enum XrootdMonDisc {
    /// Entry due to forced disconnect
    FORCED = 0x01,
    /// Entry for a bound path
    BOUNDP = 0x02,
}

#[derive(BinRead, Debug)]
#[br(big, assert(XrootdMon::APPID == xrd_mon))]
pub struct AppId {
    pub xrd_mon: XrootdMon,
    /// Up to 12 characters of application identification.
    #[br(pad_before = 3)]
    pub id: [u8; 12],
}

#[derive(BinRead, Debug)]
#[br(big, assert(XrootdMon::CLOSE == xrd_mon))]
pub struct Close {
    pub xrd_mon: XrootdMon,
    /// Number of bits `read_total` has been right shifted to fit into a 32-bit unsigned int.
    pub read_shift: u8,
    /// Number of bits `write_total` has been right shifted to fit into a 32-bit unsigned int.
    pub write_shift: u8,
    /// Scaled number of bytes read from the file.
    #[br(pad_before = 1)]
    pub read_total: u32,
    /// Scaled number of bytes written to the file.
    pub write_total: u32,
    /// The file path's dictionary ID ('d' map message).
    pub dict_id: u32,
}

#[derive(BinRead, Debug)]
#[br(big, assert(XrootdMon::DISC == xrd_mon))]
pub struct Disc {
    pub xrd_mon: XrootdMon,
    /// May contain XROOTD_MON_BOUNDP and XROOTD_MON_FORCED
    pub reason: XrootdMonDisc,
    /// Number of seconds that client was connected.
    #[br(pad_before = 8)]
    pub buflen: i32,
    /// The client's dictionary ID ('u' map message).
    pub dict_id: u32,
}

#[derive(BinRead, Debug)]
#[br(big, assert(XrootdMon::OPEN == xrd_mon))]
pub struct Open {
    // filesize are the last 7 bytes of the first 8 bytes...
    #[br(restore_position)]
    pub xrd_mon: XrootdMon,
    /// Size of the file in bytes.
    #[br(map = |x: u64| x & 0xffffffffffffff)]
    pub filesize: u64,
    /// The file path's dictionary ID ('d' map message).
    #[br(pad_before = 4)]
    pub dict_id: u32,
}

#[derive(BinRead, Debug)]
#[br(big)]
pub struct ReadWrite {
    #[br(calc = XrootdMon::READWRITE)]
    pub xrd_mon: XrootdMon,
    /// Read or write offset
    pub val: i64,
    /// Length of the read/write when non-negative/negative.
    pub bufflen: i32,
    /// The file path's dictionary ID ('d' map message).
    pub dict_id: u32,
}

#[derive(BinRead, Debug)]
#[br(big, assert(XrootdMon::READV == xrd_mon || XrootdMon::READU == xrd_mon))]
pub struct ReadVU {
    pub xrd_mon: XrootdMon,
    /// readv request identifier
    pub read_id: u8,
    /// Number of elements in the readv vector
    pub count: u16,
    #[br(pad_before = 4)]
    /// Length of the read.
    pub bufflen: i32,
    /// The file path's dictionary ID ('d' map message).
    pub dict_id: u32,
}

#[derive(BinRead, Debug)]
#[br(big, assert(XrootdMon::WINDOW == xrd_mon))]
pub struct Window {
    // server_id are the last 48 bits / 6 bytes of the first 8 bytes...
    #[br(restore_position)]
    pub xrd_mon: XrootdMon,
    /// Size of the file in bytes.
    #[br(map = |x: u64| x & 0xffffffffffff)]
    pub server_id: u64,
    /// Unix time of when the previous window ended.
    pub prev_end: i32,
    /// Unix time of when this window has started.
    pub this_start: i32,
}

#[derive(Debug)]
pub enum Trace {
    AppId(AppId),
    Close(Close),
    Disc(Disc),
    Open(Open),
    ReadWrite(ReadWrite),
    ReadVU(ReadVU),
    Window(Window),
}

#[derive(Debug)]
pub struct XrdXrootdMonBuff {
    pub hdr: Header,
    pub info: Vec<Trace>,
}

fn digest_one<R: BinReaderExt>(reader: &mut R) -> BinResult<Trace> {
    let xrd_mon: XrootdMon = reader.read_be()?;
    reader.seek(SeekFrom::Current(-1))?;
    match xrd_mon {
        XrootdMon::OPEN => Ok(Trace::Open(reader.read_be()?)),
        XrootdMon::READV | XrootdMon::READU => Ok(Trace::ReadVU(reader.read_be()?)),
        XrootdMon::APPID => Ok(Trace::AppId(reader.read_be()?)),
        XrootdMon::CLOSE => Ok(Trace::Close(reader.read_be()?)),
        XrootdMon::DISC => Ok(Trace::Disc(reader.read_be()?)),
        XrootdMon::WINDOW => Ok(Trace::Window(reader.read_be()?)),
        XrootdMon::READWRITE => Ok(Trace::ReadWrite(reader.read_be()?)),
    }
}

impl PacketPayload for XrdXrootdMonBuff {
    fn digest_payload<R: BinReaderExt>(header: Header, reader: &mut R) -> BinResult<Self> {
        assert_eq!(header.code, Code::FileIOTrace);
        let mut info: Vec<Trace> = vec![];
        loop {
            match digest_one(reader) {
                Ok(t) => info.push(t),
                // distinguish between error from EOF and error from parsing
                Err(x) => match x {
                    Error::Io(_) => break,
                    _ => return Err(x),
                },
            }
        }
        Ok(XrdXrootdMonBuff { hdr: header, info })
    }
}
