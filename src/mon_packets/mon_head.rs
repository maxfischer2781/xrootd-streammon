use binread::{BinRead, BinReaderExt, BinResult};

#[derive(Debug, BinRead, PartialEq)]
#[repr(u8)]
pub enum Code {
    /// server identification sent by xrootd or the FRM
    ServerId = b'=',
    /// dictid of a user/path combination (xrootd only)
    PathDictId = b'd',
    /// file access events (xrootd only)
    FileEvent = b'f',
    /// dictid of a user/information combination (xrootd only)
    AppDictId = b'i',
    /// file purge event (FRM only)
    FilePurge = b'p',
    /// client redirect events (xrootd only)
    RedirectEvent = b'r',
    /// a file or I/O request trace (xrootd only)
    FileIOTrace = b't',
    /// dictid of the user login name and authentication (xrootd only)
    UserDictId = b'u',
    /// file transfer event (FRM only)
    FileTransfer = b'x',
}

#[derive(BinRead, Debug)]
#[br(big)]
pub struct Header {
    pub code: Code,
    /// packet sequence
    pub pseq: u8,
    /// packet length in bytes
    pub plen: u16,
    /// Unix time at Server Start
    pub stod: i32,
}

pub trait PacketPayload: Sized {
    fn digest_payload<R: BinReaderExt>(header: Header, data: &mut R) -> BinResult<Self>;
}
