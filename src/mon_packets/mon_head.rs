use binread::{BinRead, BinReaderExt, Error as BinError};

// Shared Header structure

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

impl Header {
    /// Size of the header in bytes
    pub const SIZE: usize = 8;
}

// Parsing facilities
#[derive(Debug)]
pub enum ParseError {
    Generic(
        /// During what parse operation the issue occurred
        String,
    ),
    BinRead (BinError),
}

impl From<BinError> for ParseError {
    fn from(err: BinError) -> Self {
        Self::BinRead(err)
    }
}

impl From<&str> for ParseError {
    fn from(err: &str) -> Self {
        Self::Generic(String::from(err))
    }
}

impl From<String> for ParseError {
    fn from(err: String) -> Self {
        Self::Generic(err)
    }
}

/// There was an error parsing raw XrootD data
pub type XrdParseResult<T> = Result<T, ParseError>;

pub trait PacketPayload: Sized {
    fn digest_payload<R: BinReaderExt>(header: Header, data: &mut R) -> XrdParseResult<Self>;
}
