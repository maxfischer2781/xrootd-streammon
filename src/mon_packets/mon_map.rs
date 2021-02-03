/// Contents of the XrdXrootdMonMap struct
///
/// Each input struct contains a `userid\npayload` info field.
/// The `userid` is always represented by `UserId`,
/// while the `payload` can be any of the types of `MapPayload`.
///
/// The type of "string-like" fields is not strictly specified:
/// XRootD specifies them as `char[]`, and this module similarly
/// represents them as arbitrary `Vec<u8>`. They may-or-may-not
/// contain ASCII data.
///
/// See https://xrootd.slac.stanford.edu/doc/dev44/xrd_monitoring.htm#_Toc449036990
use std::str;
use std::str::FromStr;

type Bytes = Vec<u8>;
type BytesSlice = [u8];

/// Find the index in ``bytes`` for the substring ``at``
fn index(bytes: &BytesSlice, at: &BytesSlice) -> Option<usize> {
    bytes.windows(at.len()).position(|window| at == window)
}

/// Partition a bytes sequence at another if present
fn partition(bytes: &BytesSlice, at: &BytesSlice) -> Option<(Bytes, Bytes)> {
    match index(bytes, at) {
        Some(start) => Some((bytes[..start].to_vec(), bytes[start + at.len()..].to_vec())),
        None => None,
    }
}

/// Extract a CGI field from a CGI encoding bytes sequence
/// The `key` must be specified *without* leading/trailing ``&...=``
fn get_cgi(bytes: &BytesSlice, key: &BytesSlice) -> Option<Bytes> {
    let cgi_key = [b"&", key, b"="].concat();
    let (_, value_trail) = partition(bytes, &cgi_key)?;
    if let Some((value, _)) = partition(&value_trail, b"&") {
        Some(value)
    } else {
        Some(value_trail)
    }
}

fn parse<T: str::FromStr>(bytes: &BytesSlice) -> Option<T> {
    str::from_utf8(bytes).ok()?.parse::<T>().ok()
}

// TODO: Switch back to Result<S, E> to propagate failure reasons
trait DigestMap: Sized {
    fn from_bytes(data: &BytesSlice) -> Option<Self>;
}

/// Identification of an entity – "user" just means "not this server"
#[derive(Debug)]
struct UserId {
    /// The communication protocol being used by the client (e.g., xroot, http, etc).
    prot: Bytes,
    /// The Unix username of the user as reported by the client (i.e. unverified).
    user: Bytes,
    /// The user's process number that issued the request.
    pid: Bytes,
    /// The server's identification processing the connection to `user:pid` at `host`.
    sid: Bytes,
    /// The host name, or IP address, where the user's request originated.
    host: Bytes,
}

impl DigestMap for UserId {
    /// Parse raw data as `prot/user.pid:sid@host`
    fn from_bytes(data: &BytesSlice) -> Option<Self> {
        let (prot, rest) = partition(&data, b"/")?;
        let (user, rest) = partition(&rest, b".")?;
        let (pid, rest) = partition(&rest, b":")?;
        let (sid, host) = partition(&rest, b"@")?;
        Some(Self {
            prot,
            user,
            pid,
            sid,
            host,
        })
    }
}

#[derive(Debug)]
pub struct SrvInfo {
    /// The name of the server's executable program.
    pub pgm: Bytes,
    /// The server's version identification string.
    pub ver: Bytes,
    /// The server's instance name as specified with the –n command line option or "anon".
    pub inst: Bytes,
    /// The server's main port number.
    pub port: Bytes,
    /// The server's designated site name.
    pub site: Bytes,
}

impl DigestMap for SrvInfo {
    /// Parse raw data as `&pgm=prog&ver=vname&inst=iname&port=pnum&site=sname`
    fn from_bytes(data: &BytesSlice) -> Option<Self> {
        Some(Self {
            pgm: get_cgi(data, b"pgm")?,
            ver: get_cgi(data, b"ver")?,
            inst: get_cgi(data, b"inst")?,
            port: get_cgi(data, b"port")?,
            site: get_cgi(data, b"site")?,
        })
    }
}

/// The full path name of the file being opened.
#[derive(Debug)]
struct Path(Bytes);

impl DigestMap for Path {
    fn from_bytes(data: &BytesSlice) -> Option<Self> {
        Some(Self((*data).to_vec()))
    }
}

/// Un-interpreted application supplied information.
#[derive(Debug)]
struct AppInfo(Bytes);

#[derive(Debug)]
pub struct AuthInfo {
    /// The authentication protocol name used to authenticate the client.
    protocol: Bytes,
    /// The client's distinguished name as reported by the protocol.
    name: Option<Bytes>,
    /// The client's host’s name as reported by the protocol.
    host: Option<Bytes>,
    /// The client's organization name as reported by the protocol.
    organization: Option<Bytes>,
    /// The client's role name as reported by the protocol.
    role: Option<Bytes>,
    /// The client's group names in a space-separated list.
    groups: Option<Bytes>,
    /// ???
    m: Option<Bytes>,
    /// The name of the executable program the client is running with the path removed.
    executable: Option<Bytes>,
    /// The contents of the XRD_MONINFO client-side environmental variable.
    moninfo: Option<Bytes>,
    /// The client's network mode: '4' for IPv4 and '6' for IPv6.
    ipv: Option<u8>,
}

#[derive(Debug)]
pub enum MaybeAuthInfo {
    Unavailable,
    Full(AuthInfo),
}

impl DigestMap for MaybeAuthInfo {
    /// Parse raw data as `&p=ap&n=[dn]&h=[hn]&o=[on]&r=[rn]&g=[gn]&m=[info]&x=[xeqname]&y=[minfo]&I={4|6}`
    fn from_bytes(data: &BytesSlice) -> Option<Self> {
        // helper to parse empty fields as None
        fn empty_none(c: Option<Bytes>) -> Option<Bytes> {
            c.and_then(|v| if v.is_empty() {None} else {Some(v)})
        }
        if data.is_empty() {
            return Some(Self::Unavailable)
        }
        Some(Self::Full(AuthInfo {
            protocol: get_cgi(&data, b"p")?,
            name: empty_none(get_cgi(&data, b"n")),
            host: empty_none(get_cgi(&data, b"h")),
            organization: empty_none(get_cgi(&data, b"o")),
            role: empty_none(get_cgi(&data, b"r")),
            groups: empty_none(get_cgi(&data, b"g")),
            m: empty_none(get_cgi(&data, b"m")),
            executable: empty_none(get_cgi(&data, b"x")),
            moninfo: empty_none(get_cgi(&data, b"y")),
            ipv: empty_none(get_cgi(&data, b"I")).map(|v| v[0]),
        }))
    }
}

impl DigestMap for AppInfo {
    fn from_bytes(data: &BytesSlice) -> Option<Self> {
        Some(Self((*data).to_vec()))
    }
}

// FRM monitor maps

#[derive(Debug, PartialEq)]
#[repr(u8)]
enum FileNameType {
    /// Unknown operation, this usually indicates a logic error.
    Logical = b'l',
    /// File was copied into the server by client request.
    Physical = b'p',
}

impl FromStr for FileNameType {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "l" => Ok(Self::Logical),
            "p" => Ok(Self::Physical),
            _ => Err(()),
        }
    }
}

#[derive(Debug)]
struct PrgInfo {
    /// The logical or physical name of the file that was purged.
    xfn: Bytes,
    /// The Unix seconds, as returned by time(), when the record was produced.
    tod: i64,
    /// The size of the purged file in bytes.
    sz: i64,
    /// The file's access time in Unix seconds.
    at: i64,
    /// The file's creation time in Unix seconds.
    ct: i64,
    /// The file's modification time in Unix seconds.
    mt: i64,
    /// Whether `xfn` is a logical or physical name.
    /// Normally should be logical and indicates an error in name resolution otherwise.
    fnt: FileNameType,
}

impl DigestMap for PrgInfo {
    /// Parse raw data as `xfn\n&tod=tod&sz=bytes&at=at&ct=ct&mt=mt&fn=x`
    fn from_bytes(data: &BytesSlice) -> Option<Self> {
        let (xfn, cgi) = partition(data, b"\n")?;
        Some(Self {
            xfn,
            tod: parse(&get_cgi(&cgi, b"tod")?)?,
            sz: parse(&get_cgi(&cgi, b"sz")?)?,
            at: parse(&get_cgi(&cgi, b"at")?)?,
            ct: parse(&get_cgi(&cgi, b"ct")?)?,
            mt: parse(&get_cgi(&cgi, b"mt")?)?,
            fnt: parse(&get_cgi(&cgi, b"fn")?)?,
        })
    }
}

#[derive(Debug, PartialEq)]
#[repr(u8)]
enum XfrOpt {
    /// Unknown operation, this usually indicates a logic error.
    Unknown = b'0',
    /// File was copied into the server by client request.
    ClientStage = b'1',
    /// File was copied out of the server by migration system request.
    SystemCopy = b'2',
    /// File was copied-and-deleted out of the server by migration system request.
    SystemMove = b'3',
    /// File was copied out of the server by client request.
    ClientCopy = b'4',
    /// File was copied-and-deleted out of the server by client request.
    ClientMove = b'5',
    /// File was copied into the server by staging system request.
    SystemStage = b'6',
}

impl FromStr for XfrOpt {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "0" => Ok(Self::Unknown),
            "1" => Ok(Self::ClientStage),
            "2" => Ok(Self::SystemCopy),
            "3" => Ok(Self::SystemMove),
            "4" => Ok(Self::ClientCopy),
            "5" => Ok(Self::ClientMove),
            "6" => Ok(Self::SystemStage),
            _ => Err(()),
        }
    }
}

#[derive(Debug)]
struct XfrInfo {
    /// The logical name of the transferred file.
    xfn: Bytes,
    /// The Unix seconds, as returned by time(), when the record was produced.
    tod: i64,
    /// The time between the start of the request to the time the request completed
    tm: i64,
    /// The character operation code for a file transfer event.
    op: XfrOpt,
    /// The return code, zero on success.
    rc: i16,
    /// optional program monitoring data returned by the transfer command.
    data: Option<Bytes>,
}

impl DigestMap for XfrInfo {
    /// Parse raw data as `lfn\n&tod=tod&sz=bytes&tm=sec&op=op&rc=rc&pd=data`
    fn from_bytes(data: &BytesSlice) -> Option<Self> {
        let (xfn, cgi) = partition(data, b"\n")?;
        Some(Self {
            xfn,
            tod: parse(&get_cgi(&cgi, b"tod")?)?,
            tm: parse(&get_cgi(&cgi, b"sz")?)?,
            op: parse(&get_cgi(&cgi, b"op")?)?,
            rc: parse(&get_cgi(&cgi, b"rc")?)?,
            data: get_cgi(&cgi, b"data"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_cgi() {
        assert_eq!(
            get_cgi(
                b"lzag&keyvalue&gsdukey=notvalue&k63&key=value&124kahsbdeas",
                b"key"
            )
            .unwrap(),
            b"value"
        )
    }

    #[test]
    fn test_read_srv_info() -> Result<(), String> {
        if let Some(srv_info) =
            SrvInfo::from_bytes(b"&pgm=prog&ver=vname&inst=iname&port=pnum&site=sname")
        {
            assert_eq!(srv_info.pgm, b"prog");
            assert_eq!(srv_info.ver, b"vname");
            assert_eq!(srv_info.inst, b"iname");
            assert_eq!(srv_info.port, b"pnum");
            assert_eq!(srv_info.site, b"sname");
            Ok(())
        } else {
            Err(String::from("failed to parse"))
        }
    }

    #[test]
    fn test_read_prg_info() -> Result<(), String> {
        if let Some(prg_info) =
            PrgInfo::from_bytes(b"xfn\n&tod=1234&sz=5678&at=0&ct=-15&mt=256&fn=l")
        {
            assert_eq!(prg_info.xfn, b"xfn");
            assert_eq!(prg_info.tod, 1234);
            assert_eq!(prg_info.sz, 5678);
            assert_eq!(prg_info.at, 0);
            assert_eq!(prg_info.ct, -15);
            assert_eq!(prg_info.mt, 256);
            assert_eq!(prg_info.fnt, FileNameType::Logical);
            Ok(())
        } else {
            Err(String::from("failed to parse"))
        }
    }

    #[test]
    fn test_read_auth_info() -> Result<(), String> {
        if let Some(auth_info) =
            MaybeAuthInfo::from_bytes(b"&p=ap&n=dn&h=hn&o=on&r=rn&g=gn&m=info&x=xeqname&y=minfo&I=4")
        {
            match auth_info {
                MaybeAuthInfo::Unavailable => Err(String::from("failed to parse")),
                MaybeAuthInfo::Full(ai) => {
                    assert_eq!(ai.protocol, b"ap");
                    Ok(())
                }
            }
        } else {
            Err(String::from("failed to parse"))
        }
    }

    #[test]
    fn test_read_auth_info_empty() -> Result<(), String> {
        if MaybeAuthInfo::from_bytes(b"&n=dn&h=hn&o=on&r=rn&g=gn&m=info&x=xeqname&y=minfo&I=4").is_some() {
            return Err(String::from("parsed malformed auth info"))
        }
        match MaybeAuthInfo::from_bytes(b"") {
            None => Err(String::from("failed to parse")),
            Some(MaybeAuthInfo::Unavailable) => Ok(()),
            Some(MaybeAuthInfo::Full(_)) => Err(String::from("parsed malformed auth info")),
        }
    }
}
