/// Contents of the XrdXrootdMonMap struct
///
/// Each input struct contains a `userid\npayload` info field.
/// The `userid` is always represented by `UserId`,
/// while the `payload` can be any of the types of `MapPayload`.
///
/// Be aware that the content of fields is not strictly specified:
/// XRootD specifies them as `char[]`, and this module similarly
/// represents them as arbitrary `Vec<u8>`.
///
/// See https://xrootd.slac.stanford.edu/doc/dev44/xrd_monitoring.htm#_Toc449036990
type Bytes = Vec<u8>;
type BytesSlice = [u8];

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

impl DigestMap for AppInfo {
    fn from_bytes(data: &BytesSlice) -> Option<Self> {
        Some(Self((*data).to_vec()))
    }
}

#[derive(Debug)]
struct PrgInfo {
    /// The logical or physical name of the file that was purged.
    xfn: Bytes,
    /// The Unix seconds, as returned by time(), when the record was produced.
    tod: Bytes,
    /// The size of the purged file in bytes.
    sz: Bytes,
    /// The file's access time in Unix seconds.
    at: Bytes,
    /// The file's creation time in Unix seconds.
    ct: Bytes,
    /// The file's modification time in Unix seconds.
    mt: Bytes,
    /// The char 'l' if xfn is a logical file name (LFN) or 'p' if it is a physical file name (PFN).
    /// Normally should be 'l' and indicates an error in name resolution otherwise.
    fnt: u8,
}

impl DigestMap for PrgInfo {
    /// Parse raw data as `xfn\n&tod=tod&sz=bytes&at=at&ct=ct&mt=mt&fn=x`
    fn from_bytes(data: &BytesSlice) -> Option<Self> {
        let (xfn, cgi) = partition(data, b"\n")?;
        if let Some(fn_type) = get_cgi(&cgi, b"fn")?.get(0) {
            Some(Self {
                xfn,
                tod: get_cgi(&cgi, b"tod")?,
                sz: get_cgi(&cgi, b"sz")?,
                at: get_cgi(&cgi, b"at")?,
                ct: get_cgi(&cgi, b"ct")?,
                mt: get_cgi(&cgi, b"mt")?,
                fnt: *fn_type,
            })
        }
        else {
            None
        }
    }
}

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
            PrgInfo::from_bytes(b"xfn\n&tod=tod&sz=bytes&at=at&ct=ct&mt=mt&fn=x")
        {
            assert_eq!(prg_info.xfn, b"xfn");
            assert_eq!(prg_info.tod, b"tod");
            assert_eq!(prg_info.sz, b"bytes");
            assert_eq!(prg_info.at, b"at");
            assert_eq!(prg_info.ct, b"ct");
            assert_eq!(prg_info.mt, b"mt");
            assert_eq!(prg_info.fnt, b'x');
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
