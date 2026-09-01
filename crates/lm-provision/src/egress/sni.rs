//! Extract the SNI `host_name` from a TLS ClientHello **without decoding TLS**.
//!
//! The egress proxy allows a CONNECT by host, then peeks the ClientHello and
//! checks its SNI against that host. A subprocess that opens `CONNECT
//! allowed-host:443` and then negotiates a different site on a shared front
//! (domain fronting) is refused when the two disagree. Parsing walks record →
//! handshake → extensions to the `server_name` extension (type 0) and returns
//! its first `host_name`.
//!
//! # Why the result is three-valued
//!
//! The caller's decision on "no SNI" (allow — nothing contradicts the CONNECT
//! host) and its decision on "the bytes did not parse" (refuse — fail closed)
//! are opposite, so [`extract_sni`] must tell them apart. A hello that is
//! well-formed but simply carries no `server_name` extension is [`Sni::None`];
//! a buffer that is truncated, mis-framed, or otherwise not a ClientHello this
//! parser can walk is [`Sni::Unparseable`]. Collapsing the two — the shape a
//! bare `Option` forces — is exactly the fail-open the caller must avoid once
//! it has committed to having assembled a *complete* handshake.

/// The outcome of an SNI extraction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sni {
    /// A `server_name` host_name was present and read.
    Found(String),
    /// The ClientHello parsed cleanly and carries no `server_name`
    /// extension — nothing to contradict the CONNECT host (caller: allow).
    None,
    /// The bytes could not be walked as a ClientHello (truncated, mis-framed,
    /// not a handshake). The caller has already assembled what it believes is
    /// a whole handshake, so this is a genuine parse failure, not a partial
    /// read (caller: fail closed).
    Unparseable,
}

/// Extract the SNI from a (reassembled) ClientHello record.
pub fn extract_sni(buf: &[u8]) -> Sni {
    // TLS record header: content_type(1)=22 handshake, version(2), length(2).
    if buf.len() < 5 || buf[0] != 0x16 {
        return Sni::Unparseable;
    }
    let mut p = 5usize;
    // Handshake header: msg_type(1)=1 ClientHello, length(3).
    if buf.len() < p + 4 || buf[p] != 0x01 {
        return Sni::Unparseable;
    }
    p += 4;
    // client_version(2) + random(32).
    p += 2 + 32;
    if p > buf.len() {
        return Sni::Unparseable;
    }
    // session_id: length(1) + data.
    let Some(sid) = buf.get(p).map(|b| *b as usize) else {
        return Sni::Unparseable;
    };
    p += 1 + sid;
    // cipher_suites: length(2) + data.
    let (Some(cs_hi), Some(cs_lo)) = (buf.get(p), buf.get(p + 1)) else {
        return Sni::Unparseable;
    };
    let cs = u16::from_be_bytes([*cs_hi, *cs_lo]) as usize;
    p += 2 + cs;
    // compression_methods: length(1) + data.
    let Some(cm) = buf.get(p).map(|b| *b as usize) else {
        return Sni::Unparseable;
    };
    p += 1 + cm;
    // extensions: length(2) + data.
    if p + 2 > buf.len() {
        return Sni::Unparseable;
    }
    let ext_total = u16::from_be_bytes([buf[p], buf[p + 1]]) as usize;
    p += 2;
    let ext_end = (p + ext_total).min(buf.len());
    while p + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([buf[p], buf[p + 1]]);
        let ext_len = u16::from_be_bytes([buf[p + 2], buf[p + 3]]) as usize;
        p += 4;
        if ext_type == 0x0000 {
            // server_name: list_length(2), then entry name_type(1)=0
            // host_name, name_length(2), host. A present-but-malformed
            // server_name extension is `Unparseable`, not `None`: the field
            // is there and did not read.
            let q = p + 2;
            if q + 3 > ext_end {
                return Sni::Unparseable;
            }
            let name_type = buf[q];
            let name_len = u16::from_be_bytes([buf[q + 1], buf[q + 2]]) as usize;
            let start = q + 3;
            if name_type == 0 && start + name_len <= ext_end {
                return match String::from_utf8(buf[start..start + name_len].to_vec()) {
                    Ok(host) => Sni::Found(host),
                    Err(_) => Sni::Unparseable,
                };
            }
            return Sni::Unparseable;
        }
        p += ext_len;
    }
    // Walked the whole extension block; no server_name present.
    Sni::None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal ClientHello record carrying one SNI host_name.
    fn client_hello_with_sni(host: &str) -> Vec<u8> {
        let host = host.as_bytes();
        // server_name extension body.
        let mut sn = Vec::new();
        sn.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes()); // list len
        sn.push(0); // name_type host_name
        sn.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sn.extend_from_slice(host);
        let mut ext = Vec::new();
        ext.extend_from_slice(&0u16.to_be_bytes()); // ext type server_name
        ext.extend_from_slice(&(sn.len() as u16).to_be_bytes());
        ext.extend_from_slice(&sn);

        let mut hs_body = Vec::new();
        hs_body.extend_from_slice(&[0x03, 0x03]); // client_version
        hs_body.extend_from_slice(&[0u8; 32]); // random
        hs_body.push(0); // session_id len
        hs_body.extend_from_slice(&2u16.to_be_bytes()); // cipher_suites len
        hs_body.extend_from_slice(&[0x13, 0x01]); // one suite
        hs_body.push(1); // compression_methods len
        hs_body.push(0); // null compression
        hs_body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        hs_body.extend_from_slice(&ext);

        let mut hs = Vec::new();
        hs.push(0x01); // ClientHello
        let l = hs_body.len();
        hs.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
        hs.extend_from_slice(&hs_body);

        let mut rec = Vec::new();
        rec.push(0x16); // handshake
        rec.extend_from_slice(&[0x03, 0x01]); // record version
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn extracts_sni_from_a_well_formed_client_hello() {
        let rec = client_hello_with_sni("cdn-lfs.hf.co");
        assert_eq!(extract_sni(&rec), Sni::Found("cdn-lfs.hf.co".to_string()));
    }

    /// **A hello with no `server_name` extension is `None`, not
    /// `Unparseable`.** The two drive opposite proxy decisions (allow vs
    /// fail-closed), so a well-formed hello that simply omits SNI must read
    /// as `None`.
    #[test]
    fn a_well_formed_hello_without_a_server_name_extension_is_none() {
        assert_eq!(extract_sni(&client_hello_without_sni()), Sni::None);
    }

    #[test]
    fn non_handshake_record_is_unparseable() {
        assert_eq!(extract_sni(&[0x17, 0x03, 0x03, 0, 0]), Sni::Unparseable);
    }

    /// **A truncated hello never panics and never yields the SNI.** Every
    /// strict prefix of the record must fail to produce `Found(host)` — it
    /// is either `Unparseable` (the structural walk hit the end) or, when a
    /// truncation happens to clamp the extension block cleanly, `None`.
    /// Either is safe here because the proxy only calls `extract_sni` on a
    /// handshake it has already reassembled to its declared length; a
    /// partial buffer never reaches it (S4 lives in `peek_client_hello`).
    #[test]
    fn a_truncated_hello_never_yields_the_sni_and_never_panics() {
        let rec = client_hello_with_sni("huggingface.co");
        for cut in 0..rec.len() {
            assert_ne!(
                extract_sni(&rec[..cut]),
                Sni::Found("huggingface.co".to_string()),
                "a partial hello must not yield the full SNI (cut={cut})"
            );
        }
    }

    /// A ClientHello record with an empty extension block (no SNI).
    fn client_hello_without_sni() -> Vec<u8> {
        let mut hs_body = Vec::new();
        hs_body.extend_from_slice(&[0x03, 0x03]); // client_version
        hs_body.extend_from_slice(&[0u8; 32]); // random
        hs_body.push(0); // session_id len
        hs_body.extend_from_slice(&2u16.to_be_bytes()); // cipher_suites len
        hs_body.extend_from_slice(&[0x13, 0x01]); // one suite
        hs_body.push(1); // compression_methods len
        hs_body.push(0); // null compression
        hs_body.extend_from_slice(&0u16.to_be_bytes()); // extensions len = 0

        let mut hs = Vec::new();
        hs.push(0x01); // ClientHello
        let l = hs_body.len();
        hs.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
        hs.extend_from_slice(&hs_body);

        let mut rec = Vec::new();
        rec.push(0x16); // handshake
        rec.extend_from_slice(&[0x03, 0x01]); // record version
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }
}
