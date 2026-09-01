//! Extract the SNI `host_name` from a TLS ClientHello **without decoding TLS**.
//!
//! The egress proxy allows a CONNECT by host, then peeks the first client
//! record and checks the ClientHello's SNI against that host. A subprocess
//! that opens `CONNECT allowed-host:443` and then negotiates a different site
//! on a shared front (domain fronting) is refused when the two disagree.
//! Parsing walks record → handshake → extensions to the `server_name`
//! extension (type 0) and returns its first `host_name`. Any malformed or
//! non-ClientHello input, or a hello without SNI, yields `None` — the caller
//! decides how to treat "no SNI" (this crate: allow, since there is nothing
//! to contradict the CONNECT host).

/// Return the first SNI `host_name` in a ClientHello, or `None`.
pub fn extract_sni(buf: &[u8]) -> Option<String> {
    // TLS record header: content_type(1)=22 handshake, version(2), length(2).
    if buf.len() < 5 || buf[0] != 0x16 {
        return None;
    }
    let mut p = 5usize;
    // Handshake header: msg_type(1)=1 ClientHello, length(3).
    if buf.len() < p + 4 || buf[p] != 0x01 {
        return None;
    }
    p += 4;
    // client_version(2) + random(32).
    p += 2 + 32;
    if p > buf.len() {
        return None;
    }
    // session_id: length(1) + data.
    let sid = *buf.get(p)? as usize;
    p += 1 + sid;
    // cipher_suites: length(2) + data.
    let cs = u16::from_be_bytes([*buf.get(p)?, *buf.get(p + 1)?]) as usize;
    p += 2 + cs;
    // compression_methods: length(1) + data.
    let cm = *buf.get(p)? as usize;
    p += 1 + cm;
    // extensions: length(2) + data.
    if p + 2 > buf.len() {
        return None;
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
            // host_name, name_length(2), host.
            let q = p + 2;
            if q + 3 > ext_end {
                return None;
            }
            let name_type = buf[q];
            let name_len = u16::from_be_bytes([buf[q + 1], buf[q + 2]]) as usize;
            let start = q + 3;
            if name_type == 0 && start + name_len <= ext_end {
                return String::from_utf8(buf[start..start + name_len].to_vec()).ok();
            }
            return None;
        }
        p += ext_len;
    }
    None
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
        assert_eq!(extract_sni(&rec).as_deref(), Some("cdn-lfs.hf.co"));
    }

    #[test]
    fn non_handshake_record_yields_none() {
        assert_eq!(extract_sni(&[0x17, 0x03, 0x03, 0, 0]), None);
    }

    #[test]
    fn truncated_hello_yields_none_not_panic() {
        let rec = client_hello_with_sni("huggingface.co");
        for cut in 0..rec.len() {
            let _ = extract_sni(&rec[..cut]); // must never panic
        }
    }
}
