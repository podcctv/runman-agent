//! Pure-`std` TLS & QUIC Initial SNI parser and whitelist enforcer for Runman Rust v2.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const SNI_WHITELIST: &[&str] = &[
    "dl-cdn.alpinelinux.org",
    "deb.debian.org",
    "crates.io",
    "pypi.org",
    "rubygems.org",
    "addons.mozilla.org",
    "formulae.brew.sh",
    "static.rust-lang.org",
    "cpan.org",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SniParse {
    Found(String),
    MissingSni,
    Malformed,
    NotHandshake,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SniDecision {
    Allow,
    Block {
        reason: &'static str,
        sni: Option<String>,
        proto: u8,
        dport: u16,
        src_ip: IpAddr,
    },
}

pub fn normalize_sni(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if trimmed.is_empty() || trimmed.len() > 253 {
        return None;
    }
    if !trimmed
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
    {
        return None;
    }
    Some(trimmed)
}

pub fn is_allowed_sni(raw: &str) -> bool {
    let Some(norm) = normalize_sni(raw) else {
        return false;
    };
    SNI_WHITELIST.iter().any(|&allowed| norm == allowed)
}

pub fn extract_tls_client_hello_sni(payload: &[u8]) -> SniParse {
    if payload.len() < 6 {
        return SniParse::NotHandshake;
    }
    if payload[0] != 0x16 || payload[1] != 0x03 || payload[2] > 0x04 {
        return SniParse::NotHandshake;
    }
    let rec_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    if rec_len == 0 {
        return SniParse::Malformed;
    }
    let rec_end = (5 + rec_len).min(payload.len());
    parse_tls_handshake_client_hello_sni(&payload[5..rec_end])
}

pub fn parse_tls_handshake_client_hello_sni(hs: &[u8]) -> SniParse {
    if hs.len() < 4 || hs[0] != 0x01 {
        return SniParse::NotHandshake;
    }
    let hs_len = ((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | (hs[3] as usize);
    if hs_len < 34 || 4 + hs_len > hs.len() {
        return SniParse::Malformed;
    }
    let body = &hs[4..4 + hs_len];
    let mut pos = 34usize;
    if pos >= body.len() {
        return SniParse::Malformed;
    }
    let sid_len = body[pos] as usize;
    pos += 1;
    if pos + sid_len > body.len() {
        return SniParse::Malformed;
    }
    pos += sid_len;
    if pos + 2 > body.len() {
        return SniParse::Malformed;
    }
    let cs_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    if cs_len == 0 || (cs_len & 1) != 0 || pos + cs_len > body.len() {
        return SniParse::Malformed;
    }
    pos += cs_len;
    if pos >= body.len() {
        return SniParse::Malformed;
    }
    let comp_len = body[pos] as usize;
    pos += 1;
    if comp_len == 0 || pos + comp_len > body.len() {
        return SniParse::Malformed;
    }
    pos += comp_len;
    if pos == body.len() {
        return SniParse::MissingSni;
    }
    if pos + 2 > body.len() {
        return SniParse::Malformed;
    }
    let ext_total = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    if pos + ext_total > body.len() {
        return SniParse::Malformed;
    }
    let ext_end = pos + ext_total;
    while pos < ext_end {
        if pos + 4 > ext_end {
            return SniParse::Malformed;
        }
        let ext_type = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let ext_len = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        pos += 4;
        if pos + ext_len > ext_end {
            return SniParse::Malformed;
        }
        if ext_type == 0x0000 {
            let ext_data = &body[pos..pos + ext_len];
            if ext_data.len() < 2 {
                return SniParse::Malformed;
            }
            let list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
            if 2 + list_len > ext_data.len() {
                return SniParse::Malformed;
            }
            let mut spos = 2usize;
            let send = 2 + list_len;
            while spos < send {
                if spos + 3 > send {
                    return SniParse::Malformed;
                }
                let name_type = ext_data[spos];
                let name_len = u16::from_be_bytes([ext_data[spos + 1], ext_data[spos + 2]]) as usize;
                spos += 3;
                if spos + name_len > send {
                    return SniParse::Malformed;
                }
                if name_type == 0x00 {
                    let Ok(s) = std::str::from_utf8(&ext_data[spos..spos + name_len]) else {
                        return SniParse::Malformed;
                    };
                    return match normalize_sni(s) {
                        Some(norm) => SniParse::Found(norm),
                        None => SniParse::Malformed,
                    };
                }
                spos += name_len;
            }
            return SniParse::MissingSni;
        }
        pos += ext_len;
    }
    SniParse::MissingSni
}

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn sha256_sum(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[i * 4], chunk[i * 4 + 1], chunk[i * 4 + 2], chunk[i * 4 + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(SHA256_K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (slot, val) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *slot = slot.wrapping_add(val);
        }
    }
    let mut out = [0u8; 32];
    for (i, &w) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
    }
    out
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut k_pad = [0u8; 64];
    if key.len() > 64 {
        let d = sha256_sum(key);
        k_pad[..32].copy_from_slice(&d);
    } else {
        k_pad[..key.len()].copy_from_slice(key);
    }
    let mut inner = Vec::with_capacity(64 + data.len());
    for &b in &k_pad {
        inner.push(b ^ 0x36);
    }
    inner.extend_from_slice(data);
    let inner_hash = sha256_sum(&inner);
    let mut outer = Vec::with_capacity(64 + 32);
    for &b in &k_pad {
        outer.push(b ^ 0x5c);
    }
    outer.extend_from_slice(&inner_hash);
    sha256_sum(&outer)
}

const QUIC_V1_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c,
    0xad, 0xcc, 0xbb, 0x7f, 0x0a,
];
const QUIC_V2_SALT: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d,
    0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
];

#[rustfmt::skip]
const AES_SBOX: [u8; 256] = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
];
const AES_RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

fn xtime(x: u8) -> u8 {
    (x << 1) ^ (((x >> 7) & 1) * 0x1b)
}

fn aes128_key_expand(key: &[u8; 16]) -> [[u8; 16]; 11] {
    let mut rk = [[0u8; 16]; 11];
    rk[0] = *key;
    for r in 0..10 {
        let prev = rk[r];
        let mut next = [0u8; 16];
        next[0] = prev[0] ^ AES_SBOX[prev[13] as usize] ^ AES_RCON[r];
        next[1] = prev[1] ^ AES_SBOX[prev[14] as usize];
        next[2] = prev[2] ^ AES_SBOX[prev[15] as usize];
        next[3] = prev[3] ^ AES_SBOX[prev[12] as usize];
        for i in 4..16 {
            next[i] = prev[i] ^ next[i - 4];
        }
        rk[r + 1] = next;
    }
    rk
}

fn aes128_encrypt_block(rk: &[[u8; 16]; 11], input: &[u8; 16]) -> [u8; 16] {
    let mut s = *input;
    for i in 0..16 {
        s[i] ^= rk[0][i];
    }
    for round in 1..=10 {
        for b in &mut s {
            *b = AES_SBOX[*b as usize];
        }
        let t1 = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t1;
        s.swap(2, 10); s.swap(6, 14);
        let t3 = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t3;
        if round < 10 {
            for col in 0..4 {
                let c = col * 4;
                let (a0, a1, a2, a3) = (s[c], s[c + 1], s[c + 2], s[c + 3]);
                let t = a0 ^ a1 ^ a2 ^ a3;
                s[c] ^= t ^ xtime(a0 ^ a1);
                s[c + 1] ^= t ^ xtime(a1 ^ a2);
                s[c + 2] ^= t ^ xtime(a2 ^ a3);
                s[c + 3] ^= t ^ xtime(a3 ^ a0);
            }
        }
        for i in 0..16 {
            s[i] ^= rk[round][i];
        }
    }
    s
}

fn gf128_mul(x: &[u8; 16], y: &[u8; 16]) -> [u8; 16] {
    let mut z = 0u128;
    let mut v = u128::from_be_bytes(*y);
    let xb = u128::from_be_bytes(*x);
    for i in 0..128 {
        if (xb >> (127 - i)) & 1 == 1 {
            z ^= v;
        }
        let lsb = v & 1;
        v >>= 1;
        if lsb == 1 {
            v ^= 0xe100_0000_0000_0000_0000_0000_0000_0000u128;
        }
    }
    z.to_be_bytes()
}

fn ghash_update(acc: &mut [u8; 16], h: &[u8; 16], data: &[u8]) {
    for chunk in data.chunks(16) {
        for (i, &b) in chunk.iter().enumerate() {
            acc[i] ^= b;
        }
        *acc = gf128_mul(acc, h);
    }
}

fn aes128_gcm_decrypt(
    key: &[u8; 16],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Option<Vec<u8>> {
    let rk = aes128_key_expand(key);
    let h = aes128_encrypt_block(&rk, &[0u8; 16]);
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(nonce);
    j0[15] = 1;

    let mut acc = [0u8; 16];
    ghash_update(&mut acc, &h, aad);
    ghash_update(&mut acc, &h, ciphertext);
    let mut lens = [0u8; 16];
    lens[..8].copy_from_slice(&((aad.len() as u64) * 8).to_be_bytes());
    lens[8..].copy_from_slice(&((ciphertext.len() as u64) * 8).to_be_bytes());
    ghash_update(&mut acc, &h, &lens);

    let s0 = aes128_encrypt_block(&rk, &j0);
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= (acc[i] ^ s0[i]) ^ tag[i];
    }
    if diff != 0 {
        return None;
    }

    let mut plain = Vec::with_capacity(ciphertext.len());
    let mut ctr = 2u32;
    for chunk in ciphertext.chunks(16) {
        let mut cb = j0;
        cb[12..16].copy_from_slice(&ctr.to_be_bytes());
        let ks = aes128_encrypt_block(&rk, &cb);
        for (i, &b) in chunk.iter().enumerate() {
            plain.push(b ^ ks[i]);
        }
        ctr = ctr.wrapping_add(1);
    }
    Some(plain)
}

fn hkdf_expand_label(secret: &[u8; 32], label: &[u8], out_len: usize) -> Vec<u8> {
    let full_label_len = 6 + label.len();
    let mut info = Vec::with_capacity(4 + full_label_len);
    info.extend_from_slice(&(out_len as u16).to_be_bytes());
    info.push(full_label_len as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(0u8);

    let mut out = Vec::with_capacity(out_len);
    let mut t: Vec<u8> = Vec::new();
    let mut counter = 1u8;
    while out.len() < out_len {
        let mut msg = Vec::with_capacity(t.len() + info.len() + 1);
        msg.extend_from_slice(&t);
        msg.extend_from_slice(&info);
        msg.push(counter);
        let block = hmac_sha256(secret, &msg);
        t = block.to_vec();
        let take = (out_len - out.len()).min(32);
        out.extend_from_slice(&block[..take]);
        counter = counter.wrapping_add(1);
    }
    out
}

fn read_quic_varint(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let first = *buf.get(*pos)?;
    let prefix = first >> 6;
    let len = 1usize << prefix;
    if *pos + len > buf.len() {
        return None;
    }
    let mut val = (first & 0x3f) as u64;
    for &b in &buf[*pos + 1..*pos + len] {
        val = (val << 8) | (b as u64);
    }
    *pos += len;
    Some(val)
}

pub fn extract_quic_initial_sni(udp_payload: &[u8]) -> SniParse {
    if udp_payload.len() < 16 {
        return SniParse::NotHandshake;
    }
    let first = udp_payload[0];
    if (first & 0xc0) != 0xc0 {
        return SniParse::NotHandshake;
    }
    let version = u32::from_be_bytes([udp_payload[1], udp_payload[2], udp_payload[3], udp_payload[4]]);
    let (salt, is_v2) = match version {
        0x0000_0001 => (&QUIC_V1_SALT, false),
        0x6b33_43cf => (&QUIC_V2_SALT, true),
        _ => return SniParse::NotHandshake,
    };
    let pkt_type = (first >> 4) & 0x03;
    if pkt_type != if is_v2 { 1 } else { 0 } {
        return SniParse::NotHandshake;
    }

    let mut pos = 5usize;
    let dcid_len = *udp_payload.get(pos).unwrap_or(&255) as usize;
    pos += 1;
    if dcid_len > 20 || pos + dcid_len >= udp_payload.len() {
        return SniParse::Malformed;
    }
    let dcid = &udp_payload[pos..pos + dcid_len];
    pos += dcid_len;

    let scid_len = *udp_payload.get(pos).unwrap_or(&255) as usize;
    pos += 1;
    if scid_len > 20 || pos + scid_len > udp_payload.len() {
        return SniParse::Malformed;
    }
    pos += scid_len;

    let Some(token_len) = read_quic_varint(udp_payload, &mut pos) else {
        return SniParse::Malformed;
    };
    let token_len = token_len as usize;
    if pos + token_len > udp_payload.len() {
        return SniParse::Malformed;
    }
    pos += token_len;

    let Some(pkt_len) = read_quic_varint(udp_payload, &mut pos) else {
        return SniParse::Malformed;
    };
    let pkt_len = pkt_len as usize;
    if pkt_len < 20 || pos + pkt_len > udp_payload.len() {
        return SniParse::Malformed;
    }
    let pn_offset = pos;
    let sample_offset = pn_offset + 4;
    if sample_offset + 16 > udp_payload.len() {
        return SniParse::Malformed;
    }
    let mut sample = [0u8; 16];
    sample.copy_from_slice(&udp_payload[sample_offset..sample_offset + 16]);

    let initial_secret = hmac_sha256(salt, dcid);
    let client_in_vec = hkdf_expand_label(&initial_secret, b"client in", 32);
    let mut client_in = [0u8; 32];
    client_in.copy_from_slice(&client_in_vec);

    let (lbl_key, lbl_iv, lbl_hp) = if is_v2 {
        (b"quicv2 key".as_slice(), b"quicv2 iv".as_slice(), b"quicv2 hp".as_slice())
    } else {
        (b"quic key".as_slice(), b"quic iv".as_slice(), b"quic hp".as_slice())
    };
    let mut key = [0u8; 16];
    key.copy_from_slice(&hkdf_expand_label(&client_in, lbl_key, 16));
    let mut iv = [0u8; 12];
    iv.copy_from_slice(&hkdf_expand_label(&client_in, lbl_iv, 12));
    let mut hp_key = [0u8; 16];
    hp_key.copy_from_slice(&hkdf_expand_label(&client_in, lbl_hp, 16));

    let hp_rk = aes128_key_expand(&hp_key);
    let mask = aes128_encrypt_block(&hp_rk, &sample);
    let unmasked_first = first ^ (mask[0] & 0x0f);
    let pn_len = ((unmasked_first & 0x03) as usize) + 1;
    if pn_offset + pn_len + 16 > pn_offset + pkt_len {
        return SniParse::Malformed;
    }

    let mut header = udp_payload[..pn_offset + pn_len].to_vec();
    header[0] = unmasked_first;
    let mut pn_val = 0u64;
    for i in 0..pn_len {
        header[pn_offset + i] ^= mask[1 + i];
        pn_val = (pn_val << 8) | (header[pn_offset + i] as u64);
    }

    let mut nonce = iv;
    let pn_bytes = pn_val.to_be_bytes();
    for i in 0..8 {
        nonce[4 + i] ^= pn_bytes[i];
    }

    let enc_start = pn_offset + pn_len;
    let enc_end = pn_offset + pkt_len;
    if enc_end - enc_start < 16 {
        return SniParse::Malformed;
    }
    let ct = &udp_payload[enc_start..enc_end - 16];
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&udp_payload[enc_end - 16..enc_end]);

    let Some(plain) = aes128_gcm_decrypt(&key, &nonce, &header, ct, &tag) else {
        return SniParse::Malformed;
    };

    let mut crypto_chunks: Vec<(usize, &[u8])> = Vec::new();
    let mut fpos = 0usize;
    while fpos < plain.len() {
        let ftype = plain[fpos];
        fpos += 1;
        match ftype {
            0x00 | 0x01 => continue,
            0x06 => {
                let Some(off) = read_quic_varint(&plain, &mut fpos) else {
                    return SniParse::Malformed;
                };
                let Some(len) = read_quic_varint(&plain, &mut fpos) else {
                    return SniParse::Malformed;
                };
                let off = off as usize;
                let len = len as usize;
                if fpos + len > plain.len() || off > 8192 {
                    return SniParse::Malformed;
                }
                crypto_chunks.push((off, &plain[fpos..fpos + len]));
                fpos += len;
            }
            _ => break,
        }
    }
    if crypto_chunks.is_empty() {
        return SniParse::MissingSni;
    }
    crypto_chunks.sort_by_key(|(off, _)| *off);
    let mut assembled = Vec::new();
    for (off, chunk) in crypto_chunks {
        if off == assembled.len() {
            assembled.extend_from_slice(chunk);
        } else if off < assembled.len() && off + chunk.len() > assembled.len() {
            let skip = assembled.len() - off;
            assembled.extend_from_slice(&chunk[skip..]);
        }
    }
    if assembled.is_empty() {
        return SniParse::Malformed;
    }
    parse_tls_handshake_client_hello_sni(&assembled)
}

pub fn evaluate_inbound_sni(raw: &[u8], is_cn_src: bool) -> SniDecision {
    if raw.len() < 20 {
        return SniDecision::Allow;
    }
    let version = raw[0] >> 4;
    let (src_ip, mut proto, mut offset, total_end) = match version {
        4 => {
            let ihl = ((raw[0] & 0x0f) as usize) * 4;
            if ihl < 20 || raw.len() < ihl {
                return SniDecision::Allow;
            }
            let end = (u16::from_be_bytes([raw[2], raw[3]]) as usize).min(raw.len());
            if end < ihl {
                return SniDecision::Allow;
            }
            (IpAddr::V4(Ipv4Addr::new(raw[12], raw[13], raw[14], raw[15])), raw[9], ihl, end)
        }
        6 => {
            if raw.len() < 40 {
                return SniDecision::Allow;
            }
            let end = (40 + u16::from_be_bytes([raw[4], raw[5]]) as usize).min(raw.len());
            let mut s = [0u8; 16];
            s.copy_from_slice(&raw[8..24]);
            (IpAddr::V6(Ipv6Addr::from(s)), raw[6], 40usize, end)
        }
        _ => return SniDecision::Allow,
    };

    if version == 6 {
        let mut hops = 0u8;
        while matches!(proto, 0 | 43 | 44 | 60) && hops < 6 {
            hops += 1;
            if proto == 44 {
                if offset + 8 > total_end {
                    return SniDecision::Allow;
                }
                proto = raw[offset];
                offset += 8;
            } else {
                if offset + 2 > total_end {
                    return SniDecision::Allow;
                }
                let next = raw[offset];
                let hdr_len = (raw[offset + 1] as usize + 1) * 8;
                if offset + hdr_len > total_end {
                    return SniDecision::Allow;
                }
                proto = next;
                offset += hdr_len;
            }
        }
    }

    let (dport, payload) = match proto {
        6 => {
            if offset + 20 > total_end {
                return SniDecision::Allow;
            }
            let dport = u16::from_be_bytes([raw[offset + 2], raw[offset + 3]]);
            let data_off = ((raw[offset + 12] >> 4) as usize) * 4;
            if data_off < 20 || offset + data_off > total_end {
                return SniDecision::Allow;
            }
            (dport, &raw[offset + data_off..total_end])
        }
        17 => {
            if offset + 8 > total_end {
                return SniDecision::Allow;
            }
            let dport = u16::from_be_bytes([raw[offset + 2], raw[offset + 3]]);
            let ulen = u16::from_be_bytes([raw[offset + 4], raw[offset + 5]]) as usize;
            let end = if ulen >= 8 { (offset + ulen).min(total_end) } else { total_end };
            (dport, &raw[offset + 8..end])
        }
        _ => return SniDecision::Allow,
    };

    if payload.is_empty() {
        return SniDecision::Allow;
    }
    let parsed = if proto == 6 {
        extract_tls_client_hello_sni(payload)
    } else {
        extract_quic_initial_sni(payload)
    };
    match parsed {
        SniParse::Found(sni) => {
            if is_allowed_sni(&sni) {
                SniDecision::Allow
            } else {
                SniDecision::Block { reason: "disallowed_sni", sni: Some(sni), proto, dport, src_ip }
            }
        }
        SniParse::MissingSni | SniParse::Malformed => {
            if is_cn_src {
                SniDecision::Block { reason: "missing_or_invalid_sni_cn", sni: None, proto, dport, src_ip }
            } else {
                SniDecision::Allow
            }
        }
        SniParse::NotHandshake => SniDecision::Allow,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_hs(sni: Option<&str>) -> Vec<u8> {
        let mut ext = Vec::new();
        if let Some(name) = sni {
            let nb = name.as_bytes();
            let list_len = 3 + nb.len();
            let ext_len = 2 + list_len;
            ext.extend_from_slice(&0x0000u16.to_be_bytes());
            ext.extend_from_slice(&(ext_len as u16).to_be_bytes());
            ext.extend_from_slice(&(list_len as u16).to_be_bytes());
            ext.push(0x00);
            ext.extend_from_slice(&(nb.len() as u16).to_be_bytes());
            ext.extend_from_slice(nb);
        }
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0x11; 32]);
        body.push(0x00);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01, 0x01, 0x00]);
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);
        let mut hs = vec![0x01, ((body.len() >> 16) & 0xff) as u8, ((body.len() >> 8) & 0xff) as u8, (body.len() & 0xff) as u8];
        hs.extend_from_slice(&body);
        hs
    }

    #[test]
    fn test_runman_sni_whitelist() {
        assert!(is_allowed_sni("dl-cdn.alpinelinux.org"));
        assert!(is_allowed_sni("CRATES.IO."));
        assert!(!is_allowed_sni("www.microsoft.com"));

        let hs = build_hs(Some("pypi.org"));
        let mut tls = vec![0x16, 0x03, 0x01];
        tls.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        tls.extend_from_slice(&hs);
        let mut pkt = vec![0u8; 40 + tls.len()];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&((40 + tls.len()) as u16).to_be_bytes());
        pkt[9] = 6;
        pkt[12..16].copy_from_slice(&[1, 2, 3, 4]);
        pkt[16..20].copy_from_slice(&[10, 0, 0, 2]);
        pkt[22..24].copy_from_slice(&443u16.to_be_bytes());
        pkt[32] = 0x50;
        pkt[40..].copy_from_slice(&tls);
        assert_eq!(evaluate_inbound_sni(&pkt, true), SniDecision::Allow);

        let no_sni = build_hs(None);
        let mut tls_no = vec![0x16, 0x03, 0x01];
        tls_no.extend_from_slice(&(no_sni.len() as u16).to_be_bytes());
        tls_no.extend_from_slice(&no_sni);
        let mut pkt_no = vec![0u8; 40 + tls_no.len()];
        pkt_no[0] = 0x45;
        pkt_no[2..4].copy_from_slice(&((40 + tls_no.len()) as u16).to_be_bytes());
        pkt_no[9] = 6;
        pkt_no[12..16].copy_from_slice(&[1, 2, 3, 4]);
        pkt_no[16..20].copy_from_slice(&[10, 0, 0, 2]);
        pkt_no[22..24].copy_from_slice(&443u16.to_be_bytes());
        pkt_no[32] = 0x50;
        pkt_no[40..].copy_from_slice(&tls_no);
        assert_eq!(evaluate_inbound_sni(&pkt_no, false), SniDecision::Allow);
        assert!(matches!(evaluate_inbound_sni(&pkt_no, true), SniDecision::Block { reason: "missing_or_invalid_sni_cn", .. }));
    }
}
