use anyhow::Result;
use data_encoding::{Encoding, BASE64, BASE64_NOPAD};

use std::str;

pub fn decode(s: &str) -> Result<String> {
    decode_inner(&BASE64, s)
}

pub fn decode_nopad(s: &str) -> Result<String> {
    decode_inner(&BASE64_NOPAD, s)
}

pub fn encode(s: &str) -> String {
    BASE64.encode(s.as_bytes())
}

fn decode_inner(encoding: &Encoding, s: &str) -> Result<String> {
    Ok(str::from_utf8(&encoding.decode(s.as_bytes())?)?.to_string())
}
