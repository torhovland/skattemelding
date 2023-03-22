use anyhow::Result;
use data_encoding::BASE64;

use std::str;

pub fn decode(s: &str) -> Result<String> {
    Ok(str::from_utf8(&BASE64.decode(s.as_bytes())?)?.to_string())
}

pub fn encode(s: &str) -> String {
    BASE64.encode(s.as_bytes())
}
