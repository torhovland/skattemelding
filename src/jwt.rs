use anyhow::Result;
use data_encoding::BASE64_NOPAD;
use serde::Deserialize;

use std::str;

#[derive(Deserialize)]
pub struct IdToken {
    pub pid: String,
}

impl IdToken {
    pub fn from_str(value: &str) -> Result<Self> {
        let claims_part = value.split('.').collect::<Vec<_>>()[1];
        let claims_json =
            str::from_utf8(&BASE64_NOPAD.decode(claims_part.as_bytes())?)?.to_string();
        let claims: IdToken = serde_json::from_str(&claims_json)?;

        Ok(Self { pid: claims.pid })
    }
}
