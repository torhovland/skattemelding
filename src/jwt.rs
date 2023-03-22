use anyhow::Result;
use serde::Deserialize;

use std::str;

use crate::base64::decode_nopad;

#[derive(Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub id_token: String,
}

#[derive(Deserialize)]
pub struct IdToken {
    pub pid: String,
}

impl IdToken {
    pub fn from_str(value: &str) -> Result<Self> {
        let claims: IdToken =
            serde_json::from_str(&decode_nopad(value.split('.').collect::<Vec<_>>()[1])?)?;

        Ok(Self { pid: claims.pid })
    }
}
