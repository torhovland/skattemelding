use anyhow::Result;
use reqwest::RequestBuilder;

pub async fn get(url: &str, token: &str) -> Result<String> {
    Ok(reqwest::Client::new()
        .get(url)
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?)
}

pub fn post(url: &str, token: &str) -> RequestBuilder {
    reqwest::Client::new()
        .post(url)
        .header("Authorization", format!("Bearer {token}"))
}
