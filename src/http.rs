use anyhow::Result;

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
