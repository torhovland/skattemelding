use anyhow::Result;
use reqwest::{Client, RequestBuilder};

pub async fn get_text(url: &str, token: &str) -> Result<String> {
    Ok(get(url, Some(token))
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?)
}

pub fn delete(url: &str, token: Option<&str>) -> RequestBuilder {
    let request = Client::new().delete(url);
    maybe_with_token(request, token)
}

pub fn get(url: &str, token: Option<&str>) -> RequestBuilder {
    let request = Client::new().get(url);
    maybe_with_token(request, token)
}

pub fn post(url: &str, token: Option<&str>) -> RequestBuilder {
    let request = Client::new().post(url);
    maybe_with_token(request, token)
}

pub fn put(url: &str, token: Option<&str>) -> RequestBuilder {
    let request = Client::new().put(url);
    maybe_with_token(request, token)
}

fn maybe_with_token(request: RequestBuilder, token: Option<&str>) -> RequestBuilder {
    if let Some(token) = token {
        request.header("Authorization", format!("Bearer {token}"))
    } else {
        request
    }
}
