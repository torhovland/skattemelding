use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
    routing::get,
    Json, Router,
};
use serde::Deserialize;
use serde_json::json;
use std::fs;
use std::{error::Error, net::SocketAddr};
use tera::{Context, Tera};

#[derive(Clone)]
pub struct Config {
    pub tera: Tera,
    pub client_secret: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();

    let tera = Tera::new("templates/**/*.html")?;

    const SECRET_FILE_NAME: &str = "client_secret.txt";
    tracing::info!("Reading {SECRET_FILE_NAME}");
    let client_secret = fs::read_to_string(SECRET_FILE_NAME)?;

    let config = Config {
        tera,
        client_secret,
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/logginn", get(logginn))
        .route("/token", get(token))
        .with_state(config);

    let addr = SocketAddr::from(([127, 0, 0, 1], 12345));
    tracing::info!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}

async fn index(State(config): State<Config>) -> Result<Html<String>, AppError> {
    Ok(Html(config.tera.render("index.html", &Context::new())?))
}

async fn logginn() -> Redirect {
    // https://oidc.difi.no/idporten-oidc-provider/.well-known/openid-configuration
    Redirect::permanent("https://oidc.difi.no/idporten-oidc-provider/authorize?scope=skatteetaten%3Aformueinntekt%2Fskattemelding%20openid&acr_values=Level3&client_id=4060f6d4-28ab-410d-bf14-edd62aa88dcf&redirect_uri=http%3A%2F%2Flocalhost%3A12345%2Ftoken&response_type=code&state=SgNdr4kEG_EJOptKwlwg5Q&nonce=1678988024798240&code_challenge=v7PyFrwYJeGtsYYchHyjafe4Z_GxMtDUPDuWXX_BRMg=&code_challenge_method=S256&ui_locales=nb")
}

async fn token(
    State(config): State<Config>,
    Query(query_params): Query<QueryParams>,
) -> Result<String, AppError> {
    let form_params = [
        ("grant_type", "authorization_code".to_string()),
        (
            "client_id",
            "4060f6d4-28ab-410d-bf14-edd62aa88dcf".to_string(),
        ),
        ("client_secret", config.client_secret),
        (
            "code_verifier",
            "HalCZ880JLh4IiV0JOTEJc9E_7ghoc1qCQTK2kSSsaE".to_string(),
        ),
        ("code", query_params.code),
    ];

    let response = reqwest::Client::new()
        .post("https://oidc.difi.no/idporten-oidc-provider/token")
        .form(&form_params)
        .send()
        .await?
        .text()
        .await?;

    tracing::info!("Token response: {}", response);

    let token_response: TokenResponse = serde_json::from_str(&response)?;

    if let Some(e) = token_response.error {
        return Err(AppError::Token(e, token_response.error_description));
    }

    if let Some(token) = token_response.access_token {
        tracing::info!("Access token: {}", token);
        Ok(response)
    } else {
        Err(AppError::Token("No token received".to_string(), None))
    }
}

#[derive(Debug, Deserialize)]
struct QueryParams {
    code: String,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

enum AppError {
    Reqwest(reqwest::Error),
    Serde(serde_json::Error),
    Tera(tera::Error),
    Token(String, Option<String>),
}

impl From<reqwest::Error> for AppError {
    fn from(inner: reqwest::Error) -> Self {
        AppError::Reqwest(inner)
    }
}

impl From<serde_json::Error> for AppError {
    fn from(inner: serde_json::Error) -> Self {
        AppError::Serde(inner)
    }
}

impl From<tera::Error> for AppError {
    fn from(inner: tera::Error) -> Self {
        AppError::Tera(inner)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AppError::Reqwest(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            AppError::Serde(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            AppError::Tera(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            AppError::Token(e, description) => (
                StatusCode::UNAUTHORIZED,
                e + &description
                    .map(|s| format!(": {s}"))
                    .unwrap_or("".to_string()),
            ),
        };

        let body = Json(json!({
            "error": error_message,
        }));

        (status, body).into_response()
    }
}
