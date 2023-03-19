use anyhow::anyhow;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
    routing::get,
    Router,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, error::Error, net::SocketAddr, sync::RwLock};
use std::{fs, sync::Arc};
use tera::{Context, Tera};

const ACCESS_TOKEN: &str = "access_token";
const ID_TOKEN: &str = "id_token";

#[derive(Clone)]
pub struct Config {
    pub tera: Tera,
    pub client_secret: String,
}

#[derive(Clone)]
struct AppState {
    config: Config,
    db: HashMap<&'static str, String>,
}

impl AppState {
    fn new(config: Config) -> Self {
        AppState {
            config,
            db: HashMap::<&str, String>::default(),
        }
    }
}

type SharedState = Arc<RwLock<AppState>>;

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

    let shared_state = Arc::new(RwLock::new(AppState::new(config)));

    let app = Router::new()
        .route("/", get(index))
        .route("/logginn", get(logginn))
        .route("/token", get(token))
        .with_state(shared_state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 12345));
    tracing::info!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}

async fn index(State(state): State<SharedState>) -> Result<Html<String>, AppError> {
    match (
        state.read().unwrap().db.get(ACCESS_TOKEN),
        state.read().unwrap().db.get(ID_TOKEN),
    ) {
        (Some(access_token), Some(id_token)) => {
            Ok(Html(state.read().unwrap().config.tera.render(
                "authenticated.html",
                &Context::from_serialize(&Authenticated {
                    access_token: access_token.to_string(),
                    id_token: id_token.to_string(),
                })?,
            )?))
        }
        _ => Ok(Html(
            state
                .read()
                .unwrap()
                .config
                .tera
                .render("guest.html", &Context::new())?,
        )),
    }
}

async fn logginn() -> Redirect {
    // https://oidc.difi.no/idporten-oidc-provider/.well-known/openid-configuration
    Redirect::permanent("https://oidc.difi.no/idporten-oidc-provider/authorize?scope=skatteetaten%3Aformueinntekt%2Fskattemelding%20openid&acr_values=Level3&client_id=4060f6d4-28ab-410d-bf14-edd62aa88dcf&redirect_uri=http%3A%2F%2Flocalhost%3A12345%2Ftoken&response_type=code&state=SgNdr4kEG_EJOptKwlwg5Q&nonce=1678988024798240&code_challenge=v7PyFrwYJeGtsYYchHyjafe4Z_GxMtDUPDuWXX_BRMg=&code_challenge_method=S256&ui_locales=nb")
}

/// Using client defined at
/// https://selvbetjening-samarbeid-prod.difi.no/integrations/4060f6d4-28ab-410d-bf14-edd62aa88dcf
async fn token<'a>(
    State(state): State<SharedState>,
    Query(query_params): Query<QueryParams>,
) -> Result<Redirect, AppError> {
    let form_params = [
        ("grant_type", "authorization_code".to_string()),
        (
            "client_id",
            "4060f6d4-28ab-410d-bf14-edd62aa88dcf".to_string(),
        ),
        (
            "client_secret",
            state.read().unwrap().config.client_secret.clone(),
        ),
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

    let token_response: Result<TokenResponse, _> = serde_json::from_str(&response);

    match token_response {
        Ok(token_response) => {
            tracing::info!("Access token: {}", token_response.access_token);
            tracing::info!("Id token: {}", token_response.id_token);
            state
                .write()
                .unwrap()
                .db
                .insert(ACCESS_TOKEN, token_response.access_token);
            state
                .write()
                .unwrap()
                .db
                .insert(ID_TOKEN, token_response.id_token);

            Ok(Redirect::permanent("/"))
        }
        Err(_) => {
            let error_response: Result<ErrorResponse, _> = serde_json::from_str(&response);

            match error_response {
                Ok(error_response) => Err((anyhow!(
                    "{}: {}",
                    error_response.error,
                    error_response.error_description
                ))
                .into()),
                Err(_) => Err(anyhow!("Could not understand token response").into()),
            }
        }
    }
}

#[derive(Debug, Deserialize)]
struct QueryParams {
    code: String,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    id_token: String,
}

#[derive(Serialize)]
struct Authenticated {
    access_token: String,
    id_token: String,
}

#[derive(Deserialize)]
struct ErrorResponse {
    error: String,
    error_description: String,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Something went wrong: {}", self.0),
        )
            .into_response()
    }
}

struct AppError(anyhow::Error);

impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}
