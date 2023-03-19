use anyhow::anyhow;
use axum::{
    debug_handler,
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
    routing::get,
    Router,
};
use axum_sessions::{async_session, extractors::WritableSession, SameSite, SessionLayer};
use chrono::{Datelike, Utc};
use data_encoding::{BASE64, BASE64_NOPAD};
use serde::{Deserialize, Serialize};
use std::{error::Error, fs, net::SocketAddr, str};
use tera::{Context, Tera};
use xmltree::Element;

const ACCESS_TOKEN: &str = "access_token";
const ID_TOKEN: &str = "id_token";

#[derive(Clone)]
pub struct Config {
    pub tera: Tera,
    pub client_secret: String,
    pub org_number: String,
    pub year: i32,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();

    let tera = Tera::new("templates/**/*.html")?;

    const SECRET_FILE_NAME: &str = "client_secret.txt";
    tracing::info!("Reading {SECRET_FILE_NAME}");
    let client_secret = fs::read_to_string(SECRET_FILE_NAME)?;

    let store = async_session::MemoryStore::new();
    let secret = b"aAog7DZJZnY6C4J8v0W81NizvjPv3UHHXP9pAJLxV4srnjsTONy5zOXgqPCuaihG";

    // Lax policy, otherwise redirecting to root after auth doesn't work.
    let session_layer = SessionLayer::new(store, secret).with_same_site_policy(SameSite::Lax);

    let config = Config {
        tera,
        client_secret,
        org_number: "999579922".to_string(),
        year: Utc::now().date_naive().year() - 1,
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/logginn", get(logginn))
        .route("/token", get(token))
        .layer(session_layer)
        .with_state(config);

    let addr = SocketAddr::from(([127, 0, 0, 1], 12345));
    tracing::info!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}

#[debug_handler]
async fn index(
    State(config): State<Config>,
    session: WritableSession,
) -> Result<Html<String>, AppError> {
    let access_token: Option<String> = session.get(ACCESS_TOKEN);
    let id_token: Option<String> = session.get(ID_TOKEN);

    match (access_token, id_token) {
        (Some(access_token), Some(id_token)) => {
            let claims_part = id_token.split('.').collect::<Vec<_>>()[1];
            let claims_json =
                str::from_utf8(&BASE64_NOPAD.decode(claims_part.as_bytes())?)?.to_string();
            let claims: IdToken = serde_json::from_str(&claims_json)?;
            let pid = claims.pid;

            let utkast = reqwest::Client::new()
                .get(format!(
                    "https://idporten.api.skatteetaten.no/api/skattemelding/v2/utkast/{}/{}",
                    config.year, config.org_number
                ))
                .header("Authorization", format!("Bearer {access_token}"))
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;

            tracing::info!("Utkast: {utkast}");

            let utkast_xml = Element::parse(utkast.as_bytes())?;
            let skattemeldingdokument = utkast_xml
                .get_child("dokumenter")
                .ok_or_else(|| anyhow!("Did not find 'dokumenter' in XML structure"))?
                .get_child("skattemeldingdokument")
                .ok_or_else(|| anyhow!("Did not find 'skattemeldingdokument' in XML structure"))?;

            let dok_ref = skattemeldingdokument
                .get_child("id")
                .ok_or_else(|| anyhow!("Did not find 'id' in XML structure"))?
                .get_text()
                .ok_or_else(|| anyhow!("'id' did not contain text in XML structure"))?
                .to_string();

            let content_base64 = &skattemeldingdokument
                .get_child("content")
                .ok_or_else(|| anyhow!("Did not find 'content' in XML structure"))?
                .get_text()
                .ok_or_else(|| anyhow!("'content' did not contain text in XML structure"))?;

            let content = str::from_utf8(&BASE64.decode(content_base64.as_bytes())?)?.to_string();

            let content_xml = Element::parse(content.as_bytes())?;
            let partsnummer = content_xml
                .get_child("partsnummer")
                .ok_or_else(|| anyhow!("Did not find 'partsnummer' in XML structure"))?
                .get_text()
                .ok_or_else(|| anyhow!("'id' did not contain text in XML structure"))?
                .to_string();

            Ok(Html(config.tera.render(
                "authenticated.html",
                &Context::from_serialize(&Authenticated {
                    pid,
                    dok_ref,
                    partsnummer,
                })?,
            )?))
        }
        _ => Ok(Html(config.tera.render("guest.html", &Context::new())?)),
    }
}

async fn logginn() -> Redirect {
    // https://oidc.difi.no/idporten-oidc-provider/.well-known/openid-configuration
    Redirect::permanent("https://oidc.difi.no/idporten-oidc-provider/authorize?scope=skatteetaten%3Aformueinntekt%2Fskattemelding%20openid&acr_values=Level3&client_id=4060f6d4-28ab-410d-bf14-edd62aa88dcf&redirect_uri=http%3A%2F%2Flocalhost%3A12345%2Ftoken&response_type=code&state=SgNdr4kEG_EJOptKwlwg5Q&nonce=1678988024798240&code_challenge=v7PyFrwYJeGtsYYchHyjafe4Z_GxMtDUPDuWXX_BRMg=&code_challenge_method=S256&ui_locales=nb")
}

/// Using client defined at
/// https://selvbetjening-samarbeid-prod.difi.no/integrations/4060f6d4-28ab-410d-bf14-edd62aa88dcf
async fn token(
    State(config): State<Config>,
    mut session: WritableSession,
    Query(query_params): Query<QueryParams>,
) -> Result<Redirect, AppError> {
    let form_params = [
        ("grant_type", "authorization_code".to_string()),
        (
            "client_id",
            "4060f6d4-28ab-410d-bf14-edd62aa88dcf".to_string(),
        ),
        ("client_secret", config.client_secret.clone()),
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
        .error_for_status()?
        .text()
        .await?;

    tracing::info!("Token response: {}", response);

    let token_response: Result<TokenResponse, _> = serde_json::from_str(&response);

    match token_response {
        Ok(token_response) => {
            tracing::info!("Access token: {}", token_response.access_token);
            tracing::info!("Id token: {}", token_response.id_token);

            session.insert(ACCESS_TOKEN, token_response.access_token)?;
            session.insert(ID_TOKEN, token_response.id_token)?;

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

#[derive(Deserialize)]
struct IdToken {
    pid: String,
}

#[derive(Serialize)]
struct Authenticated {
    pid: String,
    dok_ref: String,
    partsnummer: String,
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
