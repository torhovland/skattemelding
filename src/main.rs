use anyhow::{anyhow, Result};
use axum::{
    debug_handler,
    extract::{Query, State},
    response::{Html, Redirect},
    routing::get,
    Router,
};
use axum_sessions::{async_session, extractors::WritableSession, SameSite, SessionLayer};
use chrono::{Datelike, Utc};
use serde::{Deserialize, Serialize};
use std::{error::Error, fs, net::SocketAddr, str};
use tera::{Context, Tera};

use crate::{
    base64::{decode, encode},
    error::{AppError, ErrorResponse},
    file::{read_naeringsspesifikasjon, read_skattemelding},
    http::post,
    jwt::{IdToken, TokenResponse},
    xml::{to_xml, XmlElement, XmlNode},
};

mod base64;
mod error;
mod file;
mod http;
mod jwt;
mod xml;

const ACCESS_TOKEN: &str = "access_token";
const ID_TOKEN: &str = "id_token";
const KONVOLUTT: &str = "konvolutt";

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
        .route("/altinn", get(altinn))
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
    mut session: WritableSession,
) -> Result<Html<String>, AppError> {
    let access_token: Option<String> = session.get(ACCESS_TOKEN);
    let id_token: Option<String> = session.get(ID_TOKEN);

    match (access_token, id_token) {
        (Some(access_token), Some(id_token)) => {
            let pid = IdToken::from_str(&id_token)?.pid;

            let utkast = http::get_text(
                &format!(
                    "https://idporten.api.skatteetaten.no/api/skattemelding/v2/utkast/{}/{}",
                    config.year, config.org_number
                ),
                &access_token,
            )
            .await?;

            tracing::info!("Utkast: {utkast}");

            let gjeldende = http::get_text(
                &format!(
                    "https://idporten.api.skatteetaten.no/api/skattemelding/v2/{}/{}",
                    config.year, config.org_number
                ),
                &access_token,
            )
            .await?;

            tracing::info!("Gjeldende: {gjeldende}");

            let fastsatt = http::get_text(
                &format!(
                    "https://idporten.api.skatteetaten.no/api/skattemelding/v2/fastsatt/{}/{}",
                    config.year, config.org_number
                ),
                &access_token,
            )
            .await;

            if let Ok(fastsatt) = fastsatt {
                tracing::info!("Fastsatt: {fastsatt}");
            } else {
                tracing::info!("Ingen fastsetting per no.");
            }

            let gjeldende_xml = to_xml(&gjeldende)?;
            let skattemeldingdokument = gjeldende_xml
                .child("dokumenter")?
                .child("skattemeldingdokument")?;

            let dok_ref = skattemeldingdokument.child("id")?.text()?;
            let content_base64 = &skattemeldingdokument.child("content")?.text()?;
            let content = decode(content_base64)?;

            let content_xml = to_xml(&content)?;
            let partsnummer = content_xml.child("partsnummer")?.text()?;

            let skattemelding = read_skattemelding(config.year)?;
            let skattemelding_base64 = encode(&skattemelding);

            let naeringsspesifikasjon = read_naeringsspesifikasjon(config.year)?;
            let naeringsspesifikasjon_base64 = encode(&naeringsspesifikasjon);

            let konvolutt = format!(
                r#"<?xml version="1.0" encoding="utf-8" ?>
            <skattemeldingOgNaeringsspesifikasjonRequest xmlns="no:skatteetaten:fastsetting:formueinntekt:skattemeldingognaeringsspesifikasjon:request:v2">
                <dokumenter>
                    <dokument>
                        <type>skattemeldingUpersonlig</type>
                        <encoding>utf-8</encoding>
                        <content>{}</content>
                    </dokument>
                    <dokument>
                        <type>naeringsspesifikasjon</type>
                        <encoding>utf-8</encoding>
                        <content>{}</content>
                    </dokument>
                </dokumenter>
                <dokumentreferanseTilGjeldendeDokument>
                    <dokumenttype>skattemeldingUpersonlig</dokumenttype>
                    <dokumentidentifikator>{}</dokumentidentifikator>
                </dokumentreferanseTilGjeldendeDokument>
                <inntektsaar>{}</inntektsaar>
                <innsendingsinformasjon>
                    <innsendingstype>komplett</innsendingstype>
                    <opprettetAv>Tor Hovland</opprettetAv>
                </innsendingsinformasjon>
            </skattemeldingOgNaeringsspesifikasjonRequest>"#,
                skattemelding_base64, naeringsspesifikasjon_base64, dok_ref, config.year
            );

            tracing::debug!("Konvolutt: {konvolutt}");
            session.insert(KONVOLUTT, konvolutt.clone())?;

            let validation_response = post(
                &format!(
                    "https://idporten.api.skatteetaten.no/api/skattemelding/v2/valider/{}/{}",
                    config.year, config.org_number
                ),
                Some(&access_token),
            )
            .header("Content-Type", "application/xml")
            .body(konvolutt)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;

            tracing::info!("Validation response: {}", validation_response);

            let validation_xml = to_xml(&validation_response)?;
            let validation = validation_xml.format()?;

            let dokumenter = validation_xml.child("dokumenter");

            let dokumenter = if let Ok(dokumenter) = dokumenter {
                dokumenter
                    .children
                    .iter()
                    .map(|d| {
                        let encoded = d.element()?.child("content")?.text()?;
                        let decoded = decode(&encoded)?;
                        let xml = to_xml(&decoded)?;
                        xml.format()
                    })
                    .collect::<Result<Vec<_>>>()?
            } else {
                vec![]
            };

            Ok(Html(config.tera.render(
                "validation.html",
                &Context::from_serialize(Validation {
                    pid,
                    dok_ref: &dok_ref,
                    partsnummer: &partsnummer,
                    validation: &validation,
                    dokumenter,
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

    let response = post("https://oidc.difi.no/idporten-oidc-provider/token", None)
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
                _ => Err(anyhow!("Could not understand token response").into()),
            }
        }
    }
}

async fn altinn(
    State(config): State<Config>,
    session: WritableSession,
) -> Result<Redirect, AppError> {
    let access_token: Option<String> = session.get(ACCESS_TOKEN);
    let konvolutt: Option<String> = session.get(KONVOLUTT);

    tracing::info!("Access token: {access_token:?}");

    match (access_token, konvolutt) {
        (Some(access_token), Some(konvolutt)) => {
            let altinn_token = http::get(
                "https://platform.altinn.no/authentication/api/v1/exchange/id-porten",
                Some(&access_token),
            )
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;

            tracing::info!("Altinn token: {altinn_token}");

            let instances_response = http::get("https://skd.apps.altinn.no/skd/formueinntekt-skattemelding-v2/instances/60271338/active", Some(&altinn_token))
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;

            tracing::info!("Altinn instances: {instances_response}");

            let instances: Vec<AltinnInstance> = serde_json::from_str(&instances_response)?;

            for instance in instances {
                http::delete(&format!("https://skd.apps.altinn.no/skd/formueinntekt-skattemelding-v2/instances/{}", instance.id), Some(&altinn_token))
                .send()
                .await?
                .error_for_status()?;
            }

            let body = format!("{{\"instanceOwner\": {{\"organisationNumber\": '{}'}},
            \"appOwner\": {{
                \"labels\": [\"gr\", \"x2\"]
                }}, \"appId\": \"skd/formueinntekt-skattemelding-v2\", \"dueBefore\": \"{}-12-31\", \"visibleAfter\": \"{}-01-01\",
                \"title\": {{\"nb\": \"Skattemelding\"}}, \"dataValues\": {{\"inntektsaar\": \"{}\"}}}}", config.org_number, config.year + 1, config.year + 1, config.year);

            tracing::info!("Posting new instance: {}", body);

            let instance_response = http::post(
                "https://skd.apps.altinn.no/skd/formueinntekt-skattemelding-v2/instances",
                Some(&altinn_token),
            )
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;

            tracing::info!("Instance response: {}", instance_response);

            let instance: AltinnInstance = serde_json::from_str(&instance_response)?;

            let upload_response = http::post(&(format!("https://skd.apps.altinn.no/skd/formueinntekt-skattemelding-v2/instances/{}/data?dataType=skattemeldingOgNaeringsspesifikasjon", instance.id)), Some(&altinn_token))
                .header("Content-Type", "text/xml")
                .header(
                    "Content-Disposition",
                    "attachment; filename=skattemelding.xml",
                )
                .body(konvolutt)
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;

            tracing::info!("Upload response: {}", upload_response);

            let endre_prosess_response = http::put(&(format!("https://skd.apps.altinn.no/skd/formueinntekt-skattemelding-v2/instances/{}/process/next", instance.id)), Some(&altinn_token))
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;

            tracing::info!("Endre prosess response: {}", endre_prosess_response);

            let url = format!("https://skatt.skatteetaten.no/web/skattemelding-visning/altinn?appId=skd/formueinntekt-skattemelding-v2&instansId={}", instance.id);
            tracing::info!("Går til visning på {url}");

            Ok(Redirect::permanent(&url))
        }
        _ => {
            tracing::warn!("Fant ingen access token");
            Ok(Redirect::permanent("/"))
        }
    }
}

#[derive(Debug, Deserialize)]
struct QueryParams {
    code: String,
}

#[derive(Serialize)]
struct Validation<'a> {
    pid: String,
    dok_ref: &'a str,
    partsnummer: &'a str,
    validation: &'a str,
    dokumenter: Vec<String>,
}

#[derive(Deserialize)]
struct AltinnInstance {
    id: String,
}
