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
use std::io::Write;
use std::{error::Error, fs, io::BufWriter, net::SocketAddr, str};
use tera::{Context, Tera};
use tokio::fs::File;
use tokio_util::codec::{BytesCodec, FramedRead};
use xmltree::{Element, EmitterConfig};

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

            let skattemelding = fs::read_to_string(format!("{}/skattemelding.xml", config.year))?;
            let skattemelding_base64 = BASE64.encode(skattemelding.as_bytes());

            let naeringsspesifikasjon =
                fs::read_to_string(format!("{}/naeringsspesifikasjon.xml", config.year))?;
            let naeringsspesifikasjon_base64 = BASE64.encode(naeringsspesifikasjon.as_bytes());

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

            let validation_response = reqwest::Client::new()
                .post(format!(
                    "https://idporten.api.skatteetaten.no/api/skattemelding/v2/valider/{}/{}",
                    config.year, config.org_number
                ))
                .header("Authorization", format!("Bearer {access_token}"))
                .header("Content-Type", "application/xml")
                .body(konvolutt)
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;

            tracing::debug!("Validation response: {}", validation_response);

            let validation_xml = Element::parse(validation_response.as_bytes())?;

            let mut cfg = EmitterConfig::new();
            cfg.perform_indent = true;

            let mut buf = BufWriter::new(Vec::new());
            validation_xml.write_with_config(&mut buf, cfg)?;
            let bytes = buf.into_inner()?;
            let validation = String::from_utf8(bytes)?;

            let dokumenter: Vec<_> = validation_xml
                .get_child("dokumenter")
                .ok_or_else(|| anyhow!("Did not find 'dokumenter' in XML structure"))?
                .children
                .iter()
                .map(|d| {
                    let encoded = d
                        .as_element()
                        .unwrap()
                        .get_child("content")
                        .unwrap()
                        .get_text()
                        .unwrap();

                    let decoded = str::from_utf8(&BASE64.decode(encoded.as_bytes()).unwrap())
                        .unwrap()
                        .to_string();

                    let xml = Element::parse(decoded.as_bytes()).unwrap();

                    let mut cfg = EmitterConfig::new();
                    cfg.perform_indent = true;

                    let mut buf = BufWriter::new(Vec::new());
                    xml.write_with_config(&mut buf, cfg).unwrap();
                    let bytes = buf.into_inner().unwrap();
                    String::from_utf8(bytes).unwrap()
                })
                .collect();

            Ok(Html(config.tera.render(
                "validation.html",
                &Context::from_serialize(Validation {
                    pid,
                    dok_ref,
                    partsnummer,
                    validation,
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
            let altinn_token = reqwest::Client::new()
                .get("https://platform.altinn.no/authentication/api/v1/exchange/id-porten")
                .header("Authorization", format!("Bearer {access_token}"))
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;

            tracing::info!("Altinn token: {altinn_token}");

            let claims_part = altinn_token.split('.').collect::<Vec<_>>()[1];
            let claims_json =
                str::from_utf8(&BASE64_NOPAD.decode(claims_part.as_bytes())?)?.to_string();
            let claims: IdToken = serde_json::from_str(&claims_json)?;
            let _pid = claims.pid;

            let instances_response = reqwest::Client::new()
                .get("https://skd.apps.altinn.no/skd/formueinntekt-skattemelding-v2/instances/60271338/active")
                .header("Authorization", format!("Bearer {altinn_token}"))
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;

            tracing::info!("Altinn instances: {instances_response}");

            let instances: Vec<AltinnInstance> = serde_json::from_str(&instances_response)?;

            for instance in instances {
                reqwest::Client::new()
                .delete(format!("https://skd.apps.altinn.no/skd/formueinntekt-skattemelding-v2/instances/{}", instance.id))
                .header("Authorization", format!("Bearer {altinn_token}"))
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

            let instance_response = reqwest::Client::new()
                .post("https://skd.apps.altinn.no/skd/formueinntekt-skattemelding-v2/instances")
                .header("Authorization", format!("Bearer {altinn_token}"))
                .header("Content-Type", "application/json")
                .body(body)
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;

            tracing::info!("Instance response: {}", instance_response);

            let instance: AltinnInstance = serde_json::from_str(&instance_response)?;
            let instance_id = instance.id;

            // let mut file = fs::File::create(format!("{}/validert.xml", config.year))?;
            // file.write_all(validation_response.as_bytes())?;

            // let validert = tokio::fs::File::open(format!("{}/validert.xml", config.year)).await?;

            let url = format!("https://skd.apps.altinn.no/skd/formueinntekt-skattemelding-v2/instances/{instance_id}/data?dataType=skattemeldingOgNaeringsspesifikasjon");
            // let form = reqwest::blocking::multipart::Form::new().file(
            //     "skattemeldingOgNaeringsspesifikasjon.xml",
            //     format!("{}/validert.xml", config.year),
            // )?;

            // req_send_inn = last_opp_skattedata(instans_data, altinn_header,
            //     xml=naering_as,
            //     data_type="skattemeldingOgNaeringsspesifikasjon",
            //     appnavn=altinn3_applikasjon)

            // def last_opp_skattedata(instans_data: dict, token: dict, xml: str,
            //     data_type: str = "skattemelding",
            //     appnavn: str = "skd/formueinntekt-skattemelding-v2") -> requests:
            //     url = f"{ALTINN_URL}/{appnavn}/instances/{instans_data['id']}/data?dataType={data_type}"
            //     token["content-type"] = "text/xml"
            //     token["Content-Disposition"] = "attachment; filename=skattemelding.xml"

            //     r = requests.post(url, data=xml, headers=token, verify=False)

            let upload_response = reqwest::Client::new()
                .post(url)
                // .form(&form)
                .header("Authorization", format!("Bearer {altinn_token}"))
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

            let url = format!("https://skd.apps.altinn.no/skd/formueinntekt-skattemelding-v2/instances/{instance_id}/process/next");
            let endre_prosess_response = reqwest::Client::new()
                .put(url)
                .header("Authorization", format!("Bearer {altinn_token}"))
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;

            tracing::info!("Endre prosess response: {}", endre_prosess_response);

            let url = format!("https://skatt.skatteetaten.no/web/skattemelding-visning/altinn?appId=skd/formueinntekt-skattemelding-v2&instansId={instance_id}");
            tracing::info!("Går til visning på {url}");

            Ok(Redirect::permanent(&url))
        }
        _ => {
            tracing::warn!("Fant ingen access token");
            Ok(Redirect::permanent("/"))
        }
    }
}

fn file_to_body(file: File) -> reqwest::Body {
    let stream = FramedRead::new(file, BytesCodec::new());
    reqwest::Body::wrap_stream(stream)
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
struct Validation {
    pid: String,
    dok_ref: String,
    partsnummer: String,
    validation: String,
    dokumenter: Vec<String>,
}

#[derive(Serialize)]
struct Altinn {
    pid: String,
}

#[derive(Deserialize)]
struct AltinnInstance {
    id: String,
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
