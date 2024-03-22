use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    pub error_description: String,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Html(format!(
                r#"<html>
            <head>
              <title>Skattemelding feil</title>
              <meta
                http-equiv="Cache-Control"
                content="no-cache, no-store, must-revalidate"
              />
              <meta http-equiv="Pragma" content="no-cache" />
              <meta http-equiv="Expires" content="0" />
            </head>
            <body>
              <p>Ein feil oppstod:</p>
              <pre>{}</pre>
              <a href="/">Tilbake til start</a>
            </body>
          </html>
          "#,
                self.0,
            )),
        )
            .into_response()
    }
}

pub struct AppError(anyhow::Error);

impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}
