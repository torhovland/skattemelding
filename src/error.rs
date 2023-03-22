use axum::response::{IntoResponse, Response};
use reqwest::StatusCode;
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
            format!("Something went wrong: {}", self.0),
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
