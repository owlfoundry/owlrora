use axum::{
    Json,
    extract::{FromRequest, Request},
};
use serde::de::DeserializeOwned;

use super::{ApiError, auth::request_id};

pub struct ApiJson<T>(pub T);

impl<S, T> FromRequest<S> for ApiJson<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = ApiError;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        let request_id = request_id(request.headers());
        Json::<T>::from_request(request, state)
            .await
            .map(|Json(value)| Self(value))
            .map_err(|error| ApiError::validation(error.body_text(), request_id))
    }
}

#[derive(Clone, Debug, Default, serde::Deserialize)]
pub struct PageQuery {
    pub cursor: Option<String>,
    pub limit: Option<u32>,
}

#[derive(Clone, Debug, Default, serde::Deserialize)]
pub struct LoginQuery {
    pub return_to: Option<String>,
}

#[derive(Clone, Debug, serde::Deserialize)]
pub struct CallbackQuery {
    pub state: String,
    pub code: String,
}
