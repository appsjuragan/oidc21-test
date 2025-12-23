use axum::Json;
use serde::{Deserialize, Serialize};

use crate::error::AppResult;

/// Token Introspection Request (RFC 7662)
#[derive(Debug, Deserialize)]
pub struct IntrospectRequest {
    pub token: String,
    pub token_type_hint: Option<String>,
}

/// Token Introspection Response
#[derive(Debug, Serialize)]
pub struct IntrospectResponse {
    pub active: bool,
    pub scope: Option<String>,
    pub client_id: Option<String>,
    pub username: Option<String>,
    pub token_type: Option<String>,
    pub exp: Option<i64>,
    pub iat: Option<i64>,
    pub sub: Option<String>,
}

/// Token introspection endpoint handler
/// POST /introspect
///
/// Returns metadata about a token
pub async fn introspect(
    Json(_request): Json<IntrospectRequest>,
) -> AppResult<Json<IntrospectResponse>> {
    // TODO: Implement introspection:
    // 1. Authenticate client (required)
    // 2. Parse and validate token
    // 3. Check if revoked
    // 4. Return token metadata

    Err(crate::error::AppError::InvalidRequest(
        "Not implemented yet".to_string(),
    ))
}
