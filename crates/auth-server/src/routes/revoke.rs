use axum::Json;
use serde::Deserialize;

use crate::error::AppResult;

/// Token Revocation Request (RFC 7009)
#[derive(Debug, Deserialize)]
pub struct RevokeRequest {
    pub token: String,
    pub token_type_hint: Option<String>, // "access_token" or "refresh_token"
}

/// Token revocation endpoint handler
/// POST /revoke
///
/// Revokes access or refresh tokens
pub async fn revoke(Json(_request): Json<RevokeRequest>) -> AppResult<()> {
    // TODO: Implement revocation:
    // 1. Authenticate client
    // 2. Parse token (JWT or opaque)
    // 3. Invalidate in database/Redis
    // 4. If refresh token, invalidate all associated access tokens
    // 5. Return 200 OK even if token invalid (per RFC 7009)

    Ok(())
}
