use axum::{extract::{Query, State}, response::Redirect};
use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::{error::AppResult, state::AppState};

/// OAuth 2.1 Authorization Request (Section 4.1.1)
/// Mandatory PKCE parameters required
#[derive(Debug, Deserialize, Validate)]
pub struct AuthorizationRequest {
    /// REQUIRED: Must be "code" for authorization code flow
    pub response_type: String,
    
    /// REQUIRED: Client identifier
    pub client_id: String,
    
    /// REQUIRED: Exact redirect URI (must match registered URI)
    #[validate(url)]
    pub redirect_uri: String,
    
    /// RECOMMENDED: Space-delimited scope values
    pub scope: Option<String>,
    
    /// RECOMMENDED: Opaque value for CSRF protection
    pub state: Option<String>,
    
    /// REQUIRED (OAuth 2.1): Code challenge (Base64-URL SHA256 of verifier)
    pub code_challenge: String,
    
    /// REQUIRED (OAuth 2.1): Must be "S256" for security
    pub code_challenge_method: String,
    
    /// OPTIONAL: Nonce for ID token replay prevention
    pub nonce: Option<String>,
}

/// Authorization endpoint handler
/// GET /authorize
///
/// This implements the OAuth 2.1 authorization code flow (Section 4.1)
/// with mandatory PKCE protection.
pub async fn authorize(
    State(_state): State<AppState>,
    Query(params): Query<AuthorizationRequest>,
) -> AppResult<Redirect> {
    // Validate request parameters
    params.validate()
        .map_err(|e| crate::error::AppError::InvalidRequest(e.to_string()))?;

    // OAuth 2.1: Only "code" response type is supported (no implicit flow)
    if params.response_type != "code" {
        return Err(crate::error::AppError::InvalidRequest(
            "Invalid response_type. Only 'code' is supported".to_string(),
        ));
    }

    // OAuth 2.1: PKCE is mandatory, only S256 method allowed
    if params.code_challenge_method != "S256" {
        return Err(crate::error::AppError::InvalidRequest(
            "Invalid code_challenge_method. Only 'S256' is supported".to_string(),
        ));
    }

    // TODO: Implement authorization flow:
    // 1. Validate client_id exists and is active
    // 2. Validate redirect_uri matches registered URI (exact match)
    // 3. Check if user is authenticated (session)
    // 4. If not authenticated, redirect to login page
    // 5. If authenticated, show consent screen (if needed)
    // 6. Generate authorization code with PKCE challenge
    // 7. Store authorization code in database/Redis
    // 8. Redirect back to redirect_uri with code and state

    // Placeholder response
    Ok(Redirect::to("/login"))
}
