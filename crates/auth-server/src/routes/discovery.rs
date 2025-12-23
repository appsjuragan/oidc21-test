use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};

use crate::state::AppState;

/// OpenID Connect Discovery Document (RFC 8414)
#[derive(Debug, Serialize, Deserialize)]
pub struct OpenIdConfiguration {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub jwks_uri: String,
    pub revocation_endpoint: String,
    pub introspection_endpoint: String,
    
    pub response_types_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
    pub subject_types_supported: Vec<String>,
    pub id_token_signing_alg_values_supported: Vec<String>,
    pub scopes_supported: Vec<String>,
    pub token_endpoint_auth_methods_supported: Vec<String>,
    pub claims_supported: Vec<String>,
    pub code_challenge_methods_supported: Vec<String>,
    
    // PKCE support
    pub require_request_uri_registration: bool,
}

/// /.well-known/openid-configuration endpoint
/// Returns server capabilities and endpoint locations
pub async fn openid_configuration(
    State(state): State<AppState>,
) -> Json<OpenIdConfiguration> {
    let base_url = &state.config.server.base_url;

    Json(OpenIdConfiguration {
        issuer: state.config.jwt.issuer.clone(),
        authorization_endpoint: format!("{}/authorize", base_url),
        token_endpoint: format!("{}/token", base_url),
        userinfo_endpoint: format!("{}/userinfo", base_url),
        jwks_uri: format!("{}/jwks", base_url),
        revocation_endpoint: format!("{}/revoke", base_url),
        introspection_endpoint: format!("{}/introspect", base_url),
        
        // OAuth 2.1 only supports authorization code flow
        response_types_supported: vec!["code".to_string()],
        
        grant_types_supported: vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
            "client_credentials".to_string(),
        ],
        
        subject_types_supported: vec!["public".to_string()],
        
        // OWASP recommendation: RS256 or ES256
        id_token_signing_alg_values_supported: vec![
            "RS256".to_string(),
            "ES256".to_string(),
        ],
        
        scopes_supported: vec![
            "openid".to_string(),
            "profile".to_string(),
            "email".to_string(),
            "phone".to_string(),
            "address".to_string(),
        ],
        
        token_endpoint_auth_methods_supported: vec![
            "client_secret_basic".to_string(),
            "client_secret_post".to_string(),
            "private_key_jwt".to_string(),
            "none".to_string(), // Public clients
        ],
        
        claims_supported: vec![
            "sub".to_string(),
            "iss".to_string(),
            "aud".to_string(),
            "exp".to_string(),
            "iat".to_string(),
            "auth_time".to_string(),
            "nonce".to_string(),
            "name".to_string(),
            "email".to_string(),
            "email_verified".to_string(),
            "phone_number".to_string(),
            "phone_number_verified".to_string(),
        ],
        
        // OAuth 2.1 mandates PKCE with S256
        code_challenge_methods_supported: vec!["S256".to_string()],
        
        require_request_uri_registration: false,
    })
}
