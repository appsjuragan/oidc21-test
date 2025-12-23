use axum::{
    extract::State,
    http::{header, StatusCode},
    Json, TypedHeader,
};
use serde::{Deserialize, Serialize};

use crate::{error::{AppError, AppResult}, state::AppState};
use security::verify_access_token;
use users::UserRepository;
use uuid::Uuid;

/// UserInfo Response (OIDC Section 5.3.2)
#[derive(Debug, Serialize, Deserialize)]
pub struct UserInfoResponse {
    pub sub: String,
    
    // Profile scope
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
    
    // Email scope
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    
    // Phone scope
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number_verified: Option<bool>,
}

/// UserInfo endpoint handler
/// GET /userinfo
///
/// Returns claims about the authenticated user
/// Requires valid access token in Authorization header
///
/// Implements GDPR data minimization by only returning claims
/// for scopes granted in the access token
pub async fn userinfo(
    State(state): State<AppState>,
    TypedHeader(authorization): TypedHeader<header::Authorization<header::Bearer>>,
) -> AppResult<Json<UserInfoResponse>> {
    let access_token = authorization.token();

    // Load public key for verification
    let public_key = tokio::fs::read(&state.config.jwt.public_key_path)
        .await
        .map_err(|_| AppError::Internal(anyhow::anyhow!("Failed to load public key")))?;

    // Verify and decode JWT
    let claims = verify_access_token(
        access_token,
        &public_key,
        &state.config.jwt.issuer,
    )
    .map_err(|_| AppError::Unauthorized("Invalid or expired access token".to_string()))?;

    // Parse user ID from subject
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| AppError::Internal(anyhow::anyhow!("Invalid user ID in token")))?;

    // Load user data
    let user_repo = UserRepository::new(state.db.clone());
    let user = user_repo
        .find_by_id(user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    // Parse granted scopes
    let scopes: Vec<&str> = claims.scope
        .as_ref()
        .map(|s| s.split_whitespace().collect())
        .unwrap_or_default();

    // Build response based on granted scopes (GDPR data minimization)
    let mut response = UserInfoResponse {
        sub: claims.sub.clone(), // Always include subject
        name: None,
        picture: None,
        email: None,
        email_verified: None,
        phone_number: None,
        phone_number_verified: None,
    };

    // Profile scope
    if scopes.contains(&"profile") {
        response.name = user.name.clone();
        response.picture = user.picture_url.clone();
    }

    // Email scope
    if scopes.contains(&"email") {
        response.email = Some(user.email.clone());
        response.email_verified = Some(user.email_verified);
    }

    // Phone scope
    if scopes.contains(&"phone") {
        response.phone_number = user.phone_number.clone();
        response.phone_number_verified = user.phone_number_verified;
    }

    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_userinfo_serialization() {
        let response = UserInfoResponse {
            sub: "user123".to_string(),
            name: Some("John Doe".to_string()),
            picture: None,
            email: Some("john@example.com".to_string()),
            email_verified: Some(true),
            phone_number: None,
            phone_number_verified: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        
        // Should not include null fields
        assert!(!json.contains("picture"));
        assert!(!json.contains("phone_number"));
        
        // Should include non-null fields
        assert!(json.contains("sub"));
        assert!(json.contains("name"));
        assert!(json.contains("email"));
    }
}
