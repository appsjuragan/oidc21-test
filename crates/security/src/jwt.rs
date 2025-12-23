use anyhow::Result;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum JwtError {
    #[error("JWT encoding error: {0}")]
    EncodingError(#[from] jsonwebtoken::errors::Error),
    
    #[error("Invalid token")]
    InvalidToken,
    
    #[error("Token expired")]
    TokenExpired,
}

/// JWT Claims for access tokens
#[derive(Debug, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    /// Subject (user ID)
    pub sub: String,
    
    /// Issuer
    pub iss: String,
    
    /// Audience (client ID)
    pub aud: String,
    
    /// Expiration time (Unix timestamp)
    pub exp: i64,
    
    /// Issued at (Unix timestamp)
    pub iat: i64,
    
    /// JWT ID (unique identifier for token)
    pub jti: String,
    
    /// Scope
    pub scope: Option<String>,
    
    /// Client ID
    pub client_id: String,
}

/// JWT Claims for ID tokens (OIDC)
#[derive(Debug, Serialize, Deserialize)]
pub struct IdTokenClaims {
    pub sub: String,
    pub iss: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    
    /// Authentication time
    pub auth_time: Option<i64>,
    
    /// Nonce (OIDC replay prevention)
    pub nonce: Option<String>,
    
    // Standard claims
    pub name: Option<String>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub phone_number: Option<String>,
    pub phone_number_verified: Option<bool>,
    pub picture: Option<String>,
}

/// Generate access token JWT
///
/// Uses RS256 (RSA-SHA256) algorithm for signing
/// 
/// # Arguments
/// * `user_id` - User identifier
/// * `client_id` - OAuth client ID
/// * `issuer` - Token issuer
/// * `scope` - Granted scopes
/// * `expires_in_seconds` - Token lifetime
/// * `private_key_pem` - PEM-encoded RSA private key
pub fn create_access_token(
    user_id: &str,
    client_id: &str,
    issuer: &str,
    scope: Option<String>,
    expires_in_seconds: i64,
    private_key_pem: &[u8],
) -> Result<String, JwtError> {
    let now = Utc::now();
    let exp = (now + Duration::seconds(expires_in_seconds)).timestamp();

    let claims = AccessTokenClaims {
        sub: user_id.to_string(),
        iss: issuer.to_string(),
        aud: client_id.to_string(),
        exp,
        iat: now.timestamp(),
        jti: Uuid::new_v4().to_string(),
        scope,
        client_id: client_id.to_string(),
    };

    let encoding_key = EncodingKey::from_rsa_pem(private_key_pem)?;
    let header = Header::new(Algorithm::RS256);
    
    let token = encode(&header, &claims, &encoding_key)?;
    Ok(token)
}

/// Verify and decode access token
///
/// # Arguments
/// * `token` - JWT token string
/// * `public_key_pem` - PEM-encoded RSA public key
/// * `expected_issuer` - Expected token issuer for validation
pub fn verify_access_token(
    token: &str,
    public_key_pem: &[u8],
    expected_issuer: &str,
) -> Result<AccessTokenClaims, JwtError> {
    let decoding_key = DecodingKey::from_rsa_pem(public_key_pem)?;
    
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[expected_issuer]);
    
    let token_data = decode::<AccessTokenClaims>(token, &decoding_key, &validation)?;
    Ok(token_data.claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: These tests would need actual RSA key pair
    // For production, generate keys with:
    // openssl genrsa -out private.pem 4096
    // openssl rsa -in private.pem -pubout -out public.pem
}
