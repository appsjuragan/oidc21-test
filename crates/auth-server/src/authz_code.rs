use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use security::{generate_authorization_code, verify_code_verifier};
use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum AuthCodeError {
    #[error("Authorization code not found or expired")]
    NotFound,
    
    #[error("Authorization code already used")]
    AlreadyUsed,
    
    #[error("PKCE verification failed")]
    PkceVerificationFailed,
    
    #[error("Redirect URI mismatch")]
    RedirectUriMismatch,
    
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
}

#[derive(Debug, sqlx::FromRow)]
pub struct AuthorizationCode {
    pub id: Uuid,
    pub code: String,
    pub client_id: Uuid,
    pub user_id: Uuid,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub nonce: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Authorization code repository
pub struct AuthCodeRepository {
    pool: PgPool,
}

impl AuthCodeRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create a new authorization code
    ///
    /// # Arguments
    /// * `client_id` - OAuth client ID
    /// * `user_id` - User ID
    /// * `code_challenge` - PKCE code challenge (Base64url SHA256)
    /// * `code_challenge_method` - Must be "S256"
    /// * `redirect_uri` - Redirect URI from authorization request
    /// * `scope` - Granted scopes
    /// * `nonce` - OIDC nonce (optional)
    /// * `expires_in_seconds` - Code lifetime (default: 600 = 10 minutes)
    pub async fn create(
        &self,
        client_id: Uuid,
        user_id: Uuid,
        code_challenge: &str,
        code_challenge_method: &str,
        redirect_uri: &str,
        scope: Option<&str>,
        nonce: Option<&str>,
        expires_in_seconds: i64,
    ) -> Result<String, AuthCodeError> {
        let code = generate_authorization_code();
        let expires_at = Utc::now() + Duration::seconds(expires_in_seconds);

        sqlx::query(
            r#"
            INSERT INTO authorization_codes (
                code, client_id, user_id, code_challenge, code_challenge_method,
                redirect_uri, scope, nonce, expires_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#
        )
        .bind(&code)
        .bind(client_id)
        .bind(user_id)
        .bind(code_challenge)
        .bind(code_challenge_method)
        .bind(redirect_uri)
        .bind(scope)
        .bind(nonce)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;

        Ok(code)
    }

    /// Exchange authorization code for tokens
    ///
    /// Validates:
    /// - Code exists and not expired
    /// - Code not already used
    /// - PKCE code verifier
    /// - Redirect URI matches
    ///
    /// Returns the authorization code record and marks it as used
    pub async fn exchange(
        &self,
        code: &str,
        code_verifier: &str,
        redirect_uri: &str,
    ) -> Result<AuthorizationCode, AuthCodeError> {
        // Fetch authorization code
        let auth_code = sqlx::query_as::<_, AuthorizationCode>(
            "SELECT * FROM authorization_codes WHERE code = $1"
        )
        .bind(code)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(AuthCodeError::NotFound)?;

        // Check if expired
        if auth_code.expires_at < Utc::now() {
            return Err(AuthCodeError::NotFound);
        }

        // Check if already used (single-use requirement)
        if auth_code.used_at.is_some() {
            return Err(AuthCodeError::AlreadyUsed);
        }

        // Validate PKCE
        verify_code_verifier(
            code_verifier,
            &auth_code.code_challenge,
            &auth_code.code_challenge_method,
        )
        .map_err(|_| AuthCodeError::PkceVerificationFailed)?;

        // Validate redirect URI (exact match required)
        if auth_code.redirect_uri != redirect_uri {
            return Err(AuthCodeError::RedirectUriMismatch);
        }

        // Mark as used
        sqlx::query(
            "UPDATE authorization_codes SET used_at = NOW() WHERE code = $1"
        )
        .bind(code)
        .execute(&self.pool)
        .await?;

        Ok(auth_code)
    }

    /// Delete expired authorization codes (cleanup)
    pub async fn delete_expired(&self) -> Result<u64, AuthCodeError> {
        let result = sqlx::query(
            "DELETE FROM authorization_codes WHERE expires_at < NOW()"
        )
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests require database connection
}
