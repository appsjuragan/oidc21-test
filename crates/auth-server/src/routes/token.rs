use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::Row;
use uuid::Uuid;

use crate::{authz_code::AuthCodeRepository, error::{AppError, AppResult}, state::AppState};
use authentication::verify_password;
use audit::{ AuditLogger, EventType};
use clients::ClientRepository;
use security::{create_access_token, generate_refresh_token};

/// Token Request (OAuth 2.1 Section 4.1.3)
#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    
    // Authorization code grant
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub code_verifier: Option<String>,
    
    // Client credentials
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    
    // Refresh token grant
    pub refresh_token: Option<String>,
    
    pub scope: Option<String>,
}

/// Token Response (OAuth 2.1 Section 4.1.4)
#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>, // OIDC
}

pub async fn token(
    State(state): State<AppState>,
    Json(request): Json<TokenRequest>,
) -> AppResult<Json<TokenResponse>> {
    match request.grant_type.as_str() {
        "authorization_code" => handle_authorization_code_grant(state, request).await,
        "refresh_token" => handle_refresh_token_grant(state, request).await,
        "client_credentials" => handle_client_credentials_grant(state, request).await,
        _ => Err(AppError::InvalidRequest(format!(
            "Unsupported grant_type: {}",
            request.grant_type
        ))),
    }
}

async fn handle_authorization_code_grant(
    state: AppState,
    request: TokenRequest,
) -> AppResult<Json<TokenResponse>> {
    let code = request
        .code
        .ok_or_else(|| AppError::InvalidRequest("Missing 'code' parameter".to_string()))?;
    
    let redirect_uri = request
        .redirect_uri
        .ok_or_else(|| AppError::InvalidRequest("Missing 'redirect_uri' parameter".to_string()))?;
    
    let code_verifier = request
        .code_verifier
        .ok_or_else(|| AppError::InvalidRequest("Missing 'code_verifier' parameter (PKCE required)".to_string()))?;
    
    let client_id_str = request
        .client_id
        .ok_or_else(|| AppError::InvalidRequest("Missing 'client_id' parameter".to_string()))?;

    let auth_code_repo = AuthCodeRepository::new(state.db.clone());
    let auth_code = auth_code_repo
        .exchange(&code, &code_verifier, &redirect_uri)
        .await
        .map_err(|e| AppError::InvalidRequest(e.to_string()))?;

    let client_repo = ClientRepository::new(state.db.clone());
    let client = client_repo
        .find_by_id(auth_code.client_id)
        .await?
        .ok_or_else(|| AppError::InvalidRequest("Invalid client".to_string()))?;

    if client.client_id != client_id_str {
        return Err(AppError::InvalidRequest("Client ID mismatch".to_string()));
    }

    if client_repo.is_confidential(&client) {
        let client_secret = request
            .client_secret
            .ok_or_else(|| AppError::Unauthorized("Client authentication required".to_string()))?;
        
        let secret_hash = client.client_secret_hash
            .ok_or_else(|| AppError::InvalidRequest("Client misconfigured".to_string()))?;
        
        verify_password(&client_secret, &secret_hash)
            .map_err(|_| AppError::Unauthorized("Invalid client credentials".to_string()))?;
    }

    let private_key = tokio::fs::read(&state.config.jwt.private_key_path)
        .await
        .map_err(|_| AppError::Internal(anyhow::anyhow!("Failed to load private key")))?;

    let access_token = create_access_token(
        &auth_code.user_id.to_string(),
        &client.client_id,
        &state.config.jwt.issuer,
        auth_code.scope.clone(),
        state.config.jwt.access_token_expiration_seconds,
        &private_key,
    )
    .map_err(|e| AppError::Internal(anyhow::anyhow!("Failed to create access token: {}", e)))?;

    let refresh_token_value = generate_refresh_token();
    let mut hasher = Sha256::new();
    hasher.update(&refresh_token_value);
    let refresh_token_hash = format!("{:x}", hasher.finalize());

    let refresh_expires_at = chrono::Utc::now()
        + chrono::Duration::seconds(state.config.jwt.refresh_token_expiration_seconds);
    
    // Refactored from sqlx::query! to sqlx::query
    sqlx::query(
        r#"
        INSERT INTO refresh_tokens (token_hash, client_id, user_id, scope, expires_at)
        VALUES ($1, $2, $3, $4, $5)
        "#
    )
    .bind(&refresh_token_hash)
    .bind(auth_code.client_id)
    .bind(auth_code.user_id)
    .bind(&auth_code.scope)
    .bind(refresh_expires_at)
    .execute(&state.db)
    .await?;

    let mut hasher = Sha256::new();
    hasher.update(&access_token);
    let access_token_hash = format!("{:x}", hasher.finalize());
    
    let access_expires_at = chrono::Utc::now()
        + chrono::Duration::seconds(state.config.jwt.access_token_expiration_seconds);
    
    // Refactored from sqlx::query! to sqlx::query
    sqlx::query(
        r#"
        INSERT INTO access_tokens (token_hash, client_id, user_id, scope, expires_at)
        VALUES ($1, $2, $3, $4, $5)
        "#
    )
    .bind(&access_token_hash)
    .bind(auth_code.client_id)
    .bind(auth_code.user_id)
    .bind(&auth_code.scope)
    .bind(access_expires_at)
    .execute(&state.db)
    .await?;

    let audit_logger = AuditLogger::new(state.db.clone());
    audit_logger
        .log_token_issued(
            Some(auth_code.user_id),
            auth_code.client_id,
            "authorization_code",
            auth_code.scope.as_deref(),
        )
        .await?;

    Ok(Json(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: state.config.jwt.access_token_expiration_seconds,
        refresh_token: Some(refresh_token_value),
        scope: auth_code.scope,
        id_token: None,
    }))
}

async fn handle_refresh_token_grant(
    state: AppState,
    request: TokenRequest,
) -> AppResult<Json<TokenResponse>> {
    let refresh_token_value = request
        .refresh_token
        .ok_or_else(|| AppError::InvalidRequest("Missing 'refresh_token' parameter".to_string()))?;

    let mut hasher = Sha256::new();
    hasher.update(&refresh_token_value);
    let refresh_token_hash = format!("{:x}", hasher.finalize());

    // Refactored from sqlx::query! to sqlx::query
    let row = sqlx::query(
        r#"
        SELECT id, client_id, user_id, scope, expires_at, used_at, revoked_at
        FROM refresh_tokens
        WHERE token_hash = $1
        "#,
    )
    .bind(&refresh_token_hash)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::Unauthorized("Invalid refresh token".to_string()))?;

    // Manual extraction since we don't have a struct handy
    let id: Uuid = row.try_get("id")?;
    let client_id: Uuid = row.try_get("client_id")?;
    let user_id: Uuid = row.try_get("user_id")?;
    let scope: Option<String> = row.try_get("scope")?;
    let expires_at: chrono::DateTime<chrono::Utc> = row.try_get("expires_at")?;
    let used_at: Option<chrono::DateTime<chrono::Utc>> = row.try_get("used_at")?;
    let revoked_at: Option<chrono::DateTime<chrono::Utc>> = row.try_get("revoked_at")?;

    if expires_at < chrono::Utc::now() {
        return Err(AppError::Unauthorized("Refresh token expired".to_string()));
    }

    if used_at.is_some() || revoked_at.is_some() {
        return Err(AppError::Unauthorized("Refresh token invalid".to_string()));
    }

    // Refactored from sqlx::query! to sqlx::query
    sqlx::query("UPDATE refresh_tokens SET used_at = NOW() WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await?;

    let private_key = tokio::fs::read(&state.config.jwt.private_key_path)
        .await
        .map_err(|_| AppError::Internal(anyhow::anyhow!("Failed to load private key")))?;

    let client_repo = ClientRepository::new(state.db.clone());
    let client = client_repo
        .find_by_id(client_id)
        .await?
        .ok_or_else(|| AppError::InvalidRequest("Client not found".to_string()))?;

    let access_token = create_access_token(
        &user_id.to_string(),
        &client.client_id,
        &state.config.jwt.issuer,
        scope.clone(),
        state.config.jwt.access_token_expiration_seconds,
        &private_key,
    )
    .map_err(|e| AppError::Internal(anyhow::anyhow!("Failed to create access token: {}", e)))?;

    let new_refresh_token_value = generate_refresh_token();
    let mut hasher = Sha256::new();
    hasher.update(&new_refresh_token_value);
    let new_refresh_token_hash = format!("{:x}", hasher.finalize());

    let refresh_expires_at = chrono::Utc::now()
        + chrono::Duration::seconds(state.config.jwt.refresh_token_expiration_seconds);
    
    // Refactored from sqlx::query! to sqlx::query
    sqlx::query(
        r#"
        INSERT INTO refresh_tokens (token_hash, client_id, user_id, scope, expires_at, parent_token_id)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#
    )
    .bind(&new_refresh_token_hash)
    .bind(client_id)
    .bind(user_id)
    .bind(&scope)
    .bind(refresh_expires_at)
    .bind(id)
    .execute(&state.db)
    .await?;

    let audit_logger = AuditLogger::new(state.db.clone());
    audit_logger
        .log_token_issued(
            Some(user_id),
            client_id,
            "refresh_token",
            scope.as_deref(),
        )
        .await?;

    Ok(Json(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: state.config.jwt.access_token_expiration_seconds,
        refresh_token: Some(new_refresh_token_value),
        scope,
        id_token: None,
    }))
}

async fn handle_client_credentials_grant(
    state: AppState,
    request: TokenRequest,
) -> AppResult<Json<TokenResponse>> {
    let client_id = request
        .client_id
        .ok_or_else(|| AppError::InvalidRequest("Missing 'client_id' parameter".to_string()))?;
    
    let client_secret = request
        .client_secret
        .ok_or_else(|| AppError::Unauthorized("Client authentication required".to_string()))?;

    let client_repo = ClientRepository::new(state.db.clone());
    let client = client_repo
        .find_by_client_id(&client_id)
        .await?
        .ok_or_else(|| AppError::Unauthorized("Invalid client credentials".to_string()))?;

    let secret_hash = client.client_secret_hash
        .clone()
        .ok_or_else(|| AppError::Unauthorized("Public clients cannot use client_credentials grant".to_string()))?;
    
    verify_password(&client_secret, &secret_hash)
        .map_err(|_| AppError::Unauthorized("Invalid client credentials".to_string()))?;

    if !client_repo.validate_grant_type(&client, "client_credentials") {
        return Err(AppError::InvalidRequest(
            "client_credentials grant not allowed for this client".to_string(),
        ));
    }

    let private_key = tokio::fs::read(&state.config.jwt.private_key_path)
        .await
        .map_err(|_| AppError::Internal(anyhow::anyhow!("Failed to load private key")))?;

    let access_token = create_access_token(
        &client.client_id,
        &client.client_id,
        &state.config.jwt.issuer,
        request.scope.clone(),
        state.config.jwt.access_token_expiration_seconds,
        &private_key,
    )
    .map_err(|e| AppError::Internal(anyhow::anyhow!("Failed to create access token: {}", e)))?;

    let mut hasher = Sha256::new();
    hasher.update(&access_token);
    let access_token_hash = format!("{:x}", hasher.finalize());
    
    let access_expires_at = chrono::Utc::now()
        + chrono::Duration::seconds(state.config.jwt.access_token_expiration_seconds);
    
    // Refactored from sqlx::query! to sqlx::query
    sqlx::query(
        r#"
        INSERT INTO access_tokens (token_hash, client_id, user_id, scope, expires_at)
        VALUES ($1, $2, NULL, $3, $4)
        "#
    )
    .bind(&access_token_hash)
    .bind(client.id)
    .bind(&request.scope)
    .bind(access_expires_at)
    .execute(&state.db)
    .await?;

    let audit_logger = AuditLogger::new(state.db.clone());
    audit_logger
        .log_token_issued(
            None,
            client.id,
            "client_credentials",
            request.scope.as_deref(),
        )
        .await?;

    Ok(Json(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: state.config.jwt.access_token_expiration_seconds,
        refresh_token: None,
        scope: request.scope,
        id_token: None,
    }))
}
