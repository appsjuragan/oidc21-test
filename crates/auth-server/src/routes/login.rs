use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};


use crate::{error::{AppError, AppResult}, state::AppState};
use audit::AuditLogger;
use authentication::{
    verify_password, MfaManager, SessionConfig, SessionManager,
};
use users::UserRepository;

/// Login request
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
    pub mfa_code: Option<String>,
    pub device_fingerprint: Option<String>,
}

/// Login response
#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub session_token: String,
    pub user_id: String,
    pub requires_mfa: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mfa_methods: Option<Vec<String>>,
}

/// Login endpoint
/// POST /auth/login
///
/// Authenticates user with email and password
/// Returns session token for subsequent requests
pub async fn login(
    State(state): State<AppState>,
    Json(request): Json<LoginRequest>,
) -> AppResult<Json<LoginResponse>> {
    let audit_logger = AuditLogger::new(state.db.clone());
    let user_repo = UserRepository::new(state.db.clone());

    // Find user by email
    let user = user_repo
        .find_by_email(&request.email)
        .await?
        .ok_or_else(|| {
            // Log failed attempt
            let email = request.email.clone();
            let db = state.db.clone();
            tokio::spawn(async move {
                let logger = AuditLogger::new(db);
                let _ = logger.log_login_failure(
                    &email,
                    "User not found",
                    None,
                    None,
                ).await;
            });
            AppError::Unauthorized("Invalid email or password".to_string())
        })?;

    // Check if account is locked
    if user_repo.is_account_locked(user.id).await? {
        return Err(AppError::Unauthorized(
            "Account temporarily locked due to too many failed attempts".to_string(),
        ));
    }

    // Verify password
    match verify_password(&request.password, &user.password_hash) {
        Ok(_) => {
            // Password correct - reset failed attempts
            user_repo.reset_failed_attempts(user.id).await?;
        }
        Err(_) => {
            // Increment failed attempts
            let attempts = user_repo.increment_failed_attempts(user.id).await?;

            // Lock account after max attempts (OWASP ASVS 2.2.1)
            if attempts >= state.config.security.login_max_attempts as i32 {
                user_repo
                    .lock_account(user.id, state.config.security.login_lockout_duration_seconds)
                    .await?;

                audit_logger
                    .log_account_locked(user.id, "Too many failed login attempts", None)
                    .await?;
            }

            // Log failed attempt
            audit_logger
                .log_login_failure(&request.email, "Invalid password", None, None)
                .await?;

            return Err(AppError::Unauthorized("Invalid email or password".to_string()));
        }
    }

    // Check if MFA is required
    let mfa_manager = MfaManager::new(state.db.clone(), state.config.mfa.totp_issuer.clone());
    let has_mfa = mfa_manager.has_mfa_enrolled(user.id).await?;

    if has_mfa {
        // MFA required but code not provided
        if request.mfa_code.is_none() {
            return Ok(Json(LoginResponse {
                session_token: String::new(), // No session yet
                user_id: user.id.to_string(),
                requires_mfa: true,
                mfa_methods: Some(vec!["totp".to_string()]),
            }));
        }

        // Verify MFA code
        let code = request.mfa_code.as_ref().unwrap();
        if !mfa_manager.verify_totp(user.id, code).await? {
            audit_logger
                .log_login_failure(&request.email, "Invalid MFA code", None, None)
                .await?;

            return Err(AppError::Unauthorized("Invalid MFA code".to_string()));
        }
    }

    // Admin users must have MFA (security policy)
    if user.is_admin && !has_mfa && state.config.mfa.required_for_admin {
        return Err(AppError::Unauthorized(
            "MFA is required for administrator accounts".to_string(),
        ));
    }

    // Create session
    let session_config = SessionConfig {
        idle_timeout_seconds: state.config.session.idle_timeout_seconds,
        absolute_timeout_seconds: state.config.session.absolute_timeout_seconds,
        max_concurrent: state.config.session.max_concurrent,
    };

    let mut session_manager = SessionManager::new(state.redis.clone(), session_config);

    let session = session_manager
        .create_session(
            user.id,
            None, // TODO: Extract from request
            None, // TODO: Extract IP from request
            request.device_fingerprint,
        )
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Failed to create session: {}", e)))?;

    // Update last login
    user_repo.update_last_login(user.id).await?;

    // Audit log successful login
    audit_logger.log_login_success(user.id, None, None).await?;

    Ok(Json(LoginResponse {
        session_token: session.session_token,
        user_id: user.id.to_string(),
        requires_mfa: false,
        mfa_methods: None,
    }))
}

/// Logout endpoint
/// POST /auth/logout
///
/// Invalidates the current session
#[derive(Debug, Deserialize)]
pub struct LogoutRequest {
    pub session_token: String,
}

pub async fn logout(
    State(state): State<AppState>,
    Json(request): Json<LogoutRequest>,
) -> AppResult<()> {
    let session_config = SessionConfig::default();
    let mut session_manager = SessionManager::new(state.redis.clone(), session_config);

    session_manager
        .delete_session(&request.session_token)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Failed to delete session: {}", e)))?;

    Ok(())
}
