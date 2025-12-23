use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sqlx::PgPool;
use std::net::IpAddr;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventType {
    // Authentication events
    LoginSuccess,
    LoginFailure,
    Logout,
    PasswordChanged,
    EmailVerified,
    MfaEnrolled,
    MfaVerified,
    
    // Authorization events
    TokenIssued,
    TokenRevoked,
    TokenRefreshed,
    ConsentGranted,
    ConsentWithdrawn,
    
    // Data access events
    UserDataExported,
    UserDataDeleted,
    ProfileUpdated,
    
    // Administrative events
    ClientCreated,
    ClientUpdated,
    ClientDeleted,
    UserCreated,
    UserDeactivated,
    
    // Security events
    AccountLocked,
    SuspiciousActivity,
    UnauthorizedAccess,
}

impl EventType {
    pub fn as_str(&self) -> &str {
        match self {
            EventType::LoginSuccess => "login_success",
            EventType::LoginFailure => "login_failure",
            EventType::Logout => "logout",
            EventType::PasswordChanged => "password_changed",
            EventType::EmailVerified => "email_verified",
            EventType::MfaEnrolled => "mfa_enrolled",
            EventType::MfaVerified => "mfa_verified",
            EventType::TokenIssued => "token_issued",
            EventType::TokenRevoked => "token_revoked",
            EventType::TokenRefreshed => "token_refreshed",
            EventType::ConsentGranted => "consent_granted",
            EventType::ConsentWithdrawn => "consent_withdrawn",
            EventType::UserDataExported => "user_data_exported",
            EventType::UserDataDeleted => "user_data_deleted",
            EventType::ProfileUpdated => "profile_updated",
            EventType::ClientCreated => "client_created",
            EventType::ClientUpdated => "client_updated",
            EventType::ClientDeleted => "client_deleted",
            EventType::UserCreated => "user_created",
            EventType::UserDeactivated => "user_deactivated",
            EventType::AccountLocked => "account_locked",
            EventType::SuspiciousActivity => "suspicious_activity",
            EventType::UnauthorizedAccess => "unauthorized_access",
        }
    }
    
    pub fn category(&self) -> &str {
        match self {
            EventType::LoginSuccess | EventType::LoginFailure | EventType::Logout
            | EventType::PasswordChanged | EventType::EmailVerified
            | EventType::MfaEnrolled | EventType::MfaVerified => "authentication",
            
            EventType::TokenIssued | EventType::TokenRevoked | EventType::TokenRefreshed
            | EventType::ConsentGranted | EventType::ConsentWithdrawn => "authorization",
            
            EventType::UserDataExported | EventType::UserDataDeleted
            | EventType::ProfileUpdated => "data_access",
            
            EventType::ClientCreated | EventType::ClientUpdated | EventType::ClientDeleted
            | EventType::UserCreated | EventType::UserDeactivated => "administrative",
            
            EventType::AccountLocked | EventType::SuspiciousActivity
            | EventType::UnauthorizedAccess => "security",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AuditLog {
    pub id: Uuid,
    pub event_type: String,
    pub event_category: String,
    pub user_id: Option<Uuid>,
    pub client_id: Option<Uuid>,
    pub resource: Option<String>,
    pub action: Option<String>,
    pub outcome: String,
    pub ip_address: Option<String>, // Changed to String to simplify mapping
    pub user_agent: Option<String>,
    pub details: Option<JsonValue>,
    pub created_at: DateTime<Utc>,
}

/// Audit logger for ISO 27001 A.12.4 and GDPR Article 30 compliance
pub struct AuditLogger {
    pool: PgPool,
}

impl AuditLogger {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Log an audit event
    pub async fn log(
        &self,
        event_type: EventType,
        user_id: Option<Uuid>,
        client_id: Option<Uuid>,
        resource: Option<String>,
        action: Option<String>,
        outcome: &str,
        ip_address: Option<IpAddr>,
        user_agent: Option<String>,
        details: Option<JsonValue>,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO audit_logs (
                event_type, event_category, user_id, client_id,
                resource, action, outcome, ip_address, user_agent, details
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#
        )
        .bind(event_type.as_str())
        .bind(event_type.category())
        .bind(user_id)
        .bind(client_id)
        .bind(resource)
        .bind(action)
        .bind(outcome)
        .bind(ip_address.map(|ip| ip.to_string())) // Convert IpAddr to String
        .bind(user_agent)
        .bind(details)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Log successful login
    pub async fn log_login_success(
        &self,
        user_id: Uuid,
        ip_address: Option<IpAddr>,
        user_agent: Option<String>,
    ) -> Result<()> {
        self.log(
            EventType::LoginSuccess,
            Some(user_id),
            None,
            None,
            Some("login".to_string()),
            "success",
            ip_address,
            user_agent,
            None,
        )
        .await
    }

    /// Log failed login attempt
    pub async fn log_login_failure(
        &self,
        email: &str,
        reason: &str,
        ip_address: Option<IpAddr>,
        user_agent: Option<String>,
    ) -> Result<()> {
        let details = serde_json::json!({
            "email": email,
            "reason": reason,
        });

        self.log(
            EventType::LoginFailure,
            None,
            None,
            None,
            Some("login".to_string()),
            "failure",
            ip_address,
            user_agent,
            Some(details),
        )
        .await
    }

    /// Log token issuance
    pub async fn log_token_issued(
        &self,
        user_id: Option<Uuid>,
        client_id: Uuid,
        grant_type: &str,
        scope: Option<&str>,
    ) -> Result<()> {
        let details = serde_json::json!({
            "grant_type": grant_type,
            "scope": scope,
        });

        self.log(
            EventType::TokenIssued,
            user_id,
            Some(client_id),
            Some("access_token".to_string()),
            Some("issue".to_string()),
            "success",
            None,
            None,
            Some(details),
        )
        .await
    }

    /// Log data export (GDPR)
    pub async fn log_data_export(&self, user_id: Uuid) -> Result<()> {
        self.log(
            EventType::UserDataExported,
            Some(user_id),
            None,
            Some("user_data".to_string()),
            Some("export".to_string()),
            "success",
            None,
            None,
            None,
        )
        .await
    }

    /// Log account lockout (security event)
    pub async fn log_account_locked(
        &self,
        user_id: Uuid,
        reason: &str,
        ip_address: Option<IpAddr>,
    ) -> Result<()> {
        let details = serde_json::json!({
            "reason": reason,
        });

        self.log(
            EventType::AccountLocked,
            Some(user_id),
            None,
            Some("user_account".to_string()),
            Some("lock".to_string()),
            "success",
            ip_address,
            None,
            Some(details),
        )
        .await
    }

    /// Query audit logs for a user (GDPR audit trail)
    pub async fn get_user_logs(&self, user_id: Uuid, limit: i64) -> Result<Vec<AuditLog>> {
        let logs = sqlx::query_as::<_, AuditLog>(
            "SELECT id, event_type, event_category, user_id, client_id, resource, action, outcome, ip_address::TEXT, user_agent, details, created_at FROM audit_logs WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2"
        )
        .bind(user_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(logs)
    }

    /// Query security events (for monitoring)
    pub async fn get_security_events(&self, since: DateTime<Utc>, limit: i64) -> Result<Vec<AuditLog>> {
        let logs = sqlx::query_as::<_, AuditLog>(
            r#"
            SELECT id, event_type, event_category, user_id, client_id, resource, action, outcome, ip_address::TEXT, user_agent, details, created_at FROM audit_logs 
            WHERE event_category = 'security' AND created_at >= $1
            ORDER BY created_at DESC 
            LIMIT $2
            "#
        )
        .bind(since)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(logs)
    }
}
