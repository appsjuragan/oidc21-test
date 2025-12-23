use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use security::generate_session_token;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use thiserror::Error;
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum SessionError {
    #[error("Session not found")]
    NotFound,
    
    #[error("Session expired")]
    Expired,
    
    #[error("Too many concurrent sessions")]
    TooManyConcurrent,
    
    #[error("Redis error: {0}")]
    RedisError(#[from] redis::RedisError),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub session_token: String,
    pub user_id: Uuid,
    pub user_agent: Option<String>,
    pub ip_address: Option<IpAddr>,
    pub device_fingerprint: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_activity_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Session configuration (NIST 800-63B AAL2)
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Idle timeout in seconds (default: 900 = 15 minutes)
    pub idle_timeout_seconds: i64,
    
    /// Absolute timeout in seconds (default: 43200 = 12 hours)
    pub absolute_timeout_seconds: i64,
    
    /// Maximum concurrent sessions per user
    pub max_concurrent: usize,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            idle_timeout_seconds: 900,    // 15 minutes (NIST 800-63B AAL2)
            absolute_timeout_seconds: 43200, // 12 hours (NIST 800-63B AAL2)
            max_concurrent: 5,
        }
    }
}

/// Session manager using Redis for high-performance storage
pub struct SessionManager {
    redis: ConnectionManager,
    config: SessionConfig,
}

impl SessionManager {
    pub fn new(redis: ConnectionManager, config: SessionConfig) -> Self {
        Self { redis, config }
    }

    /// Create a new session
    ///
    /// Generates 256-bit cryptographically secure session token (OWASP ASVS 3.2.1)
    pub async fn create_session(
        &mut self,
        user_id: Uuid,
        user_agent: Option<String>,
        ip_address: Option<IpAddr>,
        device_fingerprint: Option<String>,
    ) -> Result<Session, SessionError> {
        // Check concurrent session limit
        let active_sessions = self.count_user_sessions(user_id).await?;
        if active_sessions >= self.config.max_concurrent {
            return Err(SessionError::TooManyConcurrent);
        }

        let now = Utc::now();
        let session_token = generate_session_token();

        let session = Session {
            session_token: session_token.clone(),
            user_id,
            user_agent,
            ip_address,
            device_fingerprint,
            created_at: now,
            last_activity_at: now,
            expires_at: now + Duration::seconds(self.config.absolute_timeout_seconds),
        };

        // Store in Redis with expiration
        let session_key = format!("session:{}", session_token);
        let user_sessions_key = format!("user_sessions:{}", user_id);
        
        let session_json = serde_json::to_string(&session)?;
        
        // Store session data
        self.redis
            .set_ex(&session_key, session_json, self.config.absolute_timeout_seconds as u64)
            .await?;

        // Track user's active sessions
        self.redis
            .sadd(&user_sessions_key, &session_token)
            .await?;
        
        // Set expiration on user sessions set
        self.redis
            .expire(&user_sessions_key, self.config.absolute_timeout_seconds as i64)
            .await?;

        Ok(session)
    }

    /// Get session by token
    pub async fn get_session(&mut self, session_token: &str) -> Result<Session, SessionError> {
        let session_key = format!("session:{}", session_token);
        
        let session_json: Option<String> = self.redis.get(&session_key).await?;
        
        let mut session: Session = session_json
            .ok_or(SessionError::NotFound)
            .and_then(|json| serde_json::from_str(&json).map_err(|_| SessionError::NotFound))?;

        // Check if session expired
        if session.expires_at < Utc::now() {
            self.delete_session(session_token).await?;
            return Err(SessionError::Expired);
        }

        // Check idle timeout
        let idle_duration = Utc::now() - session.last_activity_at;
        if idle_duration.num_seconds() > self.config.idle_timeout_seconds {
            self.delete_session(session_token).await?;
            return Err(SessionError::Expired);
        }

        Ok(session)
    }

    /// Update session activity (refresh idle timeout)
    pub async fn touch_session(&mut self, session_token: &str) -> Result<(), SessionError> {
        let mut session = self.get_session(session_token).await?;
        
        session.last_activity_at = Utc::now();
        
        let session_key = format!("session:{}", session_token);
        let session_json = serde_json::to_string(&session)?;
        
        // Update with remaining time until absolute timeout
        let remaining_seconds = (session.expires_at - Utc::now()).num_seconds();
        if remaining_seconds > 0 {
            self.redis
                .set_ex(&session_key, session_json, remaining_seconds as u64)
                .await?;
        }

        Ok(())
    }

    /// Delete session (logout)
    pub async fn delete_session(&mut self, session_token: &str) -> Result<(), SessionError> {
        let session_key = format!("session:{}", session_token);
        
        // Get user_id before deleting
        if let Ok(session) = self.get_session(session_token).await {
            let user_sessions_key = format!("user_sessions:{}", session.user_id);
            self.redis.srem(&user_sessions_key, session_token).await?;
        }

        self.redis.del(&session_key).await?;
        
        Ok(())
    }

    /// Delete all sessions for a user (logout all devices)
    pub async fn delete_all_user_sessions(&mut self, user_id: Uuid) -> Result<(), SessionError> {
        let user_sessions_key = format!("user_sessions:{}", user_id);
        
        let session_tokens: Vec<String> = self.redis.smembers(&user_sessions_key).await?;
        
        for token in session_tokens {
            let session_key = format!("session:{}", token);
            self.redis.del(&session_key).await?;
        }
        
        self.redis.del(&user_sessions_key).await?;
        
        Ok(())
    }

    /// Count active sessions for a user
    pub async fn count_user_sessions(&mut self, user_id: Uuid) -> Result<usize, SessionError> {
        let user_sessions_key = format!("user_sessions:{}", user_id);
        let count: usize = self.redis.scard(&user_sessions_key).await?;
        Ok(count)
    }

    /// Validate session and return user_id
    pub async fn validate_session(&mut self, session_token: &str) -> Result<Uuid, SessionError> {
        let session = self.get_session(session_token).await?;
        self.touch_session(session_token).await?;
        Ok(session.user_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests require Redis connection
    // Run with: cargo test -- --ignored
}
