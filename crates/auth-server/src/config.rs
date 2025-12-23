use anyhow::Result;
use serde::Deserialize;
use std::env;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub redis: RedisConfig,
    pub jwt: JwtConfig,
    pub session: SessionConfig,
    pub security: SecurityConfig,
    pub mfa: MfaConfig,
    pub gdpr: GdprConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub base_url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub min_connections: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RedisConfig {
    pub url: String,
    pub pool_size: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct JwtConfig {
    pub issuer: String,
    pub access_token_expiration_seconds: i64,
    pub refresh_token_expiration_seconds: i64,
    pub private_key_path: String,
    pub public_key_path: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SessionConfig {
    /// NIST 800-63B AAL2: 15 minutes idle timeout
    pub idle_timeout_seconds: i64,
    /// NIST 800-63B AAL2: 12 hours absolute timeout
    pub absolute_timeout_seconds: i64,
    pub max_concurrent: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SecurityConfig {
    pub rate_limit_max_requests: u64,
    pub rate_limit_window_seconds: u64,
    /// OWASP ASVS 2.1.1: Minimum 12 characters
    pub password_min_length: usize,
    pub password_max_length: usize,
    /// OWASP ASVS 2.2.1: Maximum 5 failed attempts
    pub login_max_attempts: u32,
    /// OWASP ASVS 2.2.1: 15 minute lockout
    pub login_lockout_duration_seconds: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MfaConfig {
    pub required_for_admin: bool,
    pub totp_issuer: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GdprConfig {
    pub data_retention_days: i64,
    pub audit_log_retention_days: i64,
}

impl Config {
    pub fn load() -> Result<Self> {
        let config = Self {
            server: ServerConfig {
                host: env::var("SERVER_HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
                port: env::var("SERVER_PORT")
                    .unwrap_or_else(|_| "8080".to_string())
                    .parse()?,
                base_url: env::var("SERVER_BASE_URL")
                    .unwrap_or_else(|_| "http://localhost:8080".to_string()),
            },
            database: DatabaseConfig {
                url: env::var("DATABASE_URL")?,
                max_connections: env::var("DATABASE_MAX_CONNECTIONS")
                    .unwrap_or_else(|_| "10".to_string())
                    .parse()?,
                min_connections: env::var("DATABASE_MIN_CONNECTIONS")
                    .unwrap_or_else(|_| "2".to_string())
                    .parse()?,
            },
            redis: RedisConfig {
                url: env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string()),
                pool_size: env::var("REDIS_POOL_SIZE")
                    .unwrap_or_else(|_| "10".to_string())
                    .parse()?,
            },
            jwt: JwtConfig {
                issuer: env::var("JWT_ISSUER")
                    .unwrap_or_else(|_| "http://localhost:8080".to_string()),
                access_token_expiration_seconds: env::var("JWT_ACCESS_TOKEN_EXPIRATION_SECONDS")
                    .unwrap_or_else(|_| "900".to_string())
                    .parse()?,
                refresh_token_expiration_seconds: env::var("JWT_REFRESH_TOKEN_EXPIRATION_SECONDS")
                    .unwrap_or_else(|_| "2592000".to_string())
                    .parse()?,
                private_key_path: env::var("JWT_PRIVATE_KEY_PATH")
                    .unwrap_or_else(|_| "./keys/private_key.pem".to_string()),
                public_key_path: env::var("JWT_PUBLIC_KEY_PATH")
                    .unwrap_or_else(|_| "./keys/public_key.pem".to_string()),
            },
            session: SessionConfig {
                idle_timeout_seconds: env::var("SESSION_IDLE_TIMEOUT_SECONDS")
                    .unwrap_or_else(|_| "900".to_string())
                    .parse()?,
                absolute_timeout_seconds: env::var("SESSION_ABSOLUTE_TIMEOUT_SECONDS")
                    .unwrap_or_else(|_| "43200".to_string())
                    .parse()?,
                max_concurrent: env::var("SESSION_MAX_CONCURRENT")
                    .unwrap_or_else(|_| "5".to_string())
                    .parse()?,
            },
            security: SecurityConfig {
                rate_limit_max_requests: env::var("RATE_LIMIT_MAX_REQUESTS")
                    .unwrap_or_else(|_| "100".to_string())
                    .parse()?,
                rate_limit_window_seconds: env::var("RATE_LIMIT_WINDOW_SECONDS")
                    .unwrap_or_else(|_| "60".to_string())
                    .parse()?,
                password_min_length: env::var("PASSWORD_MIN_LENGTH")
                    .unwrap_or_else(|_| "12".to_string())
                    .parse()?,
                password_max_length: env::var("PASSWORD_MAX_LENGTH")
                    .unwrap_or_else(|_| "128".to_string())
                    .parse()?,
                login_max_attempts: env::var("LOGIN_MAX_ATTEMPTS")
                    .unwrap_or_else(|_| "5".to_string())
                    .parse()?,
                login_lockout_duration_seconds: env::var("LOGIN_LOCKOUT_DURATION_SECONDS")
                    .unwrap_or_else(|_| "900".to_string())
                    .parse()?,
            },
            mfa: MfaConfig {
                required_for_admin: env::var("MFA_REQUIRED_FOR_ADMIN")
                    .unwrap_or_else(|_| "true".to_string())
                    .parse()?,
                totp_issuer: env::var("TOTP_ISSUER")
                    .unwrap_or_else(|_| "OIDC SSO".to_string()),
            },
            gdpr: GdprConfig {
                data_retention_days: env::var("DATA_RETENTION_DAYS")
                    .unwrap_or_else(|_| "90".to_string())
                    .parse()?,
                audit_log_retention_days: env::var("AUDIT_LOG_RETENTION_DAYS")
                    .unwrap_or_else(|_| "365".to_string())
                    .parse()?,
            },
        };

        Ok(config)
    }
}
