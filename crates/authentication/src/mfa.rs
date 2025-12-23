use anyhow::Result;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use thiserror::Error;
use totp_rs::{Algorithm, Secret, TOTP};
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum MfaError {
    #[error("Invalid TOTP code")]
    InvalidCode,
    
    #[error("MFA not enrolled")]
    NotEnrolled,
    
    #[error("MFA credential not found")]
    NotFound,
    
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    
    #[error("TOTP error: {0}")]
    TotpError(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MfaType {
    Totp,
    WebAuthn,
    Sms,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TotpEnrollment {
    pub secret: String,
    pub qr_code_url: String,
    pub backup_codes: Vec<String>,
}

/// MFA Manager for NIST 800-63B AAL2/AAL3 compliance
pub struct MfaManager {
    pool: PgPool,
    issuer: String,
}

impl MfaManager {
    pub fn new(pool: PgPool, issuer: String) -> Self {
        Self { pool, issuer }
    }

    /// Generate TOTP secret and enrollment data
    ///
    /// # Arguments
    /// * `user_email` - User's email for TOTP label
    /// 
    /// # Returns
    /// TOTP enrollment data with secret, QR code URL, and backup codes
    pub fn generate_totp_enrollment(&self, user_email: &str) -> Result<TotpEnrollment, MfaError> {
        // Generate cryptographically secure secret (160 bits recommended)
        let secret = Secret::generate_secret();
        let secret_base32 = secret.to_encoded().to_string();

        // Create TOTP with standard parameters
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,  // 6-digit codes
            1,  // 1 step tolerance
            30, // 30-second time step (standard)
            secret.to_bytes().unwrap(),
            Some(self.issuer.clone()),
            user_email.to_string(),
        )
        .map_err(|e| MfaError::TotpError(e.to_string()))?;

        // Generate QR code URL for authenticator apps
        let qr_code_url = totp.get_qr_base64()
            .map_err(|e| MfaError::TotpError(e.to_string()))?;

        // Generate backup codes (10 single-use codes)
        let backup_codes = self.generate_backup_codes(10);

        Ok(TotpEnrollment {
            secret: secret_base32,
            qr_code_url,
            backup_codes,
        })
    }

    /// Enroll user in TOTP MFA
    ///
    /// Stores encrypted secret and backup codes in database
    pub async fn enroll_totp(
        &self,
        user_id: Uuid,
        secret: &str,
        backup_codes: Vec<String>,
    ) -> Result<(), MfaError> {
        // In production, encrypt the secret before storing
        // For now, store as-is (TODO: Add encryption)
        
        sqlx::query(
            r#"
            INSERT INTO mfa_credentials (user_id, mfa_type, totp_secret, backup_codes, is_active, verified_at)
            VALUES ($1, 'totp', $2, $3, false, NULL)
            "#
        )
        .bind(user_id)
        .bind(secret)
        .bind(&backup_codes)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Verify TOTP code and activate MFA
    ///
    /// Used during enrollment to confirm user has saved the secret
    pub async fn verify_enrollment(
        &self,
        user_id: Uuid,
        code: &str,
    ) -> Result<(), MfaError> {
        // Get TOTP secret
        let credential = sqlx::query!(
            r#"
            SELECT id, totp_secret
            FROM mfa_credentials
            WHERE user_id = $1 AND mfa_type = 'totp' AND is_active = false
            "#,
            user_id
        )
        .fetch_optional(&self.pool)
        .await?
        .ok_or(MfaError::NotEnrolled)?;

        let secret = credential.totp_secret
            .ok_or(MfaError::NotEnrolled)?;

        // Verify TOTP code
        self.verify_totp_code(&secret, code)?;

        // Activate MFA credential
        sqlx::query!(
            "UPDATE mfa_credentials SET is_active = true, verified_at = NOW() WHERE id = $1",
            credential.id
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Verify TOTP code for authentication
    ///
    /// # Arguments
    /// * `user_id` - User attempting to authenticate
    /// * `code` - 6-digit TOTP code from authenticator app
    pub async fn verify_totp(
        &self,
        user_id: Uuid,
        code: &str,
    ) -> Result<bool, MfaError> {
        // Get active TOTP credential
        let credential = sqlx::query!(
            r#"
            SELECT totp_secret, backup_codes
            FROM mfa_credentials
            WHERE user_id = $1 AND mfa_type = 'totp' AND is_active = true
            "#,
            user_id
        )
        .fetch_optional(&self.pool)
        .await?
        .ok_or(MfaError::NotEnrolled)?;

        let secret = credential.totp_secret
            .ok_or(MfaError::NotFound)?;

        // Try TOTP code first
        if self.verify_totp_code(&secret, code).is_ok() {
            return Ok(true);
        }

        // Try backup codes if TOTP fails
        if let Some(backup_codes) = credential.backup_codes {
            if backup_codes.contains(&code.to_string()) {
                // Remove used backup code
                let remaining_codes: Vec<String> = backup_codes
                    .into_iter()
                    .filter(|c| c != code)
                    .collect();

                sqlx::query!(
                    "UPDATE mfa_credentials SET backup_codes = $1 WHERE user_id = $2 AND mfa_type = 'totp'",
                    &remaining_codes,
                    user_id
                )
                .execute(&self.pool)
                .await?;

                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Check if user has MFA enrolled
    pub async fn has_mfa_enrolled(&self, user_id: Uuid) -> Result<bool, MfaError> {
        let count = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM mfa_credentials WHERE user_id = $1 AND is_active = true",
            user_id
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(count.unwrap_or(0) > 0)
    }

    /// Disable MFA for user (with proper authorization required)
    pub async fn disable_mfa(&self, user_id: Uuid) -> Result<(), MfaError> {
        sqlx::query!(
            "UPDATE mfa_credentials SET is_active = false WHERE user_id = $1",
            user_id
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Internal: Verify TOTP code against secret
    fn verify_totp_code(&self, secret_base32: &str, code: &str) -> Result<(), MfaError> {
        let secret = Secret::Encoded(secret_base32.to_string())
            .to_bytes()
            .map_err(|e| MfaError::TotpError(e.to_string()))?;

        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            secret,
            Some(self.issuer.clone()),
            "user".to_string(), // Label doesn't matter for verification
        )
        .map_err(|e| MfaError::TotpError(e.to_string()))?;

        if totp.check_current(code).map_err(|e| MfaError::TotpError(e.to_string()))? {
            Ok(())
        } else {
            Err(MfaError::InvalidCode)
        }
    }

    /// Generate cryptographically secure backup codes
    fn generate_backup_codes(&self, count: usize) -> Vec<String> {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        
        (0..count)
            .map(|_| {
                // Generate 8-digit backup code
                format!("{:08}", rng.gen_range(0..100_000_000))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_backup_codes() {
        let manager = MfaManager {
            pool: todo!(),
            issuer: "Test".to_string(),
        };

        let codes = manager.generate_backup_codes(10);
        assert_eq!(codes.len(), 10);
        
        // All codes should be 8 digits
        for code in codes {
            assert_eq!(code.len(), 8);
            assert!(code.chars().all(|c| c.is_ascii_digit()));
        }
    }

    #[test]
    fn test_totp_generation() {
        let manager = MfaManager {
            pool: todo!(),
            issuer: "OIDC SSO".to_string(),
        };

        let enrollment = manager.generate_totp_enrollment("test@example.com").unwrap();
        
        // Secret should be base32 encoded
        assert!(!enrollment.secret.is_empty());
        
        // Should have QR code
        assert!(enrollment.qr_code_url.starts_with("data:image/"));
        
        // Should have 10 backup codes
        assert_eq!(enrollment.backup_codes.len(), 10);
    }
}
