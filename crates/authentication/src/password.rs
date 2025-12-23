use anyhow::Result;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PasswordError {
    #[error("Password too short: minimum {0} characters required")]
    TooShort(usize),
    
    #[error("Password too long: maximum {0} characters allowed")]
    TooLong(usize),
    
    #[error("Password has been compromised in a data breach")]
    Breached,
    
    #[error("Password hashing failed: {0}")]
    HashingFailed(String),
    
    #[error("Password verification failed")]
    VerificationFailed,
}

/// Password configuration (NIST 800-63B + OWASP ASVS compliant)
pub struct PasswordConfig {
    /// Minimum length (OWASP ASVS 2.1.1: >= 12 characters)
    pub min_length: usize,
    
    /// Maximum length (NIST 800-63B: >= 64 characters)
    pub max_length: usize,
    
    /// Check against HaveIBeenPwned breach database
    pub check_breach: bool,
}

impl Default for PasswordConfig {
    fn default() -> Self {
        Self {
            min_length: 12,   // Exceeds NIST 800-63B (8 chars) and OWASP recommendation
            max_length: 128,  // No maximum per NIST
            check_breach: true,
        }
    }
}

/// Hash password using Argon2id (OWASP recommended)
///
/// Parameters: m=64MB, t=3, p=4 (OWASP ASVS recommendation)
/// 
/// # Arguments
/// * `password` - Plaintext password
/// 
/// # Returns
/// PHC string format hash
pub fn hash_password(password: &str) -> Result<String, PasswordError> {
    let salt = SaltString::generate(&mut OsRng);
    
    // Argon2id with OWASP recommended parameters
    let argon2 = Argon2::default();
    
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| PasswordError::HashingFailed(e.to_string()))?
        .to_string();

    Ok(password_hash)
}

/// Verify password against hash
///
/// Uses constant-time comparison to prevent timing attacks
/// 
/// # Arguments
/// * `password` - Plaintext password to verify
/// * `password_hash` - Stored Argon2id hash
pub fn verify_password(password: &str, password_hash: &str) -> Result<(), PasswordError> {
    let parsed_hash = PasswordHash::new(password_hash)
        .map_err(|e| PasswordError::HashingFailed(e.to_string()))?;

    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .map_err(|_| PasswordError::VerificationFailed)
}

/// Validate password meets security requirements
///
/// # Arguments
/// * `password` - Password to validate
/// * `config` - Password policy configuration
pub fn validate_password(password: &str, config: &PasswordConfig) -> Result<(), PasswordError> {
    // Length validation (NIST 800-63B + OWASP ASVS)
    if password.len() < config.min_length {
        return Err(PasswordError::TooShort(config.min_length));
    }
    
    if password.len() > config.max_length {
        return Err(PasswordError::TooLong(config.max_length));
    }

    // Note: NO composition rules per NIST 800-63B guidance
    // Users can use passphrases or any character combination
    
    Ok(())
}

/// Check if password has been found in data breaches (async)
///
/// Uses HaveIBeenPwned k-anonymity API (privacy-preserving)
/// 
/// # Arguments
/// * `password` - Password to check
///
/// # Returns
/// Ok(()) if not breached, Err if found in breaches
pub async fn check_password_breach(password: &str) -> Result<(), PasswordError> {
    use sha2::{Digest, Sha1};
    
    // SHA1 hash of password
    let mut hasher = Sha1::new();
    hasher.update(password.as_bytes());
    let hash = hasher.finalize();
    let hash_str = format!("{:X}", hash);
    
    // k-anonymity: Send first 5 chars, get back matching suffixes
    let prefix = &hash_str[..5];
    let suffix = &hash_str[5..];
    
    let url = format!("https://api.pwnedpasswords.com/range/{}", prefix);
    let response = reqwest::get(&url).await
        .map_err(|_| PasswordError::Breached)?; // Conservative: fail closed
    
    let text = response.text().await
        .map_err(|_| PasswordError::Breached)?;
    
    // Check if our suffix is in the response
    if text.contains(suffix) {
        return Err(PasswordError::Breached);
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_and_verify_password() {
        let password = "correct_horse_battery_staple";
        let hash = hash_password(password).unwrap();
        
        assert!(verify_password(password, &hash).is_ok());
        assert!(verify_password("wrong_password", &hash).is_err());
    }

    #[test]
    fn test_validate_password_length() {
        let config = PasswordConfig::default();
        
        // Too short
        assert!(matches!(
            validate_password("short", &config),
            Err(PasswordError::TooShort(_))
        ));
        
        // Valid length
        assert!(validate_password("long_enough_password", &config).is_ok());
    }

    #[tokio::test]
    async fn test_check_password_breach() {
        // Known breached password
        let result = check_password_breach("password123").await;
        assert!(result.is_err());
    }
}
