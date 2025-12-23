use anyhow::Result;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::Rng;
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PkceError {
    #[error("Invalid code verifier length: {0}. Must be between 43 and 128 characters")]
    InvalidVerifierLength(usize),
    
    #[error("Invalid code challenge method: {0}. Only S256 is supported")]
    InvalidChallengeMethod(String),
    
    #[error("PKCE verification failed")]
    VerificationFailed,
}

/// Generate a cryptographically secure code verifier
/// 
/// OAuth 2.1 requires verifier length between 43-128 characters
/// Returns base64url-encoded random string
pub fn generate_code_verifier() -> String {
    let random_bytes: [u8; 32] = rand::thread_rng().gen();
    URL_SAFE_NO_PAD.encode(random_bytes)
}

/// Create code challenge from verifier using S256 method
///
/// OAuth 2.1 mandates S256 (SHA-256) method for security
/// 
/// # Arguments
/// * `verifier` - Code verifier string (43-128 chars)
/// 
/// # Returns
/// Base64url-encoded SHA256 hash of the verifier
pub fn create_code_challenge(verifier: &str) -> Result<String, PkceError> {
    if verifier.len() < 43 || verifier.len() > 128 {
        return Err(PkceError::InvalidVerifierLength(verifier.len()));
    }

    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let hash = hasher.finalize();
    
    Ok(URL_SAFE_NO_PAD.encode(hash))
}

/// Verify PKCE code verifier against stored challenge
/// 
/// # Arguments
/// * `verifier` - Code verifier from client
/// * `challenge` - Stored code challenge from authorization request
/// * `method` - Challenge method (must be "S256")
///
/// # Returns
/// Ok(()) if verification succeeds, Err otherwise
pub fn verify_code_verifier(
    verifier: &str,
    challenge: &str,
    method: &str,
) -> Result<(), PkceError> {
    // OAuth 2.1: Only S256 is supported
    if method != "S256" {
        return Err(PkceError::InvalidChallengeMethod(method.to_string()));
    }

    let computed_challenge = create_code_challenge(verifier)?;
    
    // Constant-time comparison to prevent timing attacks
    use subtle::ConstantTimeEq;
    if computed_challenge.as_bytes().ct_eq(challenge.as_bytes()).into() {
        Ok(())
    } else {
        Err(PkceError::VerificationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_code_verifier() {
        let verifier = generate_code_verifier();
        assert!(verifier.len() >= 43 && verifier.len() <= 128);
    }

    #[test]
    fn test_create_code_challenge() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = create_code_challenge(verifier).unwrap();
        
        // Verify it's valid base64url
        assert!(URL_SAFE_NO_PAD.decode(&challenge).is_ok());
    }

    #[test]
    fn test_verify_code_verifier_success() {
        let verifier = generate_code_verifier();
        let challenge = create_code_challenge(&verifier).unwrap();
        
        assert!(verify_code_verifier(&verifier, &challenge, "S256").is_ok());
    }

    #[test]
    fn test_verify_code_verifier_failure() {
        let verifier1 = generate_code_verifier();
        let verifier2 = generate_code_verifier();
        let challenge = create_code_challenge(&verifier1).unwrap();
        
        assert!(verify_code_verifier(&verifier2, &challenge, "S256").is_err());
    }

    #[test]
    fn test_invalid_challenge_method() {
        let verifier = generate_code_verifier();
        let challenge = create_code_challenge(&verifier).unwrap();
        
        let result = verify_code_verifier(&verifier, &challenge, "plain");
        assert!(matches!(result, Err(PkceError::InvalidChallengeMethod(_))));
    }
}
