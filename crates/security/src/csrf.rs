use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::Rng;

/// Generate cryptographically secure state parameter for CSRF protection
///
/// OWASP ASVS 4.2.2: CSRF protection required for state-changing operations
/// 
/// Returns base64url-encoded random string (32 bytes = 256 bits entropy)
pub fn generate_state() -> String {
    let random_bytes: [u8; 32] = rand::thread_rng().gen();
    URL_SAFE_NO_PAD.encode(random_bytes)
}

/// Generate nonce for OIDC ID token replay prevention
///
/// Similar to state but used specifically for OIDC
/// 
/// Returns base64url-encoded random string (32 bytes = 256 bits entropy)
pub fn generate_nonce() -> String {
    let random_bytes: [u8; 32] = rand::thread_rng().gen();
    URL_SAFE_NO_PAD.encode(random_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_state() {
        let state1 = generate_state();
        let state2 = generate_state();
        
        // Should be different
        assert_ne!(state1, state2);
        
        // Should be valid base64url
        assert!(URL_SAFE_NO_PAD.decode(&state1).is_ok());
    }

    #[test]
    fn test_generate_nonce() {
        let nonce = generate_nonce();
        assert!(URL_SAFE_NO_PAD.decode(&nonce).is_ok());
    }
}
