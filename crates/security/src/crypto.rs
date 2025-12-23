use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::Rng;

/// Generate cryptographically secure random bytes
///
/// Uses system CSPRNG for cryptographic-quality randomness
/// 
/// # Arguments
/// * `length` - Number of bytes to generate
/// 
/// # Returns
/// Vector of random bytes
pub fn generate_random_bytes(length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    rand::thread_rng().fill(&mut bytes[..]);
    bytes
}

/// Generate random base64url-encoded string
///
/// Useful for tokens, secrets, and identifiers
/// 
/// # Arguments
/// * `byte_length` - Number of random bytes (not output string length)
/// 
/// # Returns
/// Base64url-encoded string
pub fn generate_secure_token(byte_length: usize) -> String {
    let bytes = generate_random_bytes(byte_length);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Generate session token (256-bit entropy per OWASP ASVS 3.2.1)
pub fn generate_session_token() -> String {
    generate_secure_token(32) // 32 bytes = 256 bits
}

/// Generate authorization code (128-bit entropy minimum)
pub fn generate_authorization_code() -> String {
    generate_secure_token(16) // 16 bytes = 128 bits
}

/// Generate refresh token (256-bit entropy)
pub fn generate_refresh_token() -> String {
    generate_secure_token(32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_random_bytes() {
        let bytes1 = generate_random_bytes(32);
        let bytes2 = generate_random_bytes(32);
        
        assert_eq!(bytes1.len(), 32);
        assert_ne!(bytes1, bytes2);
    }

    #[test]
    fn test_generate_secure_token() {
        let token = generate_secure_token(32);
        assert!(!token.is_empty());
        
        // Should be valid base64url
        assert!(URL_SAFE_NO_PAD.decode(&token).is_ok());
    }

    #[test]
    fn test_session_token_entropy() {
        let token = generate_session_token();
        let decoded = URL_SAFE_NO_PAD.decode(&token).unwrap();
        
        // Should be 32 bytes (256 bits)
        assert_eq!(decoded.len(), 32);
    }
}
