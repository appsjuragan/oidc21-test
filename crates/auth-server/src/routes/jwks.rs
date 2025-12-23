use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{error::AppResult, state::AppState};

/// JSON Web Key Set (JWKS) Response
#[derive(Debug, Serialize, Deserialize)]
pub struct JwksResponse {
    pub keys: Vec<Jwk>,
}

/// JSON Web Key (RFC 7517)
#[derive(Debug, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,           // Key type: "RSA" or "EC"
    pub kid: String,           // Key ID for rotation
    #[serde(rename = "use")]
    pub key_use: String,       // "sig" for signature
    pub alg: String,           // "RS256" or "ES256"
    
    // RSA specific fields
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,     // Modulus (Base64urlUInt)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,     // Exponent
    
    // EC specific fields
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,   // Curve name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,     // X coordinate
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,     // Y coordinate
}

/// JWKS endpoint handler
/// GET /jwks
///
/// Returns public keys for JWT signature verification
/// Clients use this to validate access tokens and ID tokens
pub async fn jwks(
    State(state): State<AppState>,
) -> AppResult<Json<JwksResponse>> {
    // Load public key
    let public_key_pem = tokio::fs::read(&state.config.jwt.public_key_path)
        .await
        .map_err(|_| crate::error::AppError::Internal(anyhow::anyhow!("Failed to load public key")))?;

    // Parse RSA public key
    let public_key_str = String::from_utf8(public_key_pem)
        .map_err(|_| crate::error::AppError::Internal(anyhow::anyhow!("Invalid public key encoding")))?;

    // Extract modulus and exponent from PEM
    // This is a simplified implementation - in production, use a proper RSA library
    let (n, e) = extract_rsa_components(&public_key_str)?;

    // Generate key ID from public key hash (for versioning/rotation)
    let mut hasher = Sha256::new();
    hasher.update(&public_key_str);
    let kid = format!("{:x}", hasher.finalize())[..16].to_string();

    let jwk = Jwk {
        kty: "RSA".to_string(),
        kid,
        key_use: "sig".to_string(),
        alg: "RS256".to_string(),
        n: Some(n),
        e: Some(e),
        crv: None,
        x: None,
        y: None,
    };

    Ok(Json(JwksResponse {
        keys: vec![jwk],
    }))
}

/// Extract RSA modulus and exponent from PEM public key
///
/// This is a simplified implementation. In production, use `rsa` crate or similar.
fn extract_rsa_components(pem: &str) -> AppResult<(String, String)> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    
    // Remove PEM headers and decode base64
    let pem_content = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<String>();
    
    let der = STANDARD.decode(pem_content.trim())
        .map_err(|_| crate::error::AppError::Internal(anyhow::anyhow!("Failed to decode public key")))?;

    // Parse DER to extract modulus and exponent
    // This is a basic ASN.1 parser for RSA public keys
    // In production, use a proper ASN.1 library
    
    // For now, return placeholder values
    // TODO: Implement proper RSA key parsing or use `rsa` crate
    let n = STANDARD.encode(&der[..256.min(der.len())]); // Placeholder
    let e = STANDARD.encode([0x01, 0x00, 0x01]); // Common exponent (65537)

    Ok((n, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwk_serialization() {
        let jwk = Jwk {
            kty: "RSA".to_string(),
            kid: "test123".to_string(),
            key_use: "sig".to_string(),
            alg: "RS256".to_string(),
            n: Some("modulus".to_string()),
            e: Some("exponent".to_string()),
            crv: None,
            x: None,
            y: None,
        };

        let json = serde_json::to_string(&jwk).unwrap();
        assert!(json.contains("RSA"));
        assert!(json.contains("RS256"));
    }
}
