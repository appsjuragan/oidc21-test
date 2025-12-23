use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Client {
    pub id: Uuid,
    pub client_id: String,
    pub client_secret_hash: Option<String>,
    pub client_name: String,
    pub client_type: ClientType,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub allowed_scopes: Vec<String>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "VARCHAR", rename_all = "lowercase")]
pub enum ClientType {
    #[sqlx(rename = "confidential")]
    Confidential,
    #[sqlx(rename = "public")]
    Public,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateClientRequest {
    pub client_name: String,
    pub client_type: ClientType,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub allowed_scopes: Vec<String>,
}

/// Client repository for OAuth/OIDC client management
pub struct ClientRepository {
    pool: PgPool,
}

impl ClientRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create a new OAuth/OIDC client
    pub async fn create(&self, request: CreateClientRequest, client_secret_hash: Option<&str>) -> Result<Client> {
        // Generate unique client_id
        let client_id = format!("client_{}", Uuid::new_v4().simple());

        let client = sqlx::query_as::<_, Client>(
            r#"
            INSERT INTO clients (
                client_id, client_secret_hash, client_name, client_type,
                redirect_uris, grant_types, allowed_scopes
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
            "#,
        )
        .bind(&client_id)
        .bind(client_secret_hash)
        .bind(&request.client_name)
        .bind(&request.client_type)
        .bind(&request.redirect_uris)
        .bind(&request.grant_types)
        .bind(&request.allowed_scopes)
        .fetch_one(&self.pool)
        .await?;

        Ok(client)
    }

    /// Find client by client_id
    pub async fn find_by_client_id(&self, client_id: &str) -> Result<Option<Client>> {
        let client = sqlx::query_as::<_, Client>(
            "SELECT * FROM clients WHERE client_id = $1"
        )
        .bind(client_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(client)
    }

    /// Find client by internal ID
    pub async fn find_by_id(&self, id: Uuid) -> Result<Option<Client>> {
        let client = sqlx::query_as::<_, Client>(
            "SELECT * FROM clients WHERE id = $1"
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(client)
    }

    /// Validate redirect URI (exact match required per OAuth 2.1)
    pub fn validate_redirect_uri(&self, client: &Client, redirect_uri: &str) -> bool {
        client.redirect_uris.iter().any(|uri| uri == redirect_uri)
    }

    /// Validate grant type is allowed for client
    pub fn validate_grant_type(&self, client: &Client, grant_type: &str) -> bool {
        client.grant_types.iter().any(|gt| gt == grant_type)
    }

    /// Validate scope is allowed for client
    pub fn validate_scope(&self, client: &Client, requested_scope: &str) -> bool {
        let requested_scopes: Vec<&str> = requested_scope.split_whitespace().collect();
        requested_scopes.iter().all(|scope| {
            client.allowed_scopes.iter().any(|allowed| allowed == scope)
        })
    }

    /// Check if client is confidential (has client secret)
    pub fn is_confidential(&self, client: &Client) -> bool {
        matches!(client.client_type, ClientType::Confidential)
    }

    /// Update client
    pub async fn update(&self, id: Uuid, request: CreateClientRequest) -> Result<Client> {
        let client = sqlx::query_as::<_, Client>(
            r#"
            UPDATE clients 
            SET client_name = $2,
                redirect_uris = $3,
                grant_types = $4,
                allowed_scopes = $5,
                updated_at = NOW()
            WHERE id = $1
            RETURNING *
            "#
        )
        .bind(id)
        .bind(&request.client_name)
        .bind(&request.redirect_uris)
        .bind(&request.grant_types)
        .bind(&request.allowed_scopes)
        .fetch_one(&self.pool)
        .await?;

        Ok(client)
    }

    /// Deactivate client
    pub async fn deactivate(&self, id: Uuid) -> Result<()> {
        sqlx::query("UPDATE clients SET is_active = false WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    /// Delete client
    pub async fn delete(&self, id: Uuid) -> Result<()> {
        sqlx::query("DELETE FROM clients WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_redirect_uri() {
        let repo = ClientRepository { pool: todo!() };
        let client = Client {
            id: Uuid::new_v4(),
            client_id: "test".to_string(),
            client_secret_hash: None,
            client_name: "Test".to_string(),
            client_type: ClientType::Public,
            redirect_uris: vec!["https://example.com/callback".to_string()],
            grant_types: vec![],
            allowed_scopes: vec![],
            is_active: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        // Exact match required
        assert!(repo.validate_redirect_uri(&client, "https://example.com/callback"));
        assert!(!repo.validate_redirect_uri(&client, "https://example.com/callback2"));
        assert!(!repo.validate_redirect_uri(&client, "https://example.com"));
    }
}
