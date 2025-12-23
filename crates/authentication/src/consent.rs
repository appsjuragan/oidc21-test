use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Consent {
    pub id: Uuid,
    pub user_id: Uuid,
    pub client_id: Uuid,
    pub scopes: Vec<String>,
    pub granted_at: DateTime<Utc>,
    pub withdrawn_at: Option<DateTime<Utc>>,
    pub purposes: Option<Vec<String>>,
}

/// Consent manager for GDPR compliance
pub struct ConsentManager {
    pool: PgPool,
}

impl ConsentManager {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Grant consent for scopes
    pub async fn grant_consent(
        &self,
        user_id: Uuid,
        client_id: Uuid,
        scopes: Vec<String>,
        purposes: Option<Vec<String>>,
    ) -> Result<Consent> {
        let consent = sqlx::query_as::<_, Consent>(
            r#"
            INSERT INTO consents (user_id, client_id, scopes, purposes)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (user_id, client_id) 
            DO UPDATE SET 
                scopes = $3,
                purposes = $4,
                granted_at = NOW(),
                withdrawn_at = NULL
            RETURNING *
            "#
        )
        .bind(user_id)
        .bind(client_id)
        .bind(&scopes)
        .bind(&purposes)
        .fetch_one(&self.pool)
        .await?;

        Ok(consent)
    }

    /// Get consent for user and client
    pub async fn get_consent(&self, user_id: Uuid, client_id: Uuid) -> Result<Option<Consent>> {
        let consent = sqlx::query_as::<_, Consent>(
            "SELECT * FROM consents WHERE user_id = $1 AND client_id = $2 AND withdrawn_at IS NULL"
        )
        .bind(user_id)
        .bind(client_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(consent)
    }

    /// Check if user has consented to scopes
    pub async fn has_consent(&self, user_id: Uuid, client_id: Uuid, required_scopes: &[String]) -> Result<bool> {
        if let Some(consent) = self.get_consent(user_id, client_id).await? {
            // Check if all required scopes are in granted scopes
            Ok(required_scopes.iter().all(|scope| consent.scopes.contains(scope)))
        } else {
            Ok(false)
        }
    }

    /// Withdraw consent (GDPR right)
    pub async fn withdraw_consent(&self, user_id: Uuid, client_id: Uuid) -> Result<()> {
        sqlx::query(
            "UPDATE consents SET withdrawn_at = NOW() WHERE user_id = $1 AND client_id = $2"
        )
        .bind(user_id)
        .bind(client_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get all consents for a user (GDPR data export)
    pub async fn get_user_consents(&self, user_id: Uuid) -> Result<Vec<Consent>> {
        let consents = sqlx::query_as::<_, Consent>(
            "SELECT * FROM consents WHERE user_id = $1 ORDER BY granted_at DESC"
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(consents)
    }
}
