use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub email_verified: bool,
    pub password_hash: String,
    
    // Profile fields
    pub name: Option<String>,
    pub phone_number: Option<String>,
    pub phone_number_verified: Option<bool>,
    pub picture_url: Option<String>,
    
    // Account status
    pub is_active: bool,
    pub is_admin: bool,
    
    // Security tracking
    pub failed_login_attempts: i32,
    pub locked_until: Option<DateTime<Utc>>,
    
    // Timestamps
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_login_at: Option<DateTime<Utc>>,
    pub password_changed_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateUserRequest {
    pub email: String,
    pub password: String,
    pub name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateUserRequest {
    pub name: Option<String>,
    pub phone_number: Option<String>,
    pub picture_url: Option<String>,
}

/// User repository for database operations
pub struct UserRepository {
    pool: PgPool,
}

impl UserRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create a new user
    pub async fn create(&self, email: &str, password_hash: &str, name: Option<&str>) -> Result<User> {
        let user = sqlx::query_as::<_, User>(
            r#"
            INSERT INTO users (email, password_hash, name, email_verified)
            VALUES ($1, $2, $3, false)
            RETURNING *
            "#,
        )
        .bind(email)
        .bind(password_hash)
        .bind(name)
        .fetch_one(&self.pool)
        .await?;

        Ok(user)
    }

    /// Find user by ID
    pub async fn find_by_id(&self, id: Uuid) -> Result<Option<User>> {
        let user = sqlx::query_as::<_, User>(
            "SELECT * FROM users WHERE id = $1"
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(user)
    }

    /// Find user by email
    pub async fn find_by_email(&self, email: &str) -> Result<Option<User>> {
        let user = sqlx::query_as::<_, User>(
            "SELECT * FROM users WHERE email = $1"
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await?;

        Ok(user)
    }

    /// Update last login timestamp
    pub async fn update_last_login(&self, user_id: Uuid) -> Result<()> {
        sqlx::query(
            "UPDATE users SET last_login_at = NOW() WHERE id = $1"
        )
        .bind(user_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Increment failed login attempts
    pub async fn increment_failed_attempts(&self, user_id: Uuid) -> Result<i32> {
        let result = sqlx::query_scalar::<_, i32>(
            r#"
            UPDATE users 
            SET failed_login_attempts = failed_login_attempts + 1
            WHERE id = $1
            RETURNING failed_login_attempts
            "#
        )
        .bind(user_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(result)
    }

    /// Lock account for specified duration (OWASP ASVS 2.2.1)
    pub async fn lock_account(&self, user_id: Uuid, duration_seconds: i64) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE users 
            SET locked_until = NOW() + ($2 || ' seconds')::INTERVAL
            WHERE id = $1
            "#
        )
        .bind(user_id)
        .bind(duration_seconds)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Reset failed login attempts (after successful login)
    pub async fn reset_failed_attempts(&self, user_id: Uuid) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE users 
            SET failed_login_attempts = 0, locked_until = NULL
            WHERE id = $1
            "#
        )
        .bind(user_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Check if account is locked
    pub async fn is_account_locked(&self, user_id: Uuid) -> Result<bool> {
        let locked_until = sqlx::query_scalar::<_, Option<DateTime<Utc>>>(
            "SELECT locked_until FROM users WHERE id = $1"
        )
        .bind(user_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(locked_until.map(|until| until > Utc::now()).unwrap_or(false))
    }

    /// Update user profile
    pub async fn update_profile(&self, user_id: Uuid, update: UpdateUserRequest) -> Result<User> {
        let user = sqlx::query_as::<_, User>(
            r#"
            UPDATE users 
            SET name = COALESCE($2, name),
                phone_number = COALESCE($3, phone_number),
                picture_url = COALESCE($4, picture_url),
                updated_at = NOW()
            WHERE id = $1
            RETURNING *
            "#
        )
        .bind(user_id)
        .bind(update.name)
        .bind(update.phone_number)
        .bind(update.picture_url)
        .fetch_one(&self.pool)
        .await?;

        Ok(user)
    }

    /// Update user password
    pub async fn update_password(&self, user_id: Uuid, new_password_hash: &str) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE users 
            SET password_hash = $2,
                password_changed_at = NOW(),
                updated_at = NOW()
            WHERE id = $1
            "#
        )
        .bind(user_id)
        .bind(new_password_hash)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Verify email address
    pub async fn verify_email(&self, user_id: Uuid) -> Result<()> {
        sqlx::query(
            "UPDATE users SET email_verified = true, updated_at = NOW() WHERE id = $1"
        )
        .bind(user_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Delete user (GDPR right to erasure)
    pub async fn delete(&self, user_id: Uuid) -> Result<()> {
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    /// Export all user data (GDPR data portability)
    pub async fn export_data(&self, user_id: Uuid) -> Result<serde_json::Value> {
        let user = self.find_by_id(user_id).await?
            .ok_or_else(|| anyhow::anyhow!("User not found"))?;

        // Include user profile and related data
        // TODO: Add sessions, consents, audit logs (with PII masking)
        Ok(serde_json::json!({
            "user_profile": {
                "email": user.email,
                "name": user.name,
                "phone_number": user.phone_number,
                "created_at": user.created_at,
            },
            "export_date": Utc::now(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests require database connection
    // Run with: cargo test -- --ignored
}
