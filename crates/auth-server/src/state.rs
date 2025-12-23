use anyhow::Result;
use redis::aio::ConnectionManager;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::sync::Arc;

use crate::config::Config;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub db: PgPool,
    pub redis: ConnectionManager,
}

impl AppState {
    pub async fn new(config: Config) -> Result<Self> {
        // Initialize PostgreSQL connection pool
        let db = PgPoolOptions::new()
            .max_connections(config.database.max_connections)
            .min_connections(config.database.min_connections)
            .connect(&config.database.url)
            .await?;

        // Run migrations
        sqlx::migrate!("../../migrations")
            .run(&db)
            .await?;

        // Initialize Redis connection
        let redis_client = redis::Client::open(config.redis.url.as_str())?;
        let redis = ConnectionManager::new(redis_client).await?;

        Ok(Self {
            config: Arc::new(config),
            db,
            redis,
        })
    }
}
