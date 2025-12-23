use axum::{extract::State, http::StatusCode, Json};
use serde_json::{json, Value};

use crate::state::AppState;

/// Health check endpoint
pub async fn health(State(state): State<AppState>) -> (StatusCode, Json<Value>) {
    // Check database connection
    let db_ok = sqlx::query("SELECT 1")
        .fetch_one(&state.db)
        .await
        .is_ok();

    // Check Redis connection
    let redis_ok = redis::cmd("PING")
        .query_async::<_, String>(&mut state.redis.clone())
        .await
        .is_ok();

    let status = if db_ok && redis_ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    let response = json!({
        "status": if status == StatusCode::OK { "healthy" } else { "unhealthy" },
        "database": if db_ok { "ok" } else { "error" },
        "redis": if redis_ok { "ok" } else { "error" },
    });

    (status, Json(response))
}
