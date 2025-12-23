use anyhow::Result;
use axum::{
    routing::{get, post},
    Router,
};
use std::net::SocketAddr;
use tower_http::{
    cors::CorsLayer,
    trace::TraceLayer,
    compression::CompressionLayer,
};
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod config;
mod routes;
mod state;
mod error;
mod authz_code;

use config::Config;
use state::AppState;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,auth_server=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer().json())
        .init();

    info!("Starting OIDC 2.1 Authorization Server");

    // Load configuration
    dotenvy::dotenv().ok();
    let config = Config::load()?;
    
    info!("Configuration loaded successfully");
    info!("Server base URL: {}", config.server.base_url);

    // Initialize application state
    let state = AppState::new(config).await?;
    
    info!("Database pool initialized");
    info!("Redis connection established");

    // Build router
    let app = Router::new()
        // OAuth 2.1 / OIDC endpoints
        .route("/.well-known/openid-configuration", get(routes::discovery::openid_configuration))
        .route("/authorize", get(routes::authorize::authorize))
        .route("/token", post(routes::token::token))
        .route("/userinfo", get(routes::userinfo::userinfo))
        .route("/jwks", get(routes::jwks::jwks))
        .route("/revoke", post(routes::revoke::revoke))
        .route("/introspect", post(routes::introspect::introspect))
        
        // Authentication endpoints
        .route("/auth/login", post(routes::login::login))
        .route("/auth/logout", post(routes::login::logout))
        
        // Health check
        .route("/health", get(routes::health::health))
        
        // Middleware
        .layer(CompressionLayer::new())
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive()) // TODO: Configure CORS properly
        
        // Application state
        .with_state(state);

    // Start server
    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    info!("Listening on {}", addr);
    
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .await?;

    Ok(())
}
