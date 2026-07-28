use anyhow::{Context, Result};
use mcloving_controller_api::{ApiState, router};
use mcloving_controller_store::Store;
use sqlx::postgres::PgPoolOptions;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<()> {
    let database_url =
        std::env::var("MCLOVING_DATABASE_URL").context("MCLOVING_DATABASE_URL is required")?;
    let bearer_token =
        std::env::var("MCLOVING_API_TOKEN").context("MCLOVING_API_TOKEN is required")?;
    let listen = std::env::var("MCLOVING_LISTEN").unwrap_or_else(|_| "127.0.0.1:8080".to_owned());
    let pool = PgPoolOptions::new()
        .max_connections(16)
        .connect(&database_url)
        .await
        .context("connect to PostgreSQL")?;
    let store = Store::new(pool);
    store.migrate().await.context("migrate controller store")?;
    let state = ApiState::new(store, &bearer_token).context("configure public API")?;
    let listener = TcpListener::bind(&listen)
        .await
        .with_context(|| format!("bind controller to {listen}"))?;
    axum::serve(listener, router(state))
        .await
        .context("serve public API")
}
