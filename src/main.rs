use clap::Parser;
use sentinel::Sentinel;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[tokio::main]
async fn main() -> eyre::Result<()> {
    // Print tracing logs to stdout for now, we will record them somewhere else eventually
    tracing_subscriber::registry()
        .with(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| "rpc=warn,sentinel=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let sentinel = Sentinel::parse();

    let server = sentinel.spawn().await?;

    server.await?;

    Ok(())
}
