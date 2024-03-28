use crate::bindings::DataAvailabilityChallenge;
use crate::challenge_manager::ChallengeManager;
use crate::config::Config;
use crate::metrics::Metrics;
use crate::storage_client::StorageClient;
use crate::store::Store;
use axum::{
    extract::Request,
    http::{header, StatusCode},
    routing::get,
    Router,
};
use clap::Parser;
use ethers::prelude::*;
use hyper::body::Incoming;
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server,
};
use prometheus_client::{encoding::text::encode, registry::Registry};
use std::future::IntoFuture;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::task::{JoinError, JoinHandle};
use tower::Service;
use tower_http::trace::TraceLayer;

#[derive(Debug, Parser)]
pub struct Sentinel {
    #[arg(short, long)]
    datadir: PathBuf,
    #[arg(long)]
    l1_rpc_http: String,
    #[arg(long)]
    l1_rpc_ws: String,
    #[arg(long)]
    da_storage_uri: String,
    #[arg(long, env = "SENTINEL_PRIVATE_KEY")]
    private_key: String,
    #[arg(long, default_value = "8064")]
    server_port: u16,
    #[arg(long)]
    config: Option<String>,
    #[arg(long, default_value = "false")]
    challenge: bool,
}

impl Sentinel {
    pub fn new(
        store: impl Into<PathBuf>,
        l1_rpc_http: String,
        l1_rpc_ws: String,
        da_storage_uri: String,
        private_key: String,
    ) -> Self {
        Self {
            datadir: store.into(),
            l1_rpc_http,
            l1_rpc_ws,
            da_storage_uri,
            private_key,
            server_port: 8064,
            config: None,
            challenge: false,
        }
    }
    pub async fn spawn(self) -> eyre::Result<SentinelHandle> {
        let wallet: LocalWallet = self.private_key.parse()?;

        let config = match self.config.as_ref() {
            Some(config) => Config::load_from_file(config)?,
            None => Config::default(),
        };

        let store = Arc::new(Store::new(&self.datadir)?);

        // remote storage for retrieving inputs when resolving challenges
        let storage_client = StorageClient::new(store.clone(), Some(self.da_storage_uri.clone()));

        let mut provider = Provider::<Http>::try_from(&self.l1_rpc_http)?;
        // transaction poll interval
        provider.set_interval(Duration::from_secs(3));

        let ch_id = provider.get_chainid().await?;
        tracing::info!("connected to l1 with chain id {}", ch_id);

        let client = Arc::new(provider.with_signer(wallet.clone().with_chain_id(ch_id.as_u64())));

        let dac = DataAvailabilityChallenge::new(config.da_challenge_address, client.clone());

        let mut registry = <Registry>::with_prefix("da_service");

        let metrics = Metrics::new(&mut registry);

        let challenges = ChallengeManager::new(
            store.clone(),
            storage_client.clone(),
            dac,
            config,
            Some(metrics.clone()),
        )
        .set_auto_challenge(self.challenge);

        let addr = format!("0.0.0.0:{}", self.server_port);

        let registry_state = Arc::new(registry);

        // expose health and metrics over http routes
        let svc = Router::new()
            .route("/healthz", get(health_probe))
            .route(
                "/metrics",
                get({
                    let registry_state = registry_state.clone();
                    || async move {
                        let mut buf = String::new();
                        encode(&mut buf, &registry_state)
                            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
                            .map(|_| {
                                (
                                [(
                                    header::CONTENT_TYPE,
                                    "application/openmetrics-text; version=1.0.0; charset=utf-8",
                                )],
                                buf,
                            )
                            })
                    }
                }),
            )
            .layer(TraceLayer::new_for_http());

        let listener = tokio::net::TcpListener::bind(&addr).await?;

        let addr = listener.local_addr()?;

        tracing::info!("Listening on {}", addr);

        let latest = client.get_block_number().await?;
        let ch = challenges.clone();
        tokio::spawn(async move {
            if let Err(e) = ch.backfill(latest.as_u64()).await {
                tracing::error!("failed to load blocks: {}", e);
            } else {
                tracing::info!("backfill complete");
            }
        });

        let handle = tokio::spawn(async move {
            let mut sigterm =
                match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                    Ok(stream) => stream,
                    Err(e) => {
                        tracing::error!("failed to create signal stream: {}", e);
                        return;
                    }
                };

            loop {
                match Provider::<Ws>::connect(&self.l1_rpc_ws).await {
                    Ok(wsp) => {
                        if let Ok(mut stream) = wsp.subscribe_blocks().await {
                            loop {
                                tokio::select! {
                                    conn = listener.accept() => {
                                        match conn {
                                            Ok((socket, _)) => {
                                                handle_conn(socket, svc.clone());
                                            }
                                            Err(e) => {
                                                tracing::error!("failed to accept connection: {}", e);
                                            }
                                        }
                                    }
                                    block = stream.next() => {
                                        if let Some(block) = block {
                                            let num = block.number;
                                            let hash = match block.hash {
                                                Some(hash) => hash,
                                                None => {
                                                    // should never happen but just in case
                                                    tracing::error!("block missing hash: {:?}", block);
                                                    continue;
                                                }
                                            };
                                            match challenges.load_block(hash).await {
                                                Ok(_) => {
                                                    tracing::info!("loaded block {:?}, {:?}", num, hash);
                                                }
                                                Err(e) => {
                                                    tracing::error!("failed to load block: {}", e);
                                                }
                                            }
                                        }
                                    }
                                    _ = sigterm.recv() => {
                                        tracing::info!("received SIGTERM, shutting down");
                                    }

                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("failed to connect to l1 ws: {:?}", e);
                    }
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        });

        Ok(SentinelHandle {
            local_addr: addr,
            handle: handle,
        })
    }
}

async fn health_probe() -> &'static str {
    "ok"
}

pub struct SentinelHandle {
    local_addr: SocketAddr,
    handle: JoinHandle<()>,
}

impl SentinelHandle {
    pub fn close(&self) {
        self.handle.abort()
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

impl IntoFuture for SentinelHandle {
    type Output = Result<(), JoinError>;
    type IntoFuture = JoinHandle<()>;

    fn into_future(self) -> Self::IntoFuture {
        self.handle
    }
}

fn handle_conn(stream: TcpStream, router: Router) {
    tokio::spawn(async move {
        let socket = TokioIo::new(stream);

        let hyper_service = hyper::service::service_fn(move |request: Request<Incoming>| {
            // We have to clone `tower_service` because hyper's `Service` uses `&self` whereas
            // tower's `Service` requires `&mut self`.
            //
            // We don't need to call `poll_ready` since `Router` is always ready.
            router.clone().call(request)
        });

        if let Err(err) = server::conn::auto::Builder::new(TokioExecutor::new())
            .serve_connection(socket, hyper_service)
            .await
        {
            eprintln!("failed to serve connection: {err:#}");
        }
    });
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::challenge_manager::tests::DacHarness;
    use ethers::core::utils::hex::ToHex;

    #[tokio::test]
    async fn test_spawn() -> eyre::Result<()> {
        let mut harness = DacHarness::start().await?;

        for _ in 0..10 {
            let (block, hash) = harness.step().await?;
            let bn = block.number.unwrap().as_u64();

            harness.new_challenge(bn, hash).await?;
        }

        let dir = tempfile::tempdir().unwrap();

        let sentinel = Sentinel::new(
            dir.path(),
            harness.anvil.endpoint(),
            harness.anvil.ws_endpoint(),
            harness.storage.storage_address,
            harness.anvil.keys()[0].to_bytes().encode_hex(),
        );

        let server = sentinel.spawn().await?;

        let ok = reqwest::get(format!("http://{}/healthz", server.local_addr()))
            .await?
            .text()
            .await?;

        assert_eq!(ok, "ok");

        server.close();

        Ok(())
    }
}
