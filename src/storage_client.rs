use crate::store::Store;
use ethers::types::Bytes;
use ethers::utils::hex;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct StorageClient {
    store: Arc<Store>,
    storage_uri: Option<String>,
    http_client: reqwest::Client,
}

impl StorageClient {
    pub fn new(store: Arc<Store>, storage_uri: Option<String>) -> Self {
        let http_client = reqwest::Client::new();
        Self {
            store,
            storage_uri,
            http_client,
        }
    }

    pub async fn put(&self, key: Bytes, value: Bytes) -> eyre::Result<()> {
        self.store.put_preimage(&key, &value)?;

        let key = format!("0x{}", hex::encode(key));
        if let Some(uri) = self.storage_uri.as_ref() {
            let uri = format!("{}/put/{}", uri, key);
            self.http_client.post(uri).body(value.0).send().await?;
        }

        tracing::info!("stored data for key {}", key);

        Ok(())
    }

    pub async fn get(&self, key: Bytes) -> eyre::Result<Option<Bytes>> {
        if let Ok(data) = self.store.get_preimage(&key) {
            return Ok(Some(data.into()));
        }
        if let Some(uri) = self.storage_uri.as_ref() {
            let key_string = format!("0x{}", hex::encode(key));
            if let Ok(res) = self
                .http_client
                .get(format!("{}/get/{}", uri, key_string))
                .send()
                .await
            {
                if res.status() == reqwest::StatusCode::NOT_FOUND {
                    return Ok(None);
                }
                let data = res.bytes().await?;
                return Ok(Some(data.into()));
            }
        }
        Err(eyre::eyre!("failed to get data for key"))
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use ethers::core::rand::RngCore;
    use ethers::prelude::*;
    use ethers::utils::keccak256;
    use http_body_util::{BodyExt, Full};
    use hyper::body::{Bytes, Incoming};
    use hyper::server::conn::http1;
    use hyper::service::Service;
    use hyper::{Request, Response};
    use hyper_util::rt::TokioIo;
    use std::collections::HashMap;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use tokio::net::TcpListener;

    #[derive(Clone, Default)]
    pub struct Storage {
        memstore: Arc<Mutex<HashMap<String, Bytes>>>,
    }

    impl std::fmt::Debug for Storage {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Storage").finish()
        }
    }

    impl Storage {
        pub fn new() -> Self {
            Default::default()
        }
        async fn get(&self, key: String) -> eyre::Result<Option<Bytes>> {
            Ok(self.memstore.lock().unwrap().get(&key).cloned())
        }

        async fn put(&self, key: String, value: Bytes) -> eyre::Result<()> {
            self.memstore.lock().unwrap().insert(key, value);
            Ok(())
        }
    }

    impl Service<Request<Incoming>> for Storage {
        type Response = Response<Full<Bytes>>;
        type Error = eyre::Error;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

        #[tracing::instrument(name = "Service::call")]
        fn call(&self, req: Request<Incoming>) -> Self::Future {
            let method = req.method().clone();
            let path = req.uri().path();
            tracing::info!("method: {:?}, path: {}", method, path);
            if path.starts_with("/healthz") {
                return Box::pin(async {
                    Ok(Response::builder()
                        .body(Full::new(Bytes::from("ok")))
                        .unwrap())
                });
            }

            if path.starts_with("/get") {
                let store = self.clone();
                let key = path.trim_start_matches("/get/").to_string();
                return Box::pin(async move {
                    let resp = Response::builder().header("Access-Control-Allow-Origin", "*");
                    match store.get(key).await {
                        Ok(Some(value)) => Ok(resp.body(Full::new(value)).unwrap()),
                        Ok(None) => {
                            tracing::error!("key not found");
                            Ok(resp
                                .status(404)
                                .body(Full::new(Bytes::from("Not Found")))
                                .unwrap())
                        }
                        Err(e) => Ok(resp
                            .status(500)
                            .body(Full::new(Bytes::from(format!("Error: {}", e))))
                            .unwrap()),
                    }
                });
            }

            if path.starts_with("/put") {
                let store = self.clone();
                let key = path.trim_start_matches("/put/").to_string();
                return Box::pin(async move {
                    let value = req.into_body().collect().await?;
                    store.put(key.clone(), value.to_bytes()).await.map(|_| {
                        Response::builder()
                            .body(Full::new(Bytes::from(key)))
                            .unwrap()
                    })
                });
            }

            return Box::pin(async {
                Ok(Response::builder()
                    .status(404)
                    .body(Full::new(Bytes::from("Not Found")))
                    .unwrap())
            });
        }
    }

    pub async fn serve_http(listener: TcpListener, storage: Storage) -> eyre::Result<()> {
        loop {
            let (tcp, _) = listener.accept().await?;
            let io = TokioIo::new(tcp);

            let store = storage.clone();
            tokio::task::spawn(async move {
                if let Err(err) = http1::Builder::new().serve_connection(io, store).await {
                    tracing::error!("Error serving connection: {:?}", err);
                }
            });
        }
    }

    pub struct StorageHarness {
        pub store: Arc<Store>,
        pub client: StorageClient,
        pub storage_server: tokio::task::JoinHandle<()>,
        pub storage_address: String,
    }

    impl StorageHarness {
        pub async fn start() -> eyre::Result<Self> {
            use std::net::SocketAddr;

            let storage = Storage::new();
            let addr: SocketAddr = ([127, 0, 0, 1], 0).into();
            let listener = TcpListener::bind(addr).await.unwrap();
            let storage_addr = listener.local_addr().unwrap();

            let storage_server = tokio::spawn(async move {
                serve_http(listener, storage).await.unwrap();
            });

            let dir = tempfile::tempdir().unwrap();
            let store = Arc::new(Store::new(dir).unwrap());

            let storage_address = format!("http://{}", storage_addr);
            let storage_client = StorageClient::new(store.clone(), Some(storage_address.clone()));

            Ok(Self {
                store,
                client: storage_client,
                storage_server,
                storage_address,
            })
        }

        pub fn random_input(&self) -> (Bytes, Bytes) {
            let mut data = vec![0u8; 100];
            rand::thread_rng().fill_bytes(&mut data);
            let hash = keccak256(&data);

            let mut key = vec![0];
            key.extend_from_slice(&hash);

            (key.into(), data.into())
        }

        pub async fn put_random_input(&self) -> eyre::Result<(Bytes, Bytes)> {
            let (key, data) = self.random_input();
            self.client
                .put(key.clone().into(), data.clone().into())
                .await?;
            Ok((key, data))
        }

        pub fn new_client(&self) -> StorageClient {
            let dir = tempfile::tempdir().unwrap();
            let store = Arc::new(Store::new(dir).unwrap());

            StorageClient::new(store, Some(self.storage_address.clone()))
        }
    }

    #[tokio::test]
    async fn storage_smoke_test() -> eyre::Result<()> {
        let sh = StorageHarness::start().await?;

        let (key, data) = sh.put_random_input().await?;

        let result = sh.client.get(key.clone().into()).await?;

        assert_eq!(Some(data.clone().into()), result);

        let new_client = sh.new_client();

        let result = new_client.get(key.into()).await?;

        assert_eq!(Some(data.clone().into()), result);

        let (new_key, _) = sh.random_input();
        let result = new_client.get(new_key.into()).await?;

        assert_eq!(None, result);

        Ok(())
    }
}
