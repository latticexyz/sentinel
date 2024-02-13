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

    pub async fn put(&self, key: &[u8; 32], value: Bytes) -> eyre::Result<()> {
        self.store.put_preimage(key, &value)?;

        let key = format!("0x{}", hex::encode(key));
        if let Some(uri) = self.storage_uri.as_ref() {
            let uri = format!("{}/put/{}", uri, key);
            self.http_client.post(uri).body(value.0).send().await?;
        }

        tracing::info!("stored data for key {}", key);

        Ok(())
    }

    pub async fn get(&self, key: &[u8; 32]) -> eyre::Result<Option<Bytes>> {
        if let Ok(data) = self.store.get_preimage(key) {
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

    pub struct StorageHarness {
        pub store: Arc<Store>,
        pub client: StorageClient,
        pub storage_server: tokio::task::JoinHandle<()>,
        pub storage_address: String,
    }

    impl StorageHarness {
        pub async fn start() -> eyre::Result<Self> {
            use std::net::SocketAddr;
            use tokio::net::TcpListener;

            let dir = tempfile::tempdir().unwrap();

            let storage = da_storage::Storage::new_local(dir.path()).unwrap();
            let addr: SocketAddr = ([127, 0, 0, 1], 0).into();
            let listener = TcpListener::bind(addr).await.unwrap();
            let storage_addr = listener.local_addr().unwrap();

            let storage_server = tokio::spawn(async move {
                da_storage::serve_http(listener, storage).await.unwrap();
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

        pub fn random_input(&self) -> ([u8; 32], Bytes) {
            let mut data = vec![0u8; 100];
            rand::thread_rng().fill_bytes(&mut data);
            let hash = keccak256(&data);

            (hash, bytes::Bytes::from(data).into())
        }

        pub async fn put_random_input(&self) -> eyre::Result<([u8; 32], Bytes)> {
            let (key, data) = self.random_input();
            self.client.put(&key, data.clone()).await?;
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

        let result = sh.client.get(&key).await?;

        assert_eq!(Some(data.clone()), result);

        let new_client = sh.new_client();

        let result = new_client.get(&key).await?;

        assert_eq!(Some(data.clone()), result);

        let (new_key, _) = sh.random_input();
        let result = new_client.get(&new_key).await?;

        assert_eq!(None, result);

        Ok(())
    }
}
