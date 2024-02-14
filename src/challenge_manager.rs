use crate::bindings::{
    ChallengeStatusChangedFilter, DataAvailabilityChallenge, DataAvailabilityChallengeErrors,
    ResolveCall,
};
use crate::config::{Config, SystemConfig};
use crate::metrics::Metrics;
use crate::storage_client::StorageClient;
use crate::store::Store;
use ethers::contract::{ContractError, EthEvent};
use ethers::core::abi::{AbiDecode, RawLog};
use ethers::middleware::{MiddlewareError, SignerMiddleware};
use ethers::providers::StreamExt;
use ethers::providers::{Http, Middleware, PendingTransaction, Provider};
use ethers::signers::LocalWallet;
use ethers::types::{Bytes, TransactionReceipt, H256, U256};
use ethers::utils::hex;
use futures::stream::FuturesOrdered;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;
use tokio::{
    sync::mpsc::{channel, Sender},
    time::sleep,
};

type DacMiddleware<P> = SignerMiddleware<Provider<P>, LocalWallet>;

pub type Dac<P> = DataAvailabilityChallenge<DacMiddleware<P>>;

#[derive(Debug)]
pub enum ChallengeStatus {
    Uninitialized,
    Active,
    Resolved,
    Expired,
}

impl TryFrom<u8> for ChallengeStatus {
    type Error = eyre::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Uninitialized),
            1 => Ok(Self::Active),
            2 => Ok(Self::Resolved),
            3 => Ok(Self::Expired),
            _ => Err(eyre::eyre!("Invalid challenge status")),
        }
    }
}

pub async fn resolve_challenge(
    contract: Dac<Http>,
    at: u64,
    key: [u8; 32],
    data: Bytes,
) -> eyre::Result<()> {
    match contract.resolve(at.into(), key, data.into()).send().await {
        Ok(tx) => match tx
            .confirmations(6)
            .retries(5)
            .log_msg("pending tx for resolving challenge")
            .await
        {
            Ok(maybe_receipt) => {
                if maybe_receipt.is_none() {
                    eyre::bail!("Failed to resolve challenge, tx dropped from the mempool");
                }
            }
            Err(e) => {
                eyre::bail!("Failed to resolve challenge: {}", e);
            }
        },
        Err(e) => {
            if let ContractError::Revert(bytes) = &e {
                if let Ok(err) = DataAvailabilityChallengeErrors::decode(bytes) {
                    tracing::error!("Challenge contract error: {:?}", err);
                }
            }
            eyre::bail!("Failed to resolve challenge: {}", e);
        }
    }
    Ok(())
}

// Set a max number of retries so we're not vulnerable to a DoS attack.
const MAX_RETRIES: usize = 12;

#[derive(Copy, Clone)]
struct ResolveJob {
    block_number: u64,
    hash: [u8; 32],
    retries: usize,
}

impl ResolveJob {
    fn new(block_number: u64, hash: [u8; 32]) -> ResolveJob {
        ResolveJob {
            block_number,
            hash,
            retries: 0,
        }
    }
    async fn maybe_retry(self, sender: Sender<ResolveJob>) {
        let mut job = self;
        if job.retries > MAX_RETRIES {
            tracing::error!("Max retries reached for resolve job {:?}, dropping...", job);
            return;
        }
        job.retries += 1;
        sleep(Duration::from_secs(1)).await;
        if let Err(e) = sender.send(job).await {
            tracing::error!("Failed to send resolve job: {}", e);
        }
    }
}

impl std::fmt::Debug for ResolveJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{} x{}",
            hex::encode(&self.hash),
            self.block_number,
            self.retries
        )
    }
}

async fn handle_resolve_challenge(
    nonce: U256,
    job: ResolveJob,
    contract: Dac<Http>,
    storage: StorageClient,
) -> eyre::Result<Option<H256>> {
    tracing::debug!("handling new challenge {:?}", job);
    let bn = job.block_number;
    let key = job.hash;
    let status = contract.get_challenge_status(bn.into(), key).call().await?;
    let status =
        ChallengeStatus::try_from(status).unwrap_or_else(|_| ChallengeStatus::Uninitialized);

    if !matches!(status, ChallengeStatus::Active) {
        tracing::debug!("challenge not active ({:?})", status);
        return Ok(None);
    }
    tracing::debug!("challenge still active ({:?}), looking up data...", status);

    match storage.get(&job.hash).await {
        Ok(Some(data)) => {
            let call = contract.resolve(bn.into(), key, data.into()).nonce(nonce);
            tracing::debug!(
                "Submitting transaction for challenge {:?} with nonce {:?}",
                job,
                call.tx.nonce(),
            );
            match call.clone().send().await {
                Ok(pending_tx) => {
                    return Ok(Some(pending_tx.tx_hash()));
                }
                Err(e) => {
                    eyre::bail!(e);
                }
            }
        }
        Err(e) => {
            eyre::bail!(e);
        }
        _ => {
            tracing::error!("Could not find data in storage service for {:?}", job);
            Ok(None)
        }
    }
}

#[derive(Clone)]
pub struct ChallengeManager {
    config: Config,
    system_config: SystemConfig,
    store: Arc<Store>,
    storage_client: StorageClient,
    contract: Dac<Http>,
    metrics: Option<Metrics>,
    jobs: Sender<ResolveJob>,
}

impl std::fmt::Debug for ChallengeManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChallengeManager").finish()
    }
}

impl ChallengeManager {
    pub fn new(
        store: Arc<Store>,
        storage_client: StorageClient,
        contract: Dac<Http>,
        config: Config,
        metrics: Option<Metrics>,
    ) -> Self {
        let (tx, mut rx) = channel::<ResolveJob>(3200);

        let sender = tx.clone();

        let provider = contract.client().clone();

        let dac = contract.clone();

        let storage = storage_client.clone();
        // Start the resolver loop in a background task
        tokio::spawn(async move {
            let init_nonce = provider
                .get_transaction_count(provider.address(), None)
                .await
                .unwrap_or_default();

            let mut nonce = init_nonce.as_u64();

            tracing::debug!("Starting resolver loop with nonce {}", nonce);
            // pending txs are matched with pending resolves by index
            let mut pending_txs: FuturesOrdered<PendingTransaction<Http>> = Default::default();
            let mut pending_resolves = VecDeque::with_capacity(16);
            loop {
                tokio::select! {
                    Some(job) = rx.recv() => {
                        let tx_nonce = nonce;
                        nonce += 1;
                        match handle_resolve_challenge(tx_nonce.into(), job, dac.clone(), storage.clone()).await {
                            Ok(tx_hash) => {
                                if let Some(tx_hash) = tx_hash {
                                    let pending_tx = PendingTransaction::new(tx_hash, provider.provider())
                                        .confirmations(6)
                                        .retries(5)
                                        .log_msg("pending tx for resolving challenge");
                                    pending_txs.push_back(pending_tx);
                                    pending_resolves.push_back(job);
                                }
                            }
                            Err(e) => {
                                if let Some(err) = e.downcast_ref::<ContractError<DacMiddleware<Http>>>() {
                                    if let ContractError::Revert(bytes) = &err {
                                        if let Ok(err) = DataAvailabilityChallengeErrors::decode(bytes) {
                                            tracing::error!("Challenge contract error: {:?}", err);
                                        }
                                        tracing::error!("Failed to resolve challenge: {:?}, dropping challenge {:?}", err, job);
                                        // Do not retry contract errors, they will always fail
                                        continue;
                                    }
                                    if let ContractError::MiddlewareError { e } = &err {
                                        if let Some(rpc_err) = e.as_error_response() {
                                            if rpc_err.message.contains("nonce too low") {
                                            if let Ok(init_nonce) = provider
                                                .get_transaction_count(provider.address(), None)
                                                .await {
                                                    nonce = init_nonce.as_u64();
                                                }
                                            }
                                        }
                                    }
                                    tracing::error!("Failed to resolve challenge: {:?}", err);
                                } else {
                                    tracing::error!("Failed to resolve challenge: {}", e);
                                }
                                job.maybe_retry(sender.clone()).await;
                            }
                        }
                    }
                    Some(tx) = pending_txs.next() => {
                        let job = pending_resolves.pop_front().expect("pending resolves is empty");
                        if let Err(e) = &tx {
                            tracing::error!("ChallengeManager::run: failed to resolve challenge for {:?}: {}", job, e);
                            job.maybe_retry(sender.clone()).await;
                        }
                        if let Ok(Some(_)) = tx {
                            tracing::debug!("ChallengeManager::run: challenge resolved ({:?})", job);
                        } else {
                            if let Ok(init_nonce) = provider
                                .get_transaction_count(provider.address(), None)
                                .await {
                                    nonce = init_nonce.as_u64();
                            }
                            tracing::debug!("ChallengeManager::run: receipt not found for challenge {:?}, reinit nonce to {}", job, nonce);
                            job.maybe_retry(sender.clone()).await;
                        }
                    }
                    else => {
                        tracing::debug!("ChallengeManager::run: no pending tasks");
                    }
                }
            }
        });

        Self {
            system_config: config.genesis.system_config.clone(),
            config,
            store,
            storage_client,
            contract,
            metrics,
            jobs: tx,
        }
    }

    pub async fn load_bond(&self) -> eyre::Result<()> {
        let bond_size = self.contract.bond_size().await?;

        let address = self.contract.client().address();

        let balance = self.contract.balances(address).call().await?;
        if balance < bond_size {
            let mut deposit = self.contract.deposit();

            deposit.tx.set_value(bond_size - balance);

            let _receipt = deposit.send().await?.await?;
        }

        Ok(())
    }

    pub async fn challenge(&self, hash: [u8; 32], bn: u64) -> eyre::Result<()> {
        self.load_bond().await?;
        self.contract.challenge(bn.into(), hash).send().await?;
        Ok(())
    }

    pub async fn query_resolved_input(&self, hash: [u8; 32]) -> eyre::Result<Bytes> {
        let mut event = self
            .contract
            .challenge_status_changed_filter()
            .from_block(0);
        event.filter = event.filter.topic1(H256::from(hash));
        let logs = event.query_with_meta().await?;
        for (log, meta) in logs {
            if log.challenged_hash != hash {
                tracing::error!("Event filter returned wrong event");
                continue;
            }
            if log.status == 2 {
                let tx = self
                    .contract
                    .client()
                    .get_transaction(meta.transaction_hash)
                    .await?
                    .ok_or_else(|| eyre::eyre!("Transaction not found"))?;
                let call = ResolveCall::decode(tx.input.as_ref())?;
                return Ok(call.pre_image);
            }
        }
        Err(eyre::eyre!("No resolved input found"))
    }

    pub fn record_challenge_status(&self, status: ChallengeStatus) {
        if let Some(metrics) = self.metrics.as_ref() {
            match status {
                ChallengeStatus::Active => metrics.record_active_challenge(),
                ChallengeStatus::Resolved => metrics.record_resolved_challenge(),
                ChallengeStatus::Expired => metrics.record_expired_challenge(),
                _ => (),
            }
        }
    }

    async fn get_block_receipts(&self, block: H256) -> eyre::Result<Vec<TransactionReceipt>> {
        let provider = self.contract.client();
        let block = provider
            .get_block(block)
            .await?
            .ok_or_else(|| eyre::eyre!("Block not found: {:?}", block))?;
        let mut receipts = Vec::new();
        for tx in block.transactions {
            let receipt = provider
                .get_transaction_receipt(tx)
                .await?
                .ok_or_else(|| eyre::eyre!("Transaction receipt not found"))?;
            receipts.push(receipt);
        }
        Ok(receipts)
    }

    pub async fn load_block(&self, block: H256) -> eyre::Result<()> {
        let receipts = self.get_block_receipts(block).await?;

        for receipt in receipts {
            if receipt.status == Some(1.into())
                && receipt
                    .to
                    .map(|to| to == self.contract.address())
                    .unwrap_or(false)
            {
                tracing::debug!("Found new challenge tx receipt");
                for log in receipt.logs {
                    let raw = RawLog::from(log);
                    if let Ok(event) = ChallengeStatusChangedFilter::decode_log(&raw) {
                        if event.status == 1 {
                            tracing::debug!("Queing resolve job");
                            let job = ResolveJob::new(
                                event.challenged_block_number.as_u64(),
                                event.challenged_hash,
                            );
                            self.jobs.send(job).await?;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    pub async fn backfill(&self, latest: u64) -> eyre::Result<()> {
        let challenge_window = self.contract.challenge_window().await?;
        let resolve_window = self.contract.resolve_window().await?;

        let provider = self.contract.client();

        let lookback = challenge_window.as_u64() + resolve_window.as_u64();
        let mut start = 0;
        if latest > lookback {
            start = latest - lookback;
        }

        tracing::info!("Backfilling challenges from block {} to {}", start, latest);

        for i in start.. {
            if let Some(block) = provider.get_block_with_txs(i).await? {
                for tx in block.transactions {
                    if tx.to == Some(self.config.batch_inbox_address)
                        && tx.from == self.system_config.batcher_addr
                    {
                        let data: [u8; 32] = tx.input[..].try_into()?;

                        let status = self.contract.get_challenge_status(i.into(), data).await?;
                        if status == 1 {
                            let job = ResolveJob::new(i, data);
                            self.jobs.send(job).await?;
                        }
                    }
                }
            } else {
                break;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::storage_client::tests::StorageHarness;
    use ethers::core::utils::{Anvil, AnvilInstance};
    use ethers::prelude::*;
    use ethers::utils::hex;
    use std::sync::Arc;
    use std::time::Duration;
    // use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

    pub struct DacHarness {
        pub dac: Dac<Http>,
        pub anvil: AnvilInstance,
        pub storage: StorageHarness,
        pub provider: Arc<SignerMiddleware<Provider<Http>, LocalWallet>>,
        pub config: Config,
        pub commitments: Vec<(u64, [u8; 32])>,
    }

    impl DacHarness {
        pub async fn start() -> eyre::Result<Self> {
            let storage = StorageHarness::start().await?;
            let anvil = Anvil::new().spawn();
            let wallet: LocalWallet = anvil.keys()[0].clone().into();

            let user_address = wallet.address();

            println!(
                "Started Anvil node at {} with user {}",
                anvil.endpoint(),
                user_address
            );
            let mut provider = Provider::<Http>::try_from(anvil.endpoint())?;
            provider.set_interval(Duration::from_millis(100));
            let provider =
                Arc::new(provider.with_signer(wallet.clone().with_chain_id(anvil.chain_id())));

            let dac = DataAvailabilityChallenge::deploy(provider.clone(), ())?
                .send()
                .await?;
            let addr = dac.address();

            println!("Deployed contract at {}", addr);

            dac.initialize(
                user_address,
                U256::from(20),
                U256::from(70),
                U256::from(1000),
            )
            .send()
            .await?
            .await?;

            let config = Config::default()
                .with_challenge_contract(dac.address())
                .with_batch_inbox("0xff00000000000000000000000000000000000123".parse()?)
                .with_batcher_addr(user_address);

            Ok(Self {
                dac,
                anvil,
                storage,
                provider,
                config,
                commitments: vec![],
            })
        }

        pub async fn new_resolver(&self) -> eyre::Result<Dac<Http>> {
            // load up a different wallet for the challenger
            let challenger = LocalWallet::new(&mut ethers::core::rand::thread_rng());

            let tx = TransactionRequest::new()
                .to(challenger.address())
                .value(ethers::utils::parse_units("1", "ether")?);

            self.provider.send_transaction(tx, None).await?.await?;

            let mut provider = Provider::<Http>::try_from(self.anvil.endpoint())?;
            provider.set_interval(Duration::from_millis(100));
            let provider = Arc::new(
                provider.with_signer(challenger.clone().with_chain_id(self.anvil.chain_id())),
            );

            let dac = DataAvailabilityChallenge::new(self.dac.address(), provider.clone());
            Ok(dac)
        }

        pub async fn step(&mut self) -> eyre::Result<(Block<H256>, [u8; 32])> {
            // simulate batcher tx
            let (comm, _) = self.storage.put_random_input().await?;
            let tx = TransactionRequest::new()
                .to(self.config.batch_inbox_address)
                .data(comm);
            let tx = self.provider.send_transaction(tx, None).await?;
            println!("published tx: {:?} ", tx);
            // let receipt = tx.await?;
            // println!("included tx {:?}", receipt);
            let block = self
                .provider
                .get_block(BlockNumber::Latest)
                .await?
                .ok_or_else(|| eyre::eyre!("no block"))?;

            self.provider
                .inner()
                .request::<_, ()>("anvil_mine", vec![2])
                .await?;

            self.commitments
                .push((block.number.unwrap().as_u64(), comm));

            Ok((block, comm))
        }

        pub async fn new_challenge(&self, bn: u64, hash: [u8; 32]) -> eyre::Result<u64> {
            let bond_size = self.dac.bond_size().await?;
            let mut deposit = self.dac.deposit();

            deposit.tx.set_value(bond_size);

            let _ = deposit.send().await?;

            if let Err(e) = self.dac.challenge(bn.into(), hash).send().await {
                if let ContractError::Revert(bytes) = e {
                    if let Ok(err) = DataAvailabilityChallengeErrors::decode(bytes) {
                        eyre::bail!("Challenge contract error: {:?}", err);
                    }
                }
            }
            println!(
                "challenged commitment {} at block {}",
                hex::encode(hash),
                bn
            );

            let bn = self.provider.get_block_number().await?.as_u64();

            Ok(bn)
        }

        pub async fn verify_resolved(&self) -> eyre::Result<()> {
            for (bn, hash) in &self.commitments {
                let status = self
                    .dac
                    .get_challenge_status((*bn).into(), *hash)
                    .call()
                    .await?;
                if status != 2 {
                    eyre::bail!(
                        "commitment {} at block {} not resolved",
                        hex::encode(hash),
                        bn
                    );
                }
            }
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_auto_resolve() -> eyre::Result<()> {
        // tracing_subscriber::registry()
        //     .with(
        //         tracing_subscriber::EnvFilter::try_from_default_env()
        //             .unwrap_or_else(|_| "rpc=warn,da_service=debug".into()),
        //     )
        //     .with(tracing_subscriber::fmt::layer())
        //     .init();

        println!(
            "Generated challenge contract bindings at {}/contract_bindings.rs",
            env!("OUT_DIR")
        );

        let mut harness = DacHarness::start().await?;

        let wsp = Provider::<Ws>::connect(harness.anvil.ws_endpoint()).await?;

        let mut stream = wsp.subscribe_blocks().await?.take(60);

        let challenge_manager = ChallengeManager::new(
            harness.storage.store.clone(),
            harness.storage.client.clone(),
            harness.new_resolver().await?,
            harness.config.clone(),
            None,
        );

        for _ in 0..10 {
            let (block, hash) = harness.step().await?;
            let bn = block.number.unwrap().as_u64();

            harness.new_challenge(bn, hash).await?;
        }

        while let Some(block) = stream.next().await {
            println!("{:?}", block.hash);

            challenge_manager.load_block(block.hash.unwrap()).await?;
        }

        harness.verify_resolved().await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_backfill() -> eyre::Result<()> {
        let mut harness = DacHarness::start().await?;

        let challenge_manager = ChallengeManager::new(
            harness.storage.store.clone(),
            harness.storage.client.clone(),
            harness.new_resolver().await?,
            harness.config.clone(),
            None,
        );

        for _ in 0..10 {
            let (block, hash) = harness.step().await?;
            let bn = block.number.unwrap().as_u64();

            harness.new_challenge(bn, hash).await?;
        }

        let latest = harness.provider.get_block_number().await?.as_u64();

        challenge_manager.backfill(latest).await?;

        harness.verify_resolved().await?;

        Ok(())
    }
}
