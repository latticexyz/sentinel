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
use ethers::types::{Bytes, Transaction, TransactionReceipt, H256, U256};
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

#[derive(Debug, Copy, Clone)]
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
    match contract
        .resolve(at.into(), key.into(), data.into())
        .send()
        .await
    {
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

#[derive(Clone)]
struct Job {
    block_number: u64,
    comm: Bytes,
    retries: usize,
    job_type: JobType,
}

#[derive(Clone, Debug)]
enum JobType {
    Challenge,
    Resolve,
}

impl Job {
    fn new(jt: JobType, block_number: u64, comm: Bytes) -> Job {
        Job {
            block_number,
            comm,
            retries: 0,
            job_type: jt,
        }
    }
    async fn maybe_retry(self, sender: Sender<Job>) {
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

    fn log_error(&self, e: &eyre::Error) {
        match self.job_type {
            JobType::Challenge => {
                tracing::error!("Job: {:?}: Failed to challenge commitment: {:?}", self, e);
            }
            JobType::Resolve => {
                tracing::error!("Job: {:?}: Failed to resolve challenge: {:?}", self, e);
            }
        }
    }

    fn log_success(&self) {
        match self.job_type {
            JobType::Challenge => {
                tracing::info!("Job: {:?}: Successfully challenged commitment", self);
            }
            JobType::Resolve => {
                tracing::info!("Job: {:?}: Successfully resolved challenge", self);
            }
        }
    }
}

impl std::fmt::Debug for Job {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:?}: {}:{} retries: {}",
            self.job_type,
            hex::encode(&self.comm),
            self.block_number,
            self.retries
        )
    }
}

async fn handle_resolve_challenge(
    nonce: U256,
    job: Job,
    contract: Dac<Http>,
    storage: StorageClient,
) -> eyre::Result<Option<H256>> {
    tracing::debug!("handling new challenge {:?}", job);
    let bn = job.block_number;
    let key = job.comm.clone();
    let status = contract
        .get_challenge_status(bn.into(), key.clone())
        .call()
        .await?;
    let status =
        ChallengeStatus::try_from(status).unwrap_or_else(|_| ChallengeStatus::Uninitialized);

    if !matches!(status, ChallengeStatus::Active) {
        tracing::debug!("challenge not active ({:?})", status);
        return Ok(None);
    }
    tracing::debug!("challenge still active ({:?}), looking up data...", status);

    match storage.get(key.clone()).await {
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
async fn load_bond(contract: Dac<Http>, nonce: Option<U256>) -> eyre::Result<()> {
    let bond_size = contract.bond_size().await?;

    let address = contract.client().address();

    let balance = contract.balances(address).call().await?;
    if balance < bond_size {
        let mut deposit = contract.deposit();

        deposit.tx.set_value(bond_size - balance);

        if let Some(nonce) = nonce {
            deposit.tx.set_nonce(nonce);
        }

        let _receipt = deposit.send().await?.await?;
    }

    Ok(())
}

async fn maybe_challenge_commitment(
    nonce: U256,
    job: Job,
    contract: Dac<Http>,
    storage: StorageClient,
) -> eyre::Result<Option<H256>> {
    tracing::debug!("handling new commitment {:?}", job);

    let key = job.comm.clone();
    let status = contract
        .get_challenge_status(job.block_number.into(), key.clone())
        .call()
        .await?;
    let status =
        ChallengeStatus::try_from(status).unwrap_or_else(|_| ChallengeStatus::Uninitialized);

    if matches!(status, ChallengeStatus::Active) {
        tracing::debug!("challenge already active ({:?})", status);
        return Ok(None);
    }

    if let Ok(None) = storage.get(key.clone()).await {
        tracing::debug!("loading bond");
        // Data is missing, challenge!
        load_bond(contract.clone(), Some(nonce)).await?;

        tracing::debug!("loaded bond");

        contract
            .challenge(job.block_number.into(), key.clone())
            .nonce(nonce + 1)
            .send()
            .await?;
    }

    return Ok(None);
}

async fn handle_job(
    nonce: U256,
    job: Job,
    contract: Dac<Http>,
    storage: StorageClient,
) -> eyre::Result<Option<H256>> {
    match job.job_type {
        JobType::Challenge => maybe_challenge_commitment(nonce, job, contract, storage).await,
        JobType::Resolve => handle_resolve_challenge(nonce, job, contract, storage).await,
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
    jobs: Sender<Job>,
    auto_challenge: bool,
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
        let (tx, mut rx) = channel::<Job>(3200);

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

                        // challenging takes 2 transactions
                        if matches!(job.job_type, JobType::Challenge) {
                            nonce += 2;
                        } else {
                            nonce += 1;
                        }

                        match handle_job(tx_nonce.into(), job.clone(), dac.clone(), storage.clone()).await {
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
                                        job.log_error(&e);
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
                                }
                                job.log_error(&e);
                                job.maybe_retry(sender.clone()).await;
                            }
                        }
                    }
                    Some(tx) = pending_txs.next() => {
                        let job = pending_resolves.pop_front().expect("pending resolves is empty");
                        match &tx {
                            Ok(Some(_)) => {
                                job.log_success();
                            }
                            Ok(None) => {
                                if let Ok(init_nonce) = provider
                                    .get_transaction_count(provider.address(), None)
                                    .await {
                                        nonce = init_nonce.as_u64();
                                }
                                tracing::debug!("ChallengeManager::run: receipt not found for job {:?}, reinit nonce to {}", job, nonce);
                                job.maybe_retry(sender.clone()).await;
                            }
                            Err(e) => {
                                job.log_error(&eyre::format_err!("{:?}", e));
                                job.maybe_retry(sender.clone()).await;
                            }
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
            auto_challenge: false,
        }
    }

    pub fn set_auto_challenge(mut self, value: bool) -> Self {
        self.auto_challenge = value;
        self
    }

    pub async fn query_resolved_input(&self, comm: Bytes) -> eyre::Result<Bytes> {
        let event = self
            .contract
            .challenge_status_changed_filter()
            .from_block(0);
        let logs = event.query_with_meta().await?;
        for (log, meta) in logs {
            if log.challenged_commitment != comm {
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
                return Ok(call.resolve_data);
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

    async fn get_block_txs(&self, block: H256) -> eyre::Result<Vec<Transaction>> {
        let provider = self.contract.client();
        let block = provider
            .get_block_with_txs(block)
            .await?
            .ok_or_else(|| eyre::eyre!("Block not found: {:?}", block))?;
        Ok(block.transactions)
    }

    async fn get_block_receipts(
        &self,
        txs: Vec<Transaction>,
    ) -> eyre::Result<Vec<TransactionReceipt>> {
        let provider = self.contract.client();
        let mut receipts = Vec::new();
        for tx in txs {
            let receipt = provider
                .get_transaction_receipt(tx.hash)
                .await?
                .ok_or_else(|| eyre::eyre!("Transaction receipt not found"))?;
            receipts.push(receipt);
        }
        Ok(receipts)
    }

    pub async fn load_block(&self, block: H256) -> eyre::Result<()> {
        let txs = self.get_block_txs(block).await?;

        if self.auto_challenge {
            for tx in &txs {
                if tx.to == Some(self.config.batch_inbox_address)
                    && tx.from == self.system_config.batcher_addr
                {
                    if tx.block_number.is_none() || !self.is_valid_commitment(&tx.input) {
                        tracing::error!("Skipping invalid tx data: {:?}", tx);
                        continue;
                    }
                    let job = Job::new(
                        JobType::Challenge,
                        tx.block_number.unwrap().as_u64(),
                        tx.input.0.slice(1..).into(),
                    );
                    tracing::debug!("Queing challenge job: {:?}", job);
                    self.jobs.send(job).await?;
                }
            }
        }

        let receipts = self.get_block_receipts(txs).await?;

        for receipt in receipts {
            let is_sender = self.is_sender(&receipt);
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
                        let status = ChallengeStatus::try_from(event.status)?;
                        self.record_challenge_status(status);
                        // do not try to resolve if we are the challenger
                        if matches!(status, ChallengeStatus::Active) && !is_sender {
                            let job = Job::new(
                                JobType::Resolve,
                                event.challenged_block_number.as_u64(),
                                event.challenged_commitment,
                            );
                            tracing::debug!("Queing resolve job: {:?}", job);
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
                        if !self.is_valid_commitment(&tx.input) {
                            tracing::info!("skipping invalid commitment: {}", tx.input);
                            continue;
                        }
                        // skip first tx data byte
                        let status = self
                            .contract
                            .get_challenge_status(i.into(), tx.input.0.slice(1..).into())
                            .await?;
                        if status == 1 {
                            let job = Job::new(JobType::Resolve, i, tx.input);
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

    fn is_sender(&self, receipt: &TransactionReceipt) -> bool {
        receipt.from == self.contract.client().address()
    }

    fn is_valid_commitment(&self, comm: &Bytes) -> bool {
        // validate txDataVersion1
        if comm[0] != 1 {
            return false;
        }
        // validate comm version 0
        if comm[1] != 0 {
            return false;
        }
        // 32 + 2 prefix bytes
        comm.len() == 34
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::storage_client::tests::StorageHarness;
    use ethers::core::utils::{Anvil, AnvilInstance};
    use ethers::prelude::*;
    use ethers::signers::{coins_bip39::English, MnemonicBuilder};
    use ethers::utils::hex;
    use std::sync::Arc;
    use std::time::Duration;
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

    pub struct DacHarness {
        pub dac: Dac<Http>,
        pub anvil: AnvilInstance,
        pub storage: StorageHarness,
        pub provider: Arc<SignerMiddleware<Provider<Http>, LocalWallet>>,
        pub config: Config,
        pub commitments: Vec<(u64, Bytes)>,
    }

    impl DacHarness {
        pub async fn start() -> eyre::Result<Self> {
            let storage = StorageHarness::start().await?;
            let anvil = Anvil::new()
                .arg("--init")
                .arg("l1-genesis.json")
                .arg("--chain-id")
                .arg("900")
                .spawn();
            let wallet = MnemonicBuilder::<English>::default()
                .phrase("test test test test test test test test test test test junk")
                .build()?;

            let user_address = wallet.address();

            println!(
                "Started Anvil node at {} with user {}",
                anvil.endpoint(),
                user_address
            );
            let mut provider = Provider::<Http>::try_from(anvil.endpoint())?;
            provider.set_interval(Duration::from_millis(100));
            let provider = Arc::new(provider.with_signer(wallet.clone().with_chain_id(900u64)));

            let proxy_address: Address = "0x978e3286EB805934215a88694d80b09aDed68D90".parse()?;

            let dac = DataAvailabilityChallenge::new(proxy_address, provider.clone());

            println!("Init contract at {:?}", dac.address());

            let config = Config::default()
                .with_challenge_contract(dac.address())
                .with_batch_inbox("0xff00000000000000000000000000000000000901".parse()?)
                .with_batcher_addr(user_address);

            println!("{:?}", config);

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

            // print the balance of the provider
            let balance = self
                .provider
                .get_balance(self.provider.address(), None)
                .await?;
            println!("Balance: {}", balance);

            let tx = TransactionRequest::new()
                .to(challenger.address())
                .value(ethers::utils::parse_units("1000", "ether")?);

            self.provider.send_transaction(tx, None).await?.await?;

            let mut provider = Provider::<Http>::try_from(self.anvil.endpoint())?;
            provider.set_interval(Duration::from_millis(100));
            let provider = Arc::new(provider.with_signer(challenger.clone().with_chain_id(900u64)));

            let dac = DataAvailabilityChallenge::new(self.dac.address(), provider.clone());
            Ok(dac)
        }

        pub async fn step(&mut self) -> eyre::Result<(Block<H256>, Bytes)> {
            // simulate batcher tx
            let (comm, _) = self.storage.put_random_input().await?;
            // prefix with txdata version 1
            let mut tx_data = vec![1];
            tx_data.extend_from_slice(&comm);

            let tx = TransactionRequest::new()
                .to(self.config.batch_inbox_address)
                .data(Bytes::from(tx_data));
            let tx = self
                .provider
                .send_transaction(tx, None)
                .await?
                .confirmations(1);
            let receipt = tx.await?;
            println!("included tx {:?}", receipt);
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
                .push((block.number.unwrap().as_u64(), comm.clone().into()));

            Ok((block, comm.into()))
        }

        pub async fn new_challenge(&self, bn: u64, comm: Bytes) -> eyre::Result<u64> {
            let bond_size = self.dac.bond_size().await?;
            let mut deposit = self.dac.deposit();

            deposit.tx.set_value(bond_size);

            let _ = deposit.send().await?;

            if let Err(e) = self.dac.challenge(bn.into(), comm.clone()).send().await {
                if let ContractError::Revert(bytes) = e {
                    if let Ok(err) = DataAvailabilityChallengeErrors::decode(bytes) {
                        eyre::bail!("Challenge contract error: {:?}", err);
                    }
                }
            }
            println!(
                "challenged commitment {} at block {}",
                hex::encode(&comm),
                bn
            );

            let bn = self.provider.get_block_number().await?.as_u64();

            Ok(bn)
        }

        pub async fn verify_resolved(&self) -> eyre::Result<()> {
            for (bn, comm) in &self.commitments {
                let status = self
                    .dac
                    .get_challenge_status((*bn).into(), comm.clone())
                    .call()
                    .await?;
                if status != 2 {
                    eyre::bail!(
                        "commitment {} at block {} not resolved",
                        hex::encode(&comm),
                        bn
                    );
                }
            }
            Ok(())
        }

        pub async fn verify_challenged(&self) -> eyre::Result<()> {
            for (bn, comm) in &self.commitments {
                let status = self
                    .dac
                    .get_challenge_status((*bn).into(), comm.clone())
                    .call()
                    .await?;
                if status != 1 {
                    eyre::bail!(
                        "commitment {} at block {} not challenged",
                        hex::encode(&comm),
                        bn
                    );
                }
            }

            Ok(())
        }
    }

    #[tokio::test]
    async fn test_auto_resolve() -> eyre::Result<()> {
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

    #[tokio::test]
    async fn test_auto_challenge() -> eyre::Result<()> {
        tracing_subscriber::registry()
            .with(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "rpc=warn,sentinel=debug".into()),
            )
            .with(tracing_subscriber::fmt::layer())
            .init();

        let mut harness = DacHarness::start().await?;

        let wsp = Provider::<Ws>::connect(harness.anvil.ws_endpoint()).await?;

        let mut stream = wsp.subscribe_blocks().await?.take(16);

        let store = harness.storage.store.clone();
        let remote = harness.storage.remote_storage.clone();

        let storage_client =
            StorageClient::new(store.clone(), Some(harness.storage.storage_address.clone()));

        let challenge_manager = ChallengeManager::new(
            store.clone(),
            storage_client,
            harness.new_resolver().await?,
            harness.config.clone(),
            None,
        )
        .set_auto_challenge(true);

        for _ in 0..3 {
            let (_, hash) = harness.step().await?;
            // make sure we don't store anything so the challenger is forced to challenge
            store.delete_preimage(hash.clone())?;
            let key_string = format!("0x{}", hex::encode(hash));
            remote.remove(key_string);
        }

        while let Some(block) = stream.next().await {
            println!("{:?}", block.hash);

            challenge_manager.load_block(block.hash.unwrap()).await?;
        }

        harness.verify_challenged().await?;

        Ok(())
    }
}
