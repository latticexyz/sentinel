use crate::head_tracker::BlockId;
use ethers::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemConfig {
    pub batcher_addr: Address,
    pub overhead: Bytes,
    pub scalar: Bytes,
    pub gas_limit: u64,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct Genesis {
    // The L1 block that the rollup starts *after* (no derived transactions)
    pub l1: BlockId,
    // The L2 block the rollup starts from (no transactions, pre-configured state)
    pub l2: BlockId,
    // Timestamp of L2 block
    pub l2_time: u64,
    // Initial system configuration values.
    // The L2 genesis block may not include transactions, and thus cannot encode the config values,
    // unlike later L2 blocks.
    pub system_config: SystemConfig,
}

// Config represents the rollup config.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub genesis: Genesis,
    pub block_time: u64,
    // Sequencer batches may not be more than MaxSequencerDrift seconds after
    // the L1 timestamp of the sequencing window end.
    //
    // Note: When L1 has many 1 second consecutive blocks, and L2 grows at fixed 2 seconds,
    // the L2 time may still grow beyond this difference.
    pub max_sequencer_drift: u64,
    // Number of epochs (L1 blocks) per sequencing window, including the epoch L1 origin block itself
    pub seq_window_size: u64,
    // Number of L1 blocks between when a channel can be opened and when it must be closed by.
    pub channel_timeout: u64,
    // Required to verify L1 signatures
    pub l1_chain_id: u64,
    // Required to identify the L2 network and create p2p signatures unique for this chain.
    pub l2_chain_id: u64,
    pub regolith_time: Option<u64>,
    pub canyon_time: Option<u64>,
    pub span_batch_time: Option<u64>,
    // L1 address that batches are sent to.
    pub batch_inbox_address: Address,
    // L1 Deposit Contract Address
    pub deposit_contract_address: Address,
    // L1 System Config Address
    pub l1_system_config_address: Address,
    // L1 address that declares the protocol versions, optional (Beta feature)
    pub protocol_versions_address: Option<Address>,
    // L1 Data Availability Challenge Contract Address
    pub da_challenge_address: Address,
    pub da_challenge_window: u64,
    pub da_resolve_window: u64,
    pub use_plasma: bool,
}

impl Config {
    pub fn load_from_file(path: impl AsRef<std::path::Path>) -> eyre::Result<Self> {
        let file = std::fs::File::open(path)?;
        let config = serde_json::from_reader(file)?;
        Ok(config)
    }

    pub fn with_challenge_contract(mut self, addr: Address) -> Self {
        self.da_challenge_address = addr;
        self
    }

    pub fn with_batch_inbox(mut self, addr: Address) -> Self {
        self.batch_inbox_address = addr;
        self
    }

    pub fn with_batcher_addr(mut self, addr: Address) -> Self {
        self.genesis.system_config.batcher_addr = addr;
        self
    }
}
