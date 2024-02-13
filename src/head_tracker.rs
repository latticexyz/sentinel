use ethers::core::rand::random;
use ethers::prelude::*;
use std::cmp::Ordering;

#[derive(Default, Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct BlockId {
    pub hash: H256,
    pub number: u64,
}

impl TryFrom<Block<TxHash>> for BlockId {
    type Error = eyre::Error;
    fn try_from(block: Block<TxHash>) -> eyre::Result<Self> {
        let (hash, number) = block
            .hash
            .zip(block.number)
            .ok_or_else(|| eyre::eyre!("Block is pending: {:?}", block))?;
        Ok(Self {
            hash: hash,
            number: number.as_u64(),
        })
    }
}

#[derive(Clone, Debug, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct L2BlockRef {
    pub hash: H256,
    pub number: u64,
    pub parent_hash: H256,
    pub timestamp: u64,
    pub l1origin: BlockId,
    pub sequence_number: u64,
}

impl Ord for L2BlockRef {
    fn cmp(&self, other: &Self) -> Ordering {
        self.number.cmp(&other.number)
    }
}

impl PartialOrd for L2BlockRef {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for L2BlockRef {
    fn eq(&self, other: &Self) -> bool {
        self.number == other.number
    }
}

impl L2BlockRef {
    pub fn random() -> Self {
        Self {
            hash: H256::random(),
            number: random::<u64>(),
            parent_hash: H256::random(),
            timestamp: random::<u64>(),
            l1origin: BlockId {
                hash: H256::random(),
                number: random::<u64>(),
            },
            sequence_number: 0,
        }
    }

    pub fn next_random(&self) -> Self {
        Self {
            hash: H256::random(),
            number: self.number + 1,
            parent_hash: self.hash,
            timestamp: self.timestamp + 1,
            l1origin: self.l1origin.clone(),
            sequence_number: self.sequence_number + 1,
        }
    }
}
