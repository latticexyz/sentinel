use crate::head_tracker::{BlockId, L2BlockRef};
use bytes::{Bytes, BytesMut};
use eyre::ContextCompat;
use rkyv::{Archive, Deserialize, Serialize};
use rocksdb::{ColumnFamilyDescriptor, Options, DB};

// Column family to store input data indexed by hash.
const CF_PREIMAGE_V0: &str = "preimage-v0";
// Column family to store challenge state indexed by hash of the challenged data.
const CF_CHALLENGE_V0: &str = "challenge-v0";
// Column family to store commitments by block number.
const CF_COMMITMENTS_V0: &str = "commitments-v0";
// Column family to store l2 block ref indexed by their L1 origin number
const CF_L2REF_V0: &str = "l2ref-v0";

// zero copy deserialization
#[derive(Debug, Archive, Deserialize, Serialize)]
#[repr(C)]
#[archive(check_bytes)]
#[archive_attr(repr(C))]
struct ChallengeV0 {
    block_number: u64,
    status: u8,
}

// Assert things without copying bytes unless we really need to.
#[derive(Clone)]
pub struct Comms(Bytes);

impl Comms {
    pub fn contains(&self, comm: &[u8; 32]) -> eyre::Result<bool> {
        let ccs = rkyv::check_archived_root::<Vec<[u8; 32]>>(&self.0[..])
            .map_err(|e| eyre::eyre!("invalid commitments: {}", e))?;

        Ok(ccs.contains(comm))
    }

    pub fn len(&self) -> eyre::Result<usize> {
        let ccs = rkyv::check_archived_root::<Vec<[u8; 32]>>(&self.0[..])
            .map_err(|e| eyre::eyre!("invalid commitments: {}", e))?;

        Ok(ccs.len())
    }

    pub fn commitments(&self) -> eyre::Result<Vec<[u8; 32]>> {
        let ccs = rkyv::check_archived_root::<Vec<[u8; 32]>>(&self.0[..])
            .map_err(|e| eyre::eyre!("invalid commitments: {}", e))?;

        Ok(ccs.iter().map(|c| *c).collect())
    }

    pub fn iter(&self) -> eyre::Result<std::slice::Iter<'_, [u8; 32]>> {
        let ccs = rkyv::check_archived_root::<Vec<[u8; 32]>>(&self.0[..])
            .map_err(|e| eyre::eyre!("invalid commitments: {}", e))?;

        Ok(ccs.iter())
    }
}

#[derive(Debug, Archive, Deserialize, Serialize)]
#[repr(C)]
#[archive(check_bytes)]
#[archive_attr(repr(C))]
struct BlockIdV0 {
    hash: [u8; 32],
    number: u64,
}

impl From<BlockIdV0> for BlockId {
    fn from(block_id: BlockIdV0) -> Self {
        Self {
            hash: block_id.hash.into(),
            number: block_id.number.into(),
        }
    }
}

impl From<BlockId> for BlockIdV0 {
    fn from(block_id: BlockId) -> Self {
        Self {
            hash: block_id.hash.0,
            number: block_id.number,
        }
    }
}

#[derive(Debug, Archive, Deserialize, Serialize)]
#[repr(C)]
#[archive(check_bytes)]
#[archive_attr(repr(C))]
struct L2BlockRefV0 {
    hash: [u8; 32],
    number: u64,
    parent_hash: [u8; 32],
    timestamp: u64,
    l1origin: BlockIdV0,
    sequence_number: u64,
}

impl From<L2BlockRefV0> for L2BlockRef {
    fn from(block_ref: L2BlockRefV0) -> Self {
        Self {
            hash: block_ref.hash.into(),
            number: block_ref.number.into(),
            parent_hash: block_ref.parent_hash.into(),
            timestamp: block_ref.timestamp.into(),
            l1origin: block_ref.l1origin.into(),
            sequence_number: block_ref.sequence_number.into(),
        }
    }
}

// TODO: do not clone until JSON serialization
impl From<&ArchivedL2BlockRefV0> for L2BlockRef {
    fn from(abr: &ArchivedL2BlockRefV0) -> Self {
        Self {
            hash: abr.hash.into(),
            number: abr.number.into(),
            parent_hash: abr.parent_hash.into(),
            timestamp: abr.timestamp.into(),
            l1origin: BlockId {
                hash: abr.l1origin.hash.into(),
                number: abr.l1origin.number.into(),
            },
            sequence_number: abr.sequence_number.into(),
        }
    }
}

impl From<L2BlockRef> for L2BlockRefV0 {
    fn from(block_ref: L2BlockRef) -> Self {
        Self {
            hash: block_ref.hash.0,
            number: block_ref.number,
            parent_hash: block_ref.parent_hash.0,
            timestamp: block_ref.timestamp,
            l1origin: block_ref.l1origin.into(),
            sequence_number: block_ref.sequence_number,
        }
    }
}

pub struct Store {
    db: DB,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store").finish()
    }
}

impl Store {
    pub fn new<P: AsRef<std::path::Path>>(path: P) -> eyre::Result<Self> {
        let preimage = ColumnFamilyDescriptor::new(CF_PREIMAGE_V0, Options::default());
        let challenge = ColumnFamilyDescriptor::new(CF_CHALLENGE_V0, Options::default());
        let commitments = ColumnFamilyDescriptor::new(CF_COMMITMENTS_V0, Options::default());
        let l2ref = ColumnFamilyDescriptor::new(CF_L2REF_V0, Options::default());

        let mut db_opts = Options::default();
        db_opts.create_missing_column_families(true);
        db_opts.create_if_missing(true);

        let db = DB::open_cf_descriptors(
            &db_opts,
            path,
            vec![preimage, challenge, commitments, l2ref],
        )?;
        Ok(Self { db })
    }

    pub fn put_preimage<K: AsRef<[u8]>, V: AsRef<[u8]>>(
        &self,
        key: K,
        value: V,
    ) -> eyre::Result<()> {
        let handle = self
            .db
            .cf_handle(CF_PREIMAGE_V0)
            .context("missing column family: preimage")?;
        self.db.put_cf(handle, key, value)?;
        Ok(())
    }

    pub fn put_challenge(&self, key: &[u8; 32], block_number: u64, status: u8) -> eyre::Result<()> {
        let handle = self
            .db
            .cf_handle(CF_CHALLENGE_V0)
            .context("missing column family: challenge")?;
        let challenge = ChallengeV0 {
            block_number,
            status,
        };
        let challenge_bytes = rkyv::to_bytes::<_, 16>(&challenge)?;
        self.db.put_cf(handle, key, challenge_bytes)?;

        Ok(())
    }

    pub fn put_commitment(&self, key: &[u8; 32], bn: u64) -> eyre::Result<()> {
        let handle = self
            .db
            .cf_handle(CF_COMMITMENTS_V0)
            .context("missing column family: challenge_commitments")?;

        if let Ok(Some(slice)) = self.db.get_pinned_cf(handle, bn.to_be_bytes()) {
            // TODO: avoid copy, using the slice directly errors:
            // `unaligned buffer, expected alignment 4 but found alignment 1`
            let bytes = BytesMut::from(&slice[..]).freeze();
            let ccs = rkyv::check_archived_root::<Vec<[u8; 32]>>(&bytes)
                .map_err(|e| eyre::eyre!("invalid challenge commitments: {}", e))?;

            // Do not deserialize unless needed. Vec layout is a bit too complex to mutate the bytes
            // directly so we have to copy it then.
            if !ccs.contains(key) {
                let mut ccs: Vec<[u8; 32]> = ccs.into_iter().map(|c| *c).collect();
                ccs.push(*key);
                let ccs_bytes = rkyv::to_bytes::<_, 128>(&ccs)?;
                self.db.put_cf(handle, bn.to_be_bytes(), ccs_bytes)?;
            }
        } else {
            let ccs = vec![*key];
            let ccs_bytes = rkyv::to_bytes::<_, 128>(&ccs)?;
            self.db.put_cf(handle, bn.to_be_bytes(), ccs_bytes)?;
        }

        Ok(())
    }

    pub fn get_commitments(&self, bn: u64) -> eyre::Result<Comms> {
        let handle = self
            .db
            .cf_handle(CF_COMMITMENTS_V0)
            .context("missing column family: challenge_commitments")?;

        let slice = self
            .db
            .get_pinned_cf(handle, bn.to_be_bytes())?
            .ok_or_else(|| eyre::eyre!("key not found"))?;
        let bytes = BytesMut::from(&slice[..]).freeze();
        Ok(Comms(bytes))
    }

    fn get_cf<K: AsRef<[u8]>>(&self, cf: &str, key: K) -> eyre::Result<Bytes> {
        let handle = self
            .db
            .cf_handle(cf)
            .context(format!("missing column family: {}", cf))?;
        let slice = self
            .db
            .get_pinned_cf(handle, key)?
            .ok_or_else(|| eyre::eyre!("key not found"))?;
        let bytes = BytesMut::from(&slice[..]).freeze();
        Ok(bytes)
    }
    pub fn get_preimage<K: AsRef<[u8]>>(&self, key: K) -> eyre::Result<Bytes> {
        self.get_cf(CF_PREIMAGE_V0, key)
    }
    pub fn get_challenge<K: AsRef<[u8]>>(&self, key: K) -> eyre::Result<(u64, u8)> {
        let bytes = self.get_cf(CF_CHALLENGE_V0, key)?;
        let challenge = rkyv::check_archived_root::<ChallengeV0>(&bytes[..])
            .map_err(|e| eyre::eyre!("invalid challenge: {}", e))?;
        Ok((challenge.block_number, challenge.status))
    }

    fn delete_cf<K: AsRef<[u8]>>(&self, cf: &str, key: K) -> eyre::Result<()> {
        let handle = self
            .db
            .cf_handle(cf)
            .context(format!("missing column family: {}", cf))?;
        self.db.delete_cf(handle, key)?;
        Ok(())
    }

    pub fn delete_preimage<K: AsRef<[u8]>>(&self, key: K) -> eyre::Result<()> {
        self.delete_cf(CF_PREIMAGE_V0, key)
    }

    pub fn delete_challenge<K: AsRef<[u8]>>(&self, key: K) -> eyre::Result<()> {
        self.delete_cf(CF_CHALLENGE_V0, key)
    }

    pub fn delete_commitments(&self, block_number: u64) -> eyre::Result<()> {
        let handle = self
            .db
            .cf_handle(CF_COMMITMENTS_V0)
            .context("missing column family: commitments")?;
        self.db.delete_cf(handle, block_number.to_be_bytes())?;
        Ok(())
    }

    pub fn set_l2ref(&self, l2ref: L2BlockRef) -> eyre::Result<()> {
        // TODO: check if we already have an l2 ref with higher number
        // so we don't override it.
        let l1num = l2ref.l1origin.number;
        let handle = self
            .db
            .cf_handle(CF_L2REF_V0)
            .context("missing column family: l2ref")?;
        let l2ref: L2BlockRefV0 = l2ref.into();

        let l2ref_bytes = rkyv::to_bytes::<_, 128>(&l2ref)?;
        let key = l1num.to_be_bytes();
        self.db.put_cf(handle, key, l2ref_bytes)?;

        Ok(())
    }

    pub fn pop_l2ref(&self, l1num: u64) -> eyre::Result<L2BlockRef> {
        let key = l1num.to_be_bytes();
        let handle = self
            .db
            .cf_handle(CF_L2REF_V0)
            .context("missing column family: l2ref")?;
        let slice = self
            .db
            .get_pinned_cf(handle, key)?
            .ok_or_else(|| eyre::eyre!("key not found"))?;

        let l2ref = rkyv::check_archived_root::<L2BlockRefV0>(&slice[..])
            .map_err(|e| eyre::eyre!("invalid l2ref bytes: {}", e))?;

        self.db.delete_cf(handle, key)?;
        Ok(l2ref.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethers::prelude::*;
    use ethers::utils::keccak256;
    use std::sync::Arc;

    #[test]
    fn test_challenge_storage() {
        let dir = tempfile::tempdir().unwrap();

        let store = Arc::new(Store::new(dir.path()).unwrap());

        let key1 = keccak256(H256::random());
        let key2 = keccak256(H256::random());
        let key3 = keccak256(H256::random());

        store.put_commitment(&key1, 1).unwrap();
        store.put_commitment(&key2, 1).unwrap();
        store.put_commitment(&key3, 1).unwrap();

        let commitments = store.get_commitments(1).unwrap();
        assert_eq!(commitments.len().unwrap(), 3);

        assert!(commitments.contains(&key1).unwrap());
        assert!(commitments.contains(&key2).unwrap());
        assert!(commitments.contains(&key3).unwrap());
    }

    #[test]
    fn test_l2ref() {
        let dir = tempfile::tempdir().unwrap();

        let store = Arc::new(Store::new(dir).unwrap());

        let l2ref = L2BlockRef::random();

        let bn = l2ref.l1origin.number;

        let data1 = H256::random();
        let key1 = keccak256(data1);
        store.put_preimage(&key1, data1).unwrap();
        let data2 = H256::random();
        let key2 = keccak256(data2);
        store.put_preimage(&key2, data2).unwrap();
        let data3 = H256::random();
        let key3 = keccak256(data3);
        store.put_preimage(&key3, data3).unwrap();

        store.put_commitment(&key1, bn).unwrap();
        store.put_commitment(&key2, bn).unwrap();
        store.put_commitment(&key3, bn).unwrap();

        store.set_l2ref(l2ref).unwrap();

        let comms = store.get_commitments(bn).unwrap();
        assert_eq!(comms.len().unwrap(), 3);
    }

    #[test]
    fn test_comms() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(&dir).unwrap());

        for i in 0..600 {
            for _ in 0..4 {
                let data = H256::random();
                let key = keccak256(data);
                store.put_commitment(&key, i).unwrap();
            }

            if i > 300 {
                store.get_commitments(i - 300).unwrap();
            }
        }

        let comms = store.get_commitments(3).unwrap();
        assert_eq!(comms.len().unwrap(), 4);

        drop(store);
        let store = Arc::new(Store::new(dir).unwrap());
        let data = H256::random();
        let key = keccak256(data);
        store.put_commitment(&key, 3).unwrap();

        let comms = store.get_commitments(3).unwrap();
        assert_eq!(comms.len().unwrap(), 5);
    }
}
