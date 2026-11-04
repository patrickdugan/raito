//! Durable batch boundaries for the recursive Cairo/STWO header prover.
//! Manifests are scheduling records, never substitutes for cryptographic proofs.
use anyhow::{anyhow, bail, Context, Result};
use blake2::{Blake2s256, Digest};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const VERSION: u32 = 1;
const MANIFEST: &str = "checkpoint.json";
const PROOF: &str = "proof.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointIdentity {
    pub genesis_hash: String,
    pub executable_hash: String,
    pub prover_params_hash: Option<String>,
    pub verifier_config_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchCheckpoint {
    pub version: u32,
    pub start_height: u32,
    pub end_height: u32,
    pub identity: CheckpointIdentity,
    pub parent_proof_hash: Option<String>,
    pub proof_hash: String,
    pub chain_state_hash: String,
}

/// Stream large files through a fixed-size digest buffer.
pub fn hash_file(path: &Path) -> Result<String> {
    let mut reader = File::open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    let mut digest = Blake2s256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex::encode(digest.finalize()))
}

pub fn hash_bytes(bytes: &[u8]) -> String {
    let mut digest = Blake2s256::new();
    digest.update(bytes);
    hex::encode(digest.finalize())
}

pub fn batch_dir(root: &Path, start_height: u32, end_height: u32) -> PathBuf {
    root.join(format!("batch_{}_to_{}", start_height, end_height))
}

pub fn proof_path(root: &Path, batch: &BatchCheckpoint) -> PathBuf {
    batch_dir(root, batch.start_height, batch.end_height).join(PROOF)
}

fn parse_batch_name(name: &str) -> Option<(u32, u32)> {
    let remainder = name.strip_prefix("batch_")?;
    let (start, end) = remainder.split_once("_to_")?;
    let start: u32 = start.parse().ok()?;
    let end: u32 = end.parse().ok()?;
    (format!("batch_{}_to_{}", start, end) == name && end > start)
        .then_some((start, end))
}

/// Inspect only sealed batches. Require an unbroken digest-linked history.
/// Unsealed proof files are ignored after a crash.
pub fn recover(root: &Path, identity: &CheckpointIdentity) -> Result<Vec<BatchCheckpoint>> {
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut found = Vec::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with("batch_") {
            continue;
        }
        let manifest_path = entry.path().join(MANIFEST);
        if !manifest_path.exists() {
            continue;
        }
        let (start, end) = parse_batch_name(&name)
            .ok_or_else(|| anyhow!("invalid sealed batch directory {}", name))?;
        if fs::metadata(&manifest_path)?.len() > 65536 {
            bail!("oversized checkpoint manifest: {}", manifest_path.display());
        }
        let batch: BatchCheckpoint = serde_json::from_slice(&fs::read(&manifest_path)?)
            .with_context(|| format!("parsing {}", manifest_path.display()))?;
        if batch.version != VERSION
            || batch.start_height != start
            || batch.end_height != end
            || batch.identity != *identity
        {
            bail!("checkpoint identity/range/version mismatch: {}", name);
        }
        let actual = hash_file(&entry.path().join(PROOF))?;
        if actual != batch.proof_hash {
            bail!("checkpoint proof digest mismatch: {}", name);
        }
        found.push(batch);
    }
    found.sort_by_key(|batch| (batch.start_height, batch.end_height));
    let mut expected_height = 0;
    let mut previous_hash: Option<String> = None;
    for batch in &found {
        if batch.start_height != expected_height {
            bail!(
                "checkpoint chain gap or overlap: expected {}, found {}",
                expected_height,
                batch.start_height
            );
        }
        if batch.parent_proof_hash != previous_hash {
            bail!("checkpoint parent proof digest mismatch at {}", expected_height);
        }
        expected_height = batch.end_height;
        previous_hash = Some(batch.proof_hash.clone());
    }
    Ok(found)
}

/// Call only after independent STARK verification and public-state matching.
pub fn seal(
    root: &Path,
    start_height: u32,
    end_height: u32,
    identity: &CheckpointIdentity,
    parent_proof_hash: Option<String>,
    chain_state_hash: String,
) -> Result<BatchCheckpoint> {
    if end_height <= start_height {
        bail!("checkpoint end height must exceed start height");
    }
    let dir = batch_dir(root, start_height, end_height);
    let proof_hash = hash_file(&dir.join(PROOF))?;
    let checkpoint = BatchCheckpoint {
        version: VERSION,
        start_height,
        end_height,
        identity: identity.clone(),
        parent_proof_hash,
        proof_hash,
        chain_state_hash,
    };
    let final_path = dir.join(MANIFEST);
    if final_path.exists() {
        bail!("checkpoint already sealed: {}", final_path.display());
    }
    let tmp_path = dir.join("checkpoint.json.tmp");
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&tmp_path)?;
    file.write_all(&serde_json::to_vec_pretty(&checkpoint)?)?;
    file.sync_all()?;
    fs::rename(&tmp_path, &final_path)?;
    if let Ok(dir_handle) = File::open(&dir) {
        let _ = dir_handle.sync_all();
    }
    Ok(checkpoint)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> CheckpointIdentity {
        CheckpointIdentity {
            genesis_hash: "genesis".into(),
            executable_hash: "executable".into(),
            prover_params_hash: None,
            verifier_config_hash: "verifier".into(),
        }
    }

    fn fake_batch(
        root: &Path,
        start: u32,
        end: u32,
        parent: Option<String>,
    ) -> BatchCheckpoint {
        let dir = batch_dir(root, start, end);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(PROOF), format!("proof-{}-{}", start, end)).unwrap();
        // Synthetic bytes test persistence only, not cryptographic verification.
        seal(root, start, end, &identity(), parent, format!("state-{}", end)).unwrap()
    }

    #[test]
    fn contiguous_batches_are_recovered() {
        let temp = tempfile::tempdir().unwrap();
        let first = fake_batch(temp.path(), 0, 2, None);
        let second = fake_batch(temp.path(), 2, 3, Some(first.proof_hash.clone()));
        let recovered = recover(temp.path(), &identity()).unwrap();
        assert_eq!(recovered.len(), 2);
        assert_eq!(recovered.last().unwrap().proof_hash, second.proof_hash);
    }

    #[test]
    fn incomplete_batch_is_not_a_checkpoint() {
        let temp = tempfile::tempdir().unwrap();
        let dir = batch_dir(temp.path(), 0, 1);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(PROOF), b"partial").unwrap();
        assert!(recover(temp.path(), &identity()).unwrap().is_empty());
    }

    #[test]
    fn tampered_proof_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let batch = fake_batch(temp.path(), 0, 1, None);
        fs::write(proof_path(temp.path(), &batch), b"modified").unwrap();
        assert!(recover(temp.path(), &identity()).is_err());
    }

    #[test]
    fn wrong_parent_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        fake_batch(temp.path(), 0, 1, None);
        fake_batch(temp.path(), 1, 2, Some("wrong parent".into()));
        assert!(recover(temp.path(), &identity()).is_err());
    }

    #[test]
    fn gap_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        fake_batch(temp.path(), 0, 1, None);
        fake_batch(temp.path(), 3, 4, Some("other".into()));
        assert!(recover(temp.path(), &identity()).is_err());
    }

    #[test]
    fn changing_verifier_or_executable_invalidates_resume() {
        let temp = tempfile::tempdir().unwrap();
        fake_batch(temp.path(), 0, 1, None);
        let mut changed = identity();
        changed.verifier_config_hash = "different verifier".into();
        assert!(recover(temp.path(), &changed).is_err());
        changed = identity();
        changed.executable_hash = "different executable".into();
        assert!(recover(temp.path(), &changed).is_err());
    }

    #[test]
    fn malformed_batch_names_fail_closed() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("batch_00_to_2");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(MANIFEST), b"{}").unwrap();
        assert!(recover(temp.path(), &identity()).is_err());
        assert_eq!(parse_batch_name("batch_0_to_2"), Some((0, 2)));
        assert_eq!(parse_batch_name("batch_2_to_2"), None);
    }
}
