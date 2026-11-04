//! Disk-staged Cairo/STWO proving with separate processes for VM adaptation and
//! proof generation. This spills the owned ProverInput to disk to release all
//! Cairo VM and adapter allocations before launching the STWO worker.
//! The STWO proof generation stage remains in-memory.
use crate::prove::{get_peak_memory_mb, run_and_adapt_with_library};
use anyhow::{anyhow, bail, Context, Result};
use bincode::Options;
use cairo_air::utils::ProofFormat;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;
use stwo_cairo_adapter::ProverInput;
use stwo_cairo_prover::prover::create_and_serialize_proof;
use tracing::info;

const MAGIC: &[u8] = b"RAITO-STWO-INPUT-V1\0";
const STAGED_NAME: &str = "prover_input.bin";
const MAX_STAGED_INPUT_BYTES: u64 = 128 * 1024 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
struct StageStats {
    stage: String,
    elapsed_seconds: f64,
    peak_rss_mb: Option<f64>,
    artifact_bytes: u64,
}

fn record_stage(dir: &Path, name: &str, started: Instant, bytes: u64) {
    let stats = StageStats {
        stage: name.to_owned(),
        elapsed_seconds: started.elapsed().as_secs_f64(),
        peak_rss_mb: get_peak_memory_mb(),
        artifact_bytes: bytes,
    };
    info!(
        "Worker {}: {:.2}s, high-water RSS: {:?} MB, artifact: {} bytes",
        stats.stage, stats.elapsed_seconds, stats.peak_rss_mb, bytes
    );
    // Operational telemetry is optional and never a proof or resume authority.
    let path = dir.join(format!("{}.stats.json", name));
    if let Ok(json) = serde_json::to_vec_pretty(&stats) {
        if let Err(error) = fs::write(&path, json) {
            tracing::warn!("Could not write {}: {}", path.display(), error);
        }
    }
}

/// Persist an owned ProverInput with a fixed format marker. The encoder is
/// streaming, with no additional full-size serialized Vec allocation.
fn spill<T: Serialize>(input: &T, output: &Path) -> Result<()> {
    let dir = output
        .parent()
        .ok_or_else(|| anyhow!("staged output requires a parent directory"))?;
    fs::create_dir_all(dir)?;
    let temporary = output.with_extension("bin.tmp");
    if temporary.exists() {
        fs::remove_file(&temporary)
            .with_context(|| format!("removing incomplete {}", temporary.display()))?;
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(&temporary)?;
    let mut writer = BufWriter::with_capacity(1024 * 1024, file);
    writer.write_all(MAGIC)?;
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_STAGED_INPUT_BYTES)
        .serialize_into(&mut writer, input)
        .context("serializing STWO prover input")?;
    writer.flush()?;
    let file = writer.into_inner().map_err(|error| error.into_error())?;
    file.sync_all()?;
    drop(file);
    if output.exists() {
        fs::remove_file(output)?;
    }
    fs::rename(&temporary, output)?;
    if let Ok(parent) = File::open(dir) {
        let _ = parent.sync_all();
    }
    Ok(())
}

/// Streaming decoding avoids a duplicate full-size byte buffer, while the
/// decoded STWO ProverInput still necessarily resides in RAM.
fn load<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let length = fs::metadata(path)?.len();
    if length > MAX_STAGED_INPUT_BYTES {
        bail!("staged input exceeds 128 GiB safety limit");
    }
    let mut reader = BufReader::with_capacity(1024 * 1024, File::open(path)?);
    let mut marker = [0u8; MAGIC.len()];
    reader.read_exact(&mut marker)?;
    if marker != MAGIC {
        bail!("invalid or unsupported STWO staged-input version");
    }
    let input = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(length)
        .deserialize_from(&mut reader)
        .with_context(|| format!("decoding staged input {}", path.display()))?;
    let mut suffix = [0u8; 1];
    if reader.read(&mut suffix)? != 0 {
        bail!("staged input has trailing bytes");
    }
    Ok(input)
}

/// Hidden CLI worker. It runs Cairo and writes a complete ProverInput, with a
/// crash-atomic rename after successful serialization.
pub fn run_adapter_worker(
    executable: &Path,
    arguments_file: &Path,
    prover_input_file: &Path,
    lowmem_adapter: bool,
) -> Result<()> {
    let started = Instant::now();
    let input = run_and_adapt_with_library(executable, arguments_file, lowmem_adapter)?;
    spill(&input, prover_input_file)?;
    drop(input);
    let dir = prover_input_file
        .parent()
        .ok_or_else(|| anyhow!("staged input requires a parent directory"))?;
    record_stage(dir, "vm-adapt", started, fs::metadata(prover_input_file)?.len());
    Ok(())
}

/// Hidden CLI worker. The previous worker process has already exited before
/// this allocates STWO twiddles and witness/commitment tables.
pub fn run_prover_worker(
    prover_input_file: &Path,
    output_dir: &Path,
    prover_params: Option<&Path>,
) -> Result<()> {
    let started = Instant::now();
    fs::create_dir_all(output_dir)?;
    let input: ProverInput = load(prover_input_file)?;
    let proof_file = output_dir.join("proof.json");
    create_and_serialize_proof(
        input,
        true,
        proof_file.clone(),
        ProofFormat::CairoSerde,
        prover_params.map(Path::to_path_buf),
    )
    .map_err(|error| anyhow!("disk-staged STWO proving failed: {}", error))?;
    record_stage(
        output_dir,
        "stwo-prove",
        started,
        fs::metadata(&proof_file)?.len(),
    );
    Ok(())
}

/// Host-side orchestration. A failed worker leaves its batch unsealed; the
/// outer checkpoint controller independently verifies every resulting proof.
pub fn run_in_worker_process(
    executable: &Path,
    arguments_file: &Path,
    output_dir: &Path,
    prover_params: Option<&Path>,
    keep_temp_files: bool,
    worker_threads: Option<usize>,
    lowmem_adapter: bool,
) -> Result<PathBuf> {
    if worker_threads == Some(0) {
        bail!("worker_threads must be positive");
    }
    fs::create_dir_all(output_dir)?;
    let binary = std::env::current_exe().context("locating Raito worker executable")?;
    let input_path = output_dir.join(STAGED_NAME);
    // An unsealed prior run has no resume authority, so its staged input is
    // discarded and regenerated against current recursive arguments.
    if input_path.exists() {
        fs::remove_file(&input_path)?;
    }

    let mut adapter = Command::new(&binary);
    adapter
        .arg("internal-adapt")
        .arg("--executable")
        .arg(executable)
        .arg("--arguments-file")
        .arg(arguments_file)
        .arg("--prover-input-file")
        .arg(&input_path);
    if lowmem_adapter {
        adapter.arg("--lowmem-adapter");
    }
    if let Some(threads) = worker_threads {
        adapter.env("RAYON_NUM_THREADS", threads.to_string());
    }
    let status = adapter.status().context("launching Cairo adapter worker")?;
    if !status.success() {
        bail!("Cairo adapter worker failed with status: {}", status);
    }

    let mut prover = Command::new(binary);
    prover
        .arg("internal-prove")
        .arg("--prover-input-file")
        .arg(&input_path)
        .arg("--output-dir")
        .arg(output_dir);
    if let Some(params) = prover_params {
        prover.arg("--prover-params-file").arg(params);
    }
    if let Some(threads) = worker_threads {
        prover.env("RAYON_NUM_THREADS", threads.to_string());
    }
    let status = prover.status().context("launching STWO prover worker")?;
    if !status.success() {
        bail!("STWO prover worker failed with status: {}", status);
    }
    if !keep_temp_files {
        fs::remove_file(&input_path)?;
    }
    Ok(output_dir.join("proof.json"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct Sample {
        height: u32,
        samples: Vec<u64>,
    }

    #[test]
    fn streaming_roundtrip_and_format_marker() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join(STAGED_NAME);
        let sample = Sample {
            height: 37,
            samples: (0..100_000).collect(),
        };
        spill(&sample, &path).unwrap();
        let back: Sample = load(&path).unwrap();
        assert_eq!(sample, back);
        assert!(fs::metadata(path).unwrap().len() > MAGIC.len() as u64);
    }

    #[test]
    fn pinned_stwo_prover_input_is_roundtrippable() {
        use stwo_cairo_adapter::builtins::BuiltinSegments;
        use stwo_cairo_adapter::memory::{Memory, MemoryConfig};
        use stwo_cairo_adapter::opcodes::StateTransitions;
        use stwo_cairo_adapter::PublicSegmentContext;

        let root = tempfile::tempdir().unwrap();
        let path = root.path().join(STAGED_NAME);
        let input = ProverInput {
            state_transitions: StateTransitions::default(),
            memory: Memory {
                config: MemoryConfig::default(),
                address_to_id: Vec::new(),
                f252_values: Vec::new(),
                small_values: Vec::new(),
            },
            pc_count: 0,
            public_memory_addresses: Vec::new(),
            builtin_segments: BuiltinSegments::default(),
            public_segment_context: PublicSegmentContext::bootloader_context(),
        };
        spill(&input, &path).unwrap();
        let decoded: ProverInput = load(&path).unwrap();
        assert_eq!(
            serde_json::to_value(&input).unwrap(),
            serde_json::to_value(&decoded).unwrap()
        );
    }

    #[test]
    fn corrupted_header_fails_closed() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join(STAGED_NAME);
        fs::write(&path, b"not a STWO input").unwrap();
        assert!(load::<Sample>(&path).is_err());
    }

    #[test]
    fn truncated_data_fails_closed() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join(STAGED_NAME);
        spill(
            &Sample {
                height: 1,
                samples: vec![7; 64],
            },
            &path,
        )
        .unwrap();
        let mut bytes = fs::read(&path).unwrap();
        bytes.truncate(bytes.len() - 5);
        fs::write(&path, bytes).unwrap();
        assert!(load::<Sample>(&path).is_err());
    }

    #[test]
    fn trailing_data_fails_closed() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join(STAGED_NAME);
        spill(
            &Sample {
                height: 2,
                samples: vec![9, 8, 7],
            },
            &path,
        )
        .unwrap();
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(b"trailing").unwrap();
        assert!(load::<Sample>(&path).is_err());
    }
}
