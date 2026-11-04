//! Proving module for raito-assumevalid
//!
//! This module provides functionality to run Cairo programs and generate STARK proofs
//! using the stwo-cairo prover library directly.

use crate::checkpoint;
use crate::gcs::{download_recent_proof_via_reqwest, upload_recent_proof, RecentProof};
use crate::generate_args::{generate_and_save_args, AssumeValidParams, ProveClient, ProveConfig};
use crate::lowmem_adapter;
use crate::staged;
use crate::BOOTLOADER_STR;
use anyhow::{anyhow, Result};
use cairo_air::utils::{deserialize_proof_from_file, serialize_proof_to_file, ProofFormat};
use cairo_program_runner_lib::cairo_run_program;
use cairo_program_runner_lib::utils::get_cairo_run_config;
use cairo_vm::types::layout_name::LayoutName;
use cairo_vm::types::program::Program;
use memory_stats::memory_stats;
use raito_spv_verify::{verify_chain_state, VerifierConfig};
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;
use stwo::core::vcs::blake2_merkle::Blake2sMerkleHasher;
use stwo_cairo_adapter::{adapter::adapt, ProverInput};
use stwo_cairo_prover::prover::create_and_serialize_proof;
use tracing::{debug, info, warn};

/// Get current memory usage in MB
fn get_memory_mb() -> f64 {
    memory_stats()
        .map(|usage| usage.physical_mem as f64 / (1024.0 * 1024.0))
        .unwrap_or(0.0)
}

/// Linux process high-water RSS, including short-lived proving allocations.
pub(crate) fn get_peak_memory_mb() -> Option<f64> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|line| line.starts_with("VmHWM:"))?;
    let kib = line.split_whitespace().nth(1)?.parse::<f64>().ok()?;
    Some(kib / 1024.0)
}

/// Execute the Cairo VM and adapt its trace into an owned STWO prover input.
/// The VM runner is released before this function returns.
pub fn run_and_adapt_with_library(
    executable: &Path,
    arguments_file: &Path,
    lowmem_adapter: bool,
) -> Result<ProverInput> {
    // Resolve paths to absolute with helpful error messages
    let executable_abs = executable.canonicalize().map_err(|e| {
        anyhow!(
            "Executable file not found at '{}': {}",
            executable.display(),
            e
        )
    })?;
    let args_file = arguments_file.canonicalize().map_err(|e| {
        anyhow!(
            "Arguments file not found at '{}': {}",
            arguments_file.display(),
            e
        )
    })?;

    // Generate program input JSON for the bootloader
    let program_input = json!({
        "single_page": true,
        "tasks": [
            {
                "type": "Cairo1Executable",
                "path": executable_abs.to_string_lossy(),
                "program_hash_function": "blake",
                "user_args_file": args_file.to_string_lossy(),
            }
        ],
    });
    let program_input_str = serde_json::to_string(&program_input)?;

    // Load bootloader program from embedded resource
    let bootloader_program = Program::from_bytes(BOOTLOADER_STR.as_bytes(), Some("main"))
        .map_err(|e| anyhow!("Failed to load bootloader program: {}", e))?;

    // Configure Cairo VM for proof mode
    let cairo_run_config = get_cairo_run_config(
        &None,                      // no dynamic layout params
        LayoutName::all_cairo_stwo, // layout
        true,                       // proof_mode
        true,                       // disable_trace_padding (redundant in stwo proof mode)
        true,                       // allow_missing_builtins (bootloader simulates them)
        false,                      // relocate_mem (adapter does relocation)
    )?;

    // Run the bootloader with the program input
    debug!("Running Cairo VM...");
    let vm_start = Instant::now();
    let runner = cairo_run_program(
        &bootloader_program,
        Some(program_input_str),
        cairo_run_config,
    )
    .map_err(|e| anyhow!("Cairo VM execution failed: {}", e))?;
    let vm_elapsed = vm_start.elapsed();
    let vm_mem = get_memory_mb();
    info!(
        "Cairo VM: {:.2}s, memory: {:.1} MB",
        vm_elapsed.as_secs_f64(),
        vm_mem
    );

    // Adapt the VM output for the prover
    debug!("Adapting VM output for prover...");
    let adapt_start = Instant::now();
    let prover_input = if lowmem_adapter {
        lowmem_adapter::adapt_low_memory(&runner)
            .map_err(|e| anyhow!("Low-memory adaptation failed: {}", e))?
    } else {
        adapt(&runner).map_err(|e| anyhow!("Failed to adapt VM output: {}", e))?
    };
    // adapt returns an owned ProverInput. Free the VM trace and memory before
    // STWO allocates its witness and commitment buffers.
    drop(runner);
    let adapt_elapsed = adapt_start.elapsed();
    let adapt_mem = get_memory_mb();
    info!(
        "Adapt: {:.2}s, memory: {:.1} MB",
        adapt_elapsed.as_secs_f64(),
        adapt_mem
    );

    Ok(prover_input)
}

/// Runs the Cairo program through the bootloader and generates a STARK proof.
///
/// This function:
/// 1. Loads the bootloader program from embedded resources
/// 2. Generates the program input JSON for the bootloader
/// 3. Runs the Cairo VM
/// 4. Adapts the VM output for the prover
/// 5. Generates and serializes the STARK proof
pub fn run_and_prove_with_library(
    executable: &Path,
    arguments_file: &Path,
    output_dir: &Path,
    prover_params: Option<&Path>,
    verify: bool,
) -> Result<PathBuf> {
    run_and_prove_with_adapter(
        executable,
        arguments_file,
        output_dir,
        prover_params,
        verify,
        false,
    )
}

/// Run a complete proof with a selectable adapter. The legacy wrapper above
/// retains the existing library signature for downstream callers.
pub fn run_and_prove_with_adapter(
    executable: &Path,
    arguments_file: &Path,
    output_dir: &Path,
    prover_params: Option<&Path>,
    verify: bool,
    lowmem_adapter: bool,
) -> Result<PathBuf> {
    let start_time = Instant::now();
    let start_mem = get_memory_mb();

    // Create output directory
    fs::create_dir_all(output_dir)?;

    // The direct route uses the same adapter as the disk-staged worker.
    let prover_input = run_and_adapt_with_library(executable, arguments_file, lowmem_adapter)?;

    // Generate the proof
    let proof_file = output_dir.join("proof.json");
    debug!("Generating STARK proof...");
    let prove_start = Instant::now();
    create_and_serialize_proof(
        prover_input,
        verify,
        proof_file.clone(),
        ProofFormat::CairoSerde,
        prover_params.map(|p| p.to_path_buf()),
    )
    .map_err(|e| anyhow!("Proof generation failed: {}", e))?;
    let prove_elapsed = prove_start.elapsed();
    let prove_mem = get_memory_mb();
    info!(
        "Prove: {:.2}s, memory: {:.1} MB",
        prove_elapsed.as_secs_f64(),
        prove_mem
    );

    let total_elapsed = start_time.elapsed();
    let peak_mem = get_peak_memory_mb().unwrap_or(prove_mem);
    info!(
        "Total: {:.2}s, process high-water RSS: {:.1} MB (started at {:.1} MB)",
        total_elapsed.as_secs_f64(),
        peak_mem,
        start_mem
    );

    Ok(proof_file)
}

/// Parameters for proving bounded-size batches iteratively.
#[derive(Debug, Clone)]
pub struct ProveParams {
    pub executable: PathBuf,
    pub load_from_gcs: bool,
    pub save_to_gcs: bool,
    pub gcs_bucket: String,
    pub bridge_url: String,
    /// Additional blocks beyond the last verified checkpoint.
    pub total_blocks: u32,
    /// Optional absolute height, allowing idempotent resume after a crash.
    pub target_height: Option<u32>,
    /// Maximum number of headers in each recursive STARK proof.
    pub step_size: u32,
    pub output_dir: PathBuf,
    pub prover_params_file: Option<PathBuf>,
    pub verifier_config_file: Option<PathBuf>,
    pub disk_staged: bool,
    pub lowmem_adapter: bool,
    pub worker_threads: Option<usize>,
    pub keep_temp_files: bool,
}

/// Extend a verified recursive STARK checkpoint using independently verified batches.
pub async fn prove(params: ProveParams) -> Result<()> {
    if params.step_size == 0 {
        return Err(anyhow!("step_size must be at least 1"));
    }
    if params.worker_threads == Some(0) {
        return Err(anyhow!("worker_threads must be positive"));
    }
    if !params.disk_staged && params.worker_threads.is_some() {
        return Err(anyhow!("worker_threads requires --disk-staged"));
    }
    fs::create_dir_all(&params.output_dir)?;
    let verifier_config: VerifierConfig = match params.verifier_config_file.as_deref() {
        Some(path) => serde_json::from_slice(&fs::read(path)?)?,
        None => VerifierConfig::default(),
    };
    let client = ProveClient::new(ProveConfig {
        bridge_node_url: params.bridge_url.clone(),
    });
    let genesis = client.get_chain_state(0).await?;
    if genesis.block_height != 0 {
        return Err(anyhow!("bridge genesis response has invalid height"));
    }
    let identity = checkpoint::CheckpointIdentity {
        genesis_hash: genesis.best_block_hash.to_string(),
        executable_hash: checkpoint::hash_file(&params.executable)?,
        prover_params_hash: params
            .prover_params_file
            .as_deref()
            .map(checkpoint::hash_file)
            .transpose()?,
        verifier_config_hash: checkpoint::hash_bytes(&serde_json::to_vec(&verifier_config)?),
    };
    let mut completed = checkpoint::recover(&params.output_dir, &identity)?;

    // A remotely downloaded starting proof must pass the same verification gate.
    if params.load_from_gcs && completed.is_empty() {
        let recent = download_recent_proof_via_reqwest(&params.gcs_bucket).await?;
        let height = recent.chainstate.block_height;
        if height == 0 {
            return Err(anyhow!("remote proof does not advance the chain"));
        }
        let expected = client.get_chain_state(height).await?;
        if expected.block_height != height
            || expected.blake2s_digest()? != recent.chainstate.blake2s_digest()?
        {
            return Err(anyhow!("GCS proof chain state disagrees with bridge"));
        }
        let dir = checkpoint::batch_dir(&params.output_dir, 0, height);
        fs::create_dir_all(&dir)?;
        let path = dir.join("proof.json");
        serialize_proof_to_file::<Blake2sMerkleHasher>(
            &recent.proof,
            &path,
            ProofFormat::CairoSerde,
        )?;
        let proof = deserialize_proof_from_file(&path, ProofFormat::CairoSerde)?;
        verify_chain_state(&expected, proof, &verifier_config)?;
        completed.push(checkpoint::seal(
            &params.output_dir,
            0,
            height,
            &identity,
            None,
            expected.blake2s_digest()?,
        )?);
    }

    // The final STARK proves the recursive history, while hashes detect local
    // checkpoint corruption and prevent a different proof from being spliced in.
    if let Some(tip) = completed.last() {
        let state = client.get_chain_state(tip.end_height).await?;
        if state.block_height != tip.end_height
            || state.blake2s_digest()? != tip.chain_state_hash
        {
            return Err(anyhow!("recovered checkpoint chain state mismatch"));
        }
        let proof = deserialize_proof_from_file(
            &checkpoint::proof_path(&params.output_dir, tip),
            ProofFormat::CairoSerde,
        )?;
        verify_chain_state(&state, proof, &verifier_config)?;
        info!("Verified recursive checkpoint through height {}", tip.end_height);
    }

    let start_height = completed.last().map_or(0, |tip| tip.end_height);
    let end_height = match params.target_height {
        Some(target) if target < start_height => {
            return Err(anyhow!("target height is behind the verified checkpoint"));
        }
        Some(target) => target,
        None => start_height
            .checked_add(params.total_blocks)
            .ok_or_else(|| anyhow!("block range overflow"))?,
    };
    let mut current_height = start_height;
    let mut last_proof_path: Option<PathBuf> = None;
    let mut last_height = start_height;
    info!(
        "Resumable STWO proving: start={}, end={}, max_batch_headers={}",
        current_height, end_height, params.step_size
    );

    while current_height < end_height {
        let current_step = params.step_size.min(end_height - current_height);
        let next_height = current_height
            .checked_add(current_step)
            .ok_or_else(|| anyhow!("batch height overflow"))?;
        let dir = checkpoint::batch_dir(&params.output_dir, current_height, next_height);
        fs::create_dir_all(&dir)?;
        let parent = completed.last().map(|batch| batch.proof_hash.clone());
        let previous_proof = completed
            .last()
            .map(|batch| checkpoint::proof_path(&params.output_dir, batch));
        if current_height != 0 && previous_proof.is_none() {
            return Err(anyhow!("missing authenticated recursive predecessor"));
        }

        let args_file = dir.join("arguments.json");
        let args_started = Instant::now();
        generate_and_save_args(
            &client,
            AssumeValidParams {
                start_height: current_height,
                block_count: current_step,
                chain_state_proof_path: previous_proof,
            },
            &args_file.to_string_lossy(),
        )
        .await?;
        debug!(
            "Generated arguments for [{}..{}] in {:.2}s",
            current_height,
            next_height,
            args_started.elapsed().as_secs_f64()
        );

        let proof_path = if params.disk_staged {
            staged::run_in_worker_process(
                &params.executable,
                &args_file,
                &dir,
                params.prover_params_file.as_deref(),
                params.keep_temp_files,
                params.worker_threads,
                params.lowmem_adapter,
            )?
        } else {
            run_and_prove_with_adapter(
                &params.executable,
                &args_file,
                &dir,
                params.prover_params_file.as_deref(),
                true,
                params.lowmem_adapter,
            )?
        };
        let state = client.get_chain_state(next_height).await?;
        if state.block_height != next_height {
            return Err(anyhow!("bridge returned the wrong post-batch height"));
        }
        let proof = deserialize_proof_from_file(&proof_path, ProofFormat::CairoSerde)?;
        verify_chain_state(&state, proof, &verifier_config)?;
        completed.push(checkpoint::seal(
            &params.output_dir,
            current_height,
            next_height,
            &identity,
            parent,
            state.blake2s_digest()?,
        )?);
        info!("Sealed verified checkpoint at height {}", next_height);
        current_height = next_height;
        last_height = next_height;
        last_proof_path = Some(proof_path);
        if !params.keep_temp_files {
            if let Err(err) = fs::remove_file(&args_file) {
                warn!("Could not remove args file: {}", err);
            }
        }
    }

    if params.save_to_gcs {
        if let Some(path) = last_proof_path {
            let chainstate = client.get_chain_state(last_height).await?;
            let proof = deserialize_proof_from_file(&path, ProofFormat::CairoSerde)?;
            let recent = RecentProof {
                timestamp: chrono::Utc::now().to_string(),
                chainstate,
                proof,
            };
            upload_recent_proof(&recent, &params.gcs_bucket).await?;
            info!("Uploaded verified checkpoint at height {} to GCS", last_height);
        }
    }
    Ok(())
}
