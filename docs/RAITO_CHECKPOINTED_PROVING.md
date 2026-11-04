# Resumable recursive STARK proving in Raito

Raito's `raito-assumevalid` executable uses Cairo/STWO recursive STARK proofs. It does not use Groth16 for this proving path. The existing `--step-size` sets the maximum number of headers inside a single proof. A new independently verified proof can extend the preceding proof, so a completed batch acts as a cryptographic checkpoint.

## Command

```bash
cargo run -p raito-assumevalid -- prove \
  --step-size 1 --target-height 20 \
  --disk-staged --lowmem-adapter --worker-threads 1 \
  --output-dir .proofs/small-ram
```

After interruption, rerun with the same output directory and `--target-height 20`. The operation becomes a no-op once that height is verified. The alternate `--total-blocks` flag specifies additional headers beyond the most recent verified checkpoint. Change `--step-size` to try a smaller per-batch RAM footprint; completed batches remain usable. If the executable or pinned verifier changes, use a fresh directory.

Use `--verifier-config-file path.json` when the expected bootloader/task program hashes differ from `VerifierConfig::default()`. The JSON must deserialize into `raito_spv_verify::VerifierConfig`.

## What the checkpoint contains

Each verified batch persists a recursive `proof.json` and an atomically sealed `checkpoint.json` with the version, height range, genesis identity, executable and verifier hashes, optional proving-parameter hash, proof digest, parent proof digest, and committed chain-state digest.

Recovery ignores unsealed batches from interrupted runs. Sealed batches must form one contiguous digest-linked chain starting at height zero. Before extending that chain, the host independently checks the final recursive STARK using `raito_spv_verify::verify_chain_state` against the bridge chain-state response and pinned task/program hashes. Recursion authenticates the earlier batches when the circuits correctly check their predecessor proofs.

A manifest, file hash, GCS height claim, or JSON file by itself is never accepted as evidence of proof validity. GCS imports undergo the same cryptographic check before being sealed.

## Disk-staged worker pipeline

With `--disk-staged`, the Cairo VM and adapter run in a dedicated process. The worker streams an owned STWO `ProverInput` to `prover_input.bin` using a pinned bincode-v1 envelope and exits. A fresh process reads that file through a buffered deserializer and generates the STWO proof, so its allocation peak cannot overlap the former VM/adapter process. After the proof passes independent verification, the outer controller seals a checkpoint and deletes the spilled intermediate unless `--keep-temp-files` is set. Interrupted worker artifacts remain unsealed and are regenerated.

Each batch records `vm-adapt.stats.json` and `stwo-prove.stats.json`, with elapsed seconds, artifact bytes, and process high-water RSS on Linux. These files are operational observations and have no role in proof verification. `--worker-threads 1` limits Rayon thread parallelism within both workers, often useful when investigating per-thread scratch memory.

The opt-in `--lowmem-adapter` uses pinned STWO adapter APIs to feed relocated memory entries directly to `MemoryBuilder::from_iter` and opcode states to `StateTransitions::from_iter`. This omits full intermediate relocated-memory and relocated-trace vectors and releases the cloned Cairo memory before opcode decoding. It may use more CPU time than the parallel adapter. The existing adapter remains the default until a genuine full ProverInput parity test and proof verification pass.

## Prover-input parity and RSS benchmark

Build the standalone Rust binary once to exclude compilation memory from the measurement:

```bash
cargo build --release -p raito-assumevalid
```

Use a small, known-valid arguments file for the reference-versus-streaming adapter diagnostic:

```bash
target/release/raito-assumevalid adapter-parity \
  --executable crates/raito-assumevalid/compiled/assumevalid-syscalls.executable.json \
  --arguments-file path/to/small-valid-arguments.json
```

The diagnostic constructs both ProverInput values and compares their fields, permitting reordered opcode rows. It is deliberately memory-intensive and should be run on a small fixture. Only the independent recursive STARK verifier can establish that the resulting proof is accepted. Genuine end-to-end proof acceptance under both modes is mandatory before relying on the streaming adapter.

Measure the direct baseline against the process-separated streaming path with two fresh output directories:

```bash
/usr/bin/time -v target/release/raito-assumevalid prove \
  --target-height 2 --step-size 1 --output-dir .proofs/benchmark-direct
/usr/bin/time -v target/release/raito-assumevalid prove \
  --target-height 2 --step-size 1 --disk-staged --lowmem-adapter \
  --worker-threads 1 --output-dir .proofs/benchmark-lowmem
```

Ensure both commands use the same bridge RPC, pinned executable, verifier config, and prover parameters. The staged batch directories contain JSON phase metrics; the direct prover logs process high-water RSS. Collect peak RSS, proof bytes, total wall time, and whether both resulting recursive proofs pass independent verification. An optional Linux cgroup or container limit provides a hard RAM ceiling; a sampled RSS measurement is observational.

## RAM ceiling

This change provides durable checkpointing between Cairo/STWO proofs, with a configurable maximum number of headers per proof. It also drops the owned Cairo VM runner immediately after adaptation, before STWO witness/commitment allocation. On Linux the prover logs process-high-water RSS from `/proc/self/status` (`VmHWM`). The Cairo VM, adapter, and STWO prover still operate on a complete batch in memory. A one-header proof can exceed a small machine's RAM. Benchmark with an OS/container memory limit for a hard ceiling.

Current memory peaks include the Cairo VM execution trace, MemoryBuilder caches, the owned STWO ProverInput, STWO precomputed twiddles, witness columns, and polynomial commitments. The implementation now removes some intermediate vectors and separates the VM/adapter and STWO proving processes. Further reductions require changing the pinned STWO commitment/prover backend to support chunked or file-backed columns. Benchmark direct, disk-staged, and disk-staged + low-memory adapters with identical inputs to measure peak RSS, disk writes, wall time, and proof acceptance. A Groth16 wrapper, if desired for a separate verifier environment, requires its own circuit and benchmarking.

## Testing and limits

```bash
cargo fmt --check
cargo test -p raito-assumevalid checkpoint
cargo test -p raito-assumevalid staged
cargo test -p raito-assumevalid lowmem_adapter
```

Unit tests cover the checkpoint seal, codec envelope, corruption rejection, and equivalence between the pinned relocation helpers and the streaming mapper for representative cells and trace entries. They do not constitute a full STARK parity or proof-verifier test. Full end-to-end validation requires a genuine Cairo/STWO proof, pinned verifier config, and live bridge chain state. Run one prover per checkpoint directory.

Existing batch directories without sealed manifests are treated as incomplete and will be re-proved. Preserve the original directory separately before migrating older proof archives.