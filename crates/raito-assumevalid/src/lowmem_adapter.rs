//! Experimental low-memory Cairo/STWO adapter for the pinned dependency.
//! It streams relocated memory into MemoryBuilder and relocates trace states
//! on demand. Cairo VM execution and STWO proving remain in-memory.
//! Keep opt-in pending end-to-end parity with the reference adapter.
use anyhow::{bail, Result};
use serde_json::Value;
use cairo_vm::types::relocatable::MaybeRelocatable;
use cairo_vm::vm::runners::cairo_runner::CairoRunner;
use cairo_vm::vm::trace::trace_entry::{RelocatedTraceEntry, TraceEntry};
use stwo_cairo_adapter::builtins::BuiltinSegments;
use stwo_cairo_adapter::memory::{MemoryBuilder, MemoryConfig, MemoryEntry};
use stwo_cairo_adapter::opcodes::StateTransitions;
use stwo_cairo_adapter::relocator::Relocator;
use stwo_cairo_adapter::{ProverInput, PublicSegmentContext};
use tracing::info;

/// Decode each relocated memory cell lazily instead of allocating a second
/// full-size relocated-memory vector. Limb encoding matches the pinned adapter.
fn memory_entries<'a>(
    segments: &'a [Vec<Option<MaybeRelocatable>>],
    relocator: &'a Relocator,
) -> impl Iterator<Item = MemoryEntry> + 'a {
    segments
        .iter()
        .enumerate()
        .flat_map(move |(segment_index, segment)| {
            segment.iter().enumerate().map(move |(offset, cell)| {
                let address = relocator.calc_relocated_addr(segment_index, offset) as u64;
                let value = match cell {
                    None => [0; 8],
                    Some(MaybeRelocatable::RelocatableValue(target)) => {
                        let mut words = [0; 8];
                        words[0] =
                            relocator.calc_relocated_addr(target.segment_index as usize, target.offset);
                        words
                    }
                    Some(MaybeRelocatable::Int(value)) => {
                        let bytes = value.to_bytes_le();
                        let mut words = [0; 8];
                        for (index, word) in words.iter_mut().enumerate() {
                            *word = u32::from_ne_bytes(
                                bytes[index * 4..(index + 1) * 4].try_into().unwrap(),
                            );
                        }
                        words
                    }
                };
                MemoryEntry { address, value }
            })
        })
}

fn relocate_trace_entry(relocator: &Relocator, entry: &TraceEntry) -> RelocatedTraceEntry {
    RelocatedTraceEntry {
        pc: relocator.relocation_table[entry.pc.segment_index as usize] as usize + entry.pc.offset,
        ap: relocator.relocation_table[1] as usize + entry.ap,
        fp: relocator.relocation_table[1] as usize + entry.fp,
    }
}

/// Low-allocation replacement for the pinned STWO adapter with identical
/// ProverInput fields. The sequential opcode decoder can cost additional CPU.
pub fn adapt_low_memory(runner: &CairoRunner) -> Result<ProverInput> {
    let relocatable_trace = runner.get_relocatable_trace()?;
    info!("Low-memory adapter: {} Cairo steps", relocatable_trace.len());
    let mut relocatable_memory = runner.get_relocatable_memory();
    let builtin_segments = runner.get_builtin_segments();
    BuiltinSegments::pad_relocatble_builtin_segments(&mut relocatable_memory, &builtin_segments);

    let relocator = Relocator::new(&relocatable_memory);
    let public_memory_addresses =
        relocator.relocate_public_addresses(&runner.vm.segments.public_memory_offsets);
    let builtin_segments = relocator.relocate_builtin_segments(&builtin_segments);

    let memory = MemoryBuilder::from_iter(
        MemoryConfig::default(),
        memory_entries(&relocatable_memory, &relocator),
    );
    drop(relocatable_memory);

    let state_transitions = StateTransitions::from_iter(
        relocatable_trace
            .iter()
            .map(|entry| relocate_trace_entry(&relocator, entry)),
        &memory,
    );
    info!(
        "Low-memory opcode counts: {:?}",
        state_transitions.casm_states_by_opcode.counts()
    );
    let (memory, instruction_cache) = memory.build();

    Ok(ProverInput {
        state_transitions,
        memory,
        pc_count: instruction_cache.len(),
        public_memory_addresses,
        builtin_segments,
        public_segment_context: PublicSegmentContext::bootloader_context(),
    })
}

/// Diagnostic for tiny Cairo inputs. It compares the full adapted prover
/// input while treating instruction sets as multisets; Rayon may reorder
/// same-opcode rows without changing their meaning. This is intentionally
/// memory-intensive and should not run during bounded-RAM proof generation.
pub fn verify_adapter_parity(executable: &std::path::Path, arguments: &std::path::Path) -> Result<()> {
    fn canonicalize(mut value: Value) -> Value {
        if let Some(opcodes) = value
            .get_mut("state_transitions")
            .and_then(|state| state.get_mut("casm_states_by_opcode"))
            .and_then(Value::as_object_mut)
        {
            for entries in opcodes.values_mut() {
                if let Some(rows) = entries.as_array_mut() {
                    rows.sort_by_cached_key(|row| row.to_string());
                }
            }
        }
        value
    }

    let reference = crate::prove::run_and_adapt_with_library(executable, arguments, false)?;
    let reference = canonicalize(serde_json::to_value(reference)?);
    let streamed = crate::prove::run_and_adapt_with_library(executable, arguments, true)?;
    let streamed = canonicalize(serde_json::to_value(streamed)?);
    if reference != streamed {
        bail!("low-memory STWO adapter differs from the pinned reference adapter");
    }
    info!("Full adapted ProverInput parity check passed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairo_vm::types::relocatable::Relocatable;

    #[test]
    fn streamed_memory_matches_pinned_relocator() {
        let segments = vec![
            vec![
                Some(MaybeRelocatable::Int(1u32.into())),
                Some(MaybeRelocatable::Int(0x1234_5678u32.into())),
                Some(MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: 1,
                    offset: 0,
                })),
                None,
            ],
            vec![Some(MaybeRelocatable::Int(0u32.into()))],
        ];
        let relocator = Relocator::new(&segments);
        let legacy = relocator.relocate_memory(&segments);
        let streamed = memory_entries(&segments, &relocator).collect::<Vec<_>>();
        assert_eq!(streamed, legacy);
    }

    #[test]
    fn streamed_trace_matches_pinned_relocator() {
        let segments = vec![vec![None, None, None], vec![None, None]];
        let relocator = Relocator::new(&segments);
        let trace = vec![
            TraceEntry {
                pc: Relocatable {
                    segment_index: 0,
                    offset: 1,
                },
                ap: 1,
                fp: 0,
            },
            TraceEntry {
                pc: Relocatable {
                    segment_index: 0,
                    offset: 2,
                },
                ap: 2,
                fp: 1,
            },
        ];
        let expected = relocator.relocate_trace(&trace);
        let streamed = trace
            .iter()
            .map(|entry| relocate_trace_entry(&relocator, entry))
            .collect::<Vec<_>>();
        assert_eq!(streamed, expected);
    }
}
