//! ZeroSync-style header-chain segment.
//!
//! Validates a batch of block headers on top of a chain state and the Merkle Mountain
//! Range of block hashes, and outputs commitments to both ends: the Blake2s digests of the
//! chain state and of the MMR before and after the batch. A verifier that links segments
//! end to start, from the genesis state, learns that a valid header chain leads to the
//! final chain state; nothing about the batch has to be trusted.
//!
//! This is Raito's `assumevalid` program without the recursive step: instead of verifying
//! the previous proof in Cairo, it publishes its initial commitments, and the verifier
//! links proofs outside Cairo.

use consensus::types::block::{Block, BlockHash, TransactionData};
use consensus::types::chain_state::{ChainState, ChainStateHashTrait};
use consensus::validation::header::validate_block_header;
use core::box::BoxImpl;
use utils::blake2s_hasher::{Blake2sDigest, Blake2sDigestIntoU256};
use utils::mmr::{MMR, MMRTrait};

#[derive(Drop, Serde)]
struct Args {
    /// Chain state before the batch.
    chain_state: ChainState,
    /// MMR of the block hashes up to and including `chain_state.best_block_hash`.
    block_mmr: MMR,
    /// Headers to apply, each with its Merkle root (`TransactionData::MerkleRoot`).
    blocks: Array<Block>,
}

#[derive(Drop, Serde)]
struct Output {
    initial_chain_state_hash: u256,
    initial_block_mmr_hash: u256,
    final_chain_state_hash: u256,
    final_block_mmr_hash: u256,
    /// Number of headers applied; zero-length batches would let a segment repeat a state.
    n_blocks: u32,
}

/// Mainnet heights from which Bitcoin Core rejects headers below a version
/// (`bad-version`): BIP34 (2), BIP66 (3), BIP65 (4).
const BIP34_HEIGHT: u32 = 227931;
const BIP66_HEIGHT: u32 = 363725;
const BIP65_HEIGHT: u32 = 388381;

#[executable]
fn main(args: Args) -> Output {
    let Args { chain_state, block_mmr, blocks } = args;
    let n_blocks = blocks.len();
    assert(n_blocks > 0, 'Empty batch');

    // The MMR digest hashes zeros in place of the last root when the root count is odd,
    // without reading it, so the commitment covers the MMR only if that root is `None`
    // (which `add` maintains). Require it, and that the MMR holds one leaf per block.
    let roots = block_mmr.roots;
    assert(roots.len() > 0, 'MMR without roots');
    assert(roots[roots.len() - 1].is_none(), 'MMR last root not None');
    assert(leaf_count(roots) == chain_state.block_height.into() + 1, 'MMR size != height + 1');

    let initial_chain_state_hash = chain_state.blake2s_digest().into();
    let initial_block_mmr_hash = block_mmr.blake2s_digest().into();

    let mut current_chain_state = chain_state;
    let mut current_block_mmr = BoxImpl::new(block_mmr);
    for block in blocks {
        let height = current_chain_state.block_height + 1;
        validate_version(block.header.version, height);
        validate_canonical_bits(block.header.bits);
        let merkle_root = match block.data {
            TransactionData::MerkleRoot(root) => root,
            TransactionData::Transactions(_) => panic!("Expected Merkle root"),
        };
        let leaf = block.header.blake2s_digest(current_chain_state.best_block_hash, merkle_root);
        current_block_mmr = BoxImpl::new(current_block_mmr.add(leaf));
        match validate_block_header(current_chain_state, block) {
            Ok(new_chain_state) => { current_chain_state = new_chain_state; },
            Err(err) => panic!("FAIL: error='{}'", err),
        };
    }

    Output {
        initial_chain_state_hash,
        initial_block_mmr_hash,
        final_chain_state_hash: current_chain_state.blake2s_digest().into(),
        final_block_mmr_hash: current_block_mmr.blake2s_digest().into(),
        n_blocks,
    }
}

/// Number of leaves: root `h` stands for `2^h` of them.
fn leaf_count(roots: Span<Option<Blake2sDigest>>) -> u64 {
    let mut count: u64 = 0;
    let mut weight: u64 = 1;
    for root in roots {
        if root.is_some() {
            count += weight;
        }
        weight *= 2;
    }
    count
}

/// Core's `bad-version` rule. `nVersion` is a signed 32-bit integer, so a value with the
/// top bit set is negative and below every minimum.
fn validate_version(version: u32, height: u32) {
    let min: u32 = if height >= BIP65_HEIGHT {
        4
    } else if height >= BIP66_HEIGHT {
        3
    } else if height >= BIP34_HEIGHT {
        2
    } else {
        return;
    };
    assert(version < 0x80000000 && version >= min, 'bad-version');
}

/// Only the canonical compact encoding of a target (`GetCompact`) is accepted, as Core
/// requires `nBits` to equal its computed value exactly; `validate_bits` compares the
/// decoded targets, which several encodings share. Canonical: sign bit clear, and the
/// mantissa's top byte non-zero unless it was shifted out because the next byte has its
/// top bit set.
fn validate_canonical_bits(bits: u32) {
    let mantissa = bits & 0xffffff;
    assert(mantissa & 0x800000 == 0, 'bad-diffbits: negative');
    let top = mantissa / 0x10000;
    let next = (mantissa / 0x100) & 0xff;
    assert(top != 0 || next >= 0x80, 'bad-diffbits: not canonical');
}

#[cfg(test)]
mod tests {
    use consensus::types::block::{BlockHash, Header};
    use utils::hash::Digest;
    use consensus::types::chain_state::{ChainState, ChainStateHashTrait};
    use utils::blake2s_hasher::Blake2sDigestIntoU256;
    use utils::mmr::{MMR, MMRTrait};

    /// Vectors the Rust side (rust-bitcoin `zk/sync`) must reproduce.
    #[test]
    fn genesis_commitments() {
        let state: ChainState = Default::default();
        let state_hash: u256 = state.blake2s_digest().into();
        println!("genesis chain state hash {:x}", state_hash);

        let genesis = Header { version: 1, time: 1231006505, bits: 486604799, nonce: 2083236893 };
        let merkle_root: Digest =
            0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b_u256.into();
        let zero: Digest = 0_u256.into();
        let leaf = genesis.blake2s_digest(zero, merkle_root);
        let mmr: MMR = Default::default();
        let mmr = mmr.add(leaf);
        let mmr_hash: u256 = mmr.blake2s_digest().into();
        let leaf_u256: u256 = leaf.into();
        println!("genesis leaf {:x}", leaf_u256);
        println!("genesis block MMR hash {:x}", mmr_hash);
        assert_eq!(leaf_u256, 0x5fd720d341e64d17d3b8624b17979b0d0dad4fc17d891796a3a51a99d3f41599);
    }
}

#[cfg(test)]
mod rule_tests {
    use super::{validate_canonical_bits, validate_version};

    #[test]
    fn canonical_bits_accepts_mainnet_values() {
        validate_canonical_bits(0x1d00ffff); // genesis: top byte 0, next byte 0xff
        validate_canonical_bits(0x1b0404cb);
        validate_canonical_bits(0x17034219);
    }

    #[test]
    #[should_panic(expected: 'bad-diffbits: not canonical')]
    fn canonical_bits_rejects_shiftable_mantissa() {
        // Same target as 0x1c7fff00 (mantissa shifted down a byte, exponent up).
        validate_canonical_bits(0x1d007fff);
    }

    #[test]
    #[should_panic(expected: 'bad-version')]
    fn version_rule_after_bip65() {
        validate_version(3, 388381);
    }

    #[test]
    #[should_panic(expected: 'bad-version')]
    fn negative_version_is_low() {
        validate_version(0x80000004, 400000);
    }

    #[test]
    fn version_rule_before_bip34() {
        validate_version(1, 227930);
        validate_version(0x20000000, 700000);
    }
}
