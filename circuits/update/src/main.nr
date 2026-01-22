use library::{next_witness_wide, vcof_prove_wide, witness_to_pubkey};
use std::embedded_curve_ops::EmbeddedCurvePoint;

/// Main entry point for the VCOF update circuit (Grumpkin variant).
///
/// Uses the wide derivation path: wn_next = (H(i,w,0) + H(i,w,1) * 2^254) mod l
/// This ensures the derived witness is unbiased and valid in both Ed25519 and Grumpkin.
///
/// For curves where N_SF < N_ed25519 (e.g., BabyJubJub), use vcof_prove_native instead.
fn main(i: pub Field, wn_prev: Field, pub_prev: pub EmbeddedCurvePoint, pub_next: pub EmbeddedCurvePoint) {
    vcof_prove_wide(i, wn_prev, pub_prev, pub_next);
}

// ============================================================================
// Benchmark Tests (Wide derivation for Grumpkin)
// ============================================================================

/// Benchmark: Single VCOF update with small values
#[test]
fn benchmark_vcof_wide_single_update_small() {
    let i: Field = 1;
    let wn_prev: Field = 12345;

    let pub_prev = witness_to_pubkey(wn_prev);
    let wn_next = next_witness_wide(i, wn_prev);
    let pub_next = witness_to_pubkey(wn_next);

    vcof_prove_wide(i, wn_prev, pub_prev, pub_next);
}

/// Benchmark: Single VCOF update with large 254-bit values
#[test]
fn benchmark_vcof_wide_single_update_large() {
    let wn_prev: Field = 0x2523648240000001ba344d80000000086121000000000013a700000000000012;
    let i: Field = 999999999;

    let pub_prev = witness_to_pubkey(wn_prev);
    let wn_next = next_witness_wide(i, wn_prev);
    let pub_next = witness_to_pubkey(wn_next);

    vcof_prove_wide(i, wn_prev, pub_prev, pub_next);
}

/// Benchmark: Chain of 5 consecutive VCOF updates
#[test]
fn benchmark_vcof_wide_chain_5_updates() {
    let mut w: Field = 0xabcdef123456789;

    for i in 1..5 {
        let pub_prev = witness_to_pubkey(w);
        let w_next = next_witness_wide(i as Field, w);
        let pub_next = witness_to_pubkey(w_next);
        vcof_prove_wide(i as Field, w, pub_prev, pub_next);
        w = w_next;
    }
}

/// Benchmark: Chain of 10 consecutive VCOF updates
#[test]
fn benchmark_vcof_wide_chain_10_updates() {
    let mut w: Field = 0xfeedface12345678;

    for i in 1..10 {
        let pub_prev = witness_to_pubkey(w);
        let w_next = next_witness_wide(i as Field, w);
        let pub_next = witness_to_pubkey(w_next);
        vcof_prove_wide(i as Field, w, pub_prev, pub_next);
        w = w_next;
    }
}

