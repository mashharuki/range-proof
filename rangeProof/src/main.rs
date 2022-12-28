extern crate rand;
extern crate curve25519_dalek;
extern crate merlin;
extern crate bulletproofs;

use rand::thread_rng;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};

/**
 * main method
 */
fn main() {
    // Generators for Pedersen commitments.  These can be selected
    // independently of the Bulletproofs generators.
    let pc_gens = PedersenGens::default();

    // Generators for Bulletproofs, valid for proofs up to bitsize 64
    // and aggregation size up to 1.
    let bp_gens = BulletproofGens::new(64, 1);

    // A secret value we want to prove lies in the range [0, 2^32)
    let secret_value = 1037578891u64;

    let mut rng = rand::thread_rng();

    // The API takes a blinding factor for the commitment.
    let blinding = curve25519_dalek::scalar::Scalar::random(&mut rng);

    // The proof can be chained to an existing transcript.
    // Here we create a transcript with a doctest domain separator.
    let mut prover_transcript = Transcript::new(b"doctest example");

    // Create a 32-bit rangeproof.
    let (proof, committed_value) = RangeProof::prove_single(
        &bp_gens,
        &pc_gens,
        &mut prover_transcript,
        secret_value,
        &blinding,
        32,
    ).expect("A real program could handle errors");

    // Verification requires a transcript with identical initial state:
    let mut verifier_transcript = Transcript::new(b"doctest example");
    assert!(
        proof
            .verify_single(&bp_gens, &pc_gens, &mut verifier_transcript, &committed_value, 32)
            .is_ok()
    );
}

/* 
fn main() {
    // Generators for Pedersen commitments.  These can be selected
    // independently of the Bulletproofs generators.
    // コミットメントを生成
    let pc_gens = PedersenGens::default();

    // Generators for Bulletproofs, valid for proofs up to bitsize 64
    // and aggregation size up to 16.
    // proofを作成
    let bp_gens = BulletproofGens::new(64, 16);

    // Four secret values we want to prove lie in the range [0, 2^32)
    // 範囲証明したい値 (0〜2^32-1内にあることを確認する。)
    let secrets = [4242344947u64, 3718732727u64, 2255562556u64, 2526146994u64];

    // The API takes blinding factors for the commitments.
    let blindings: Vec<_> = (0..4).map(|_| Scalar::random(&mut thread_rng())).collect();

    // The proof can be chained to an existing transcript.
    // Here we create a transcript with a doctest domain separator.
    let mut prover_transcript = Transcript::new(b"doctest example");

    // Create an aggregated 32-bit rangeproof and corresponding commitments.
    // proofとコミットメントを生成
    let (proof, commitments) = RangeProof::prove_multiple(
        &bp_gens,
        &pc_gens,
        &mut prover_transcript,
        &secrets,
        &blindings,
        32,
    ).expect("A real program could handle errors");

    // Verification requires a transcript with identical initial state:
    // ゼロ知識証明の検証を実行
    let mut verifier_transcript = Transcript::new(b"doctest example");
    assert!(
        proof
            .verify_multiple(&bp_gens, &pc_gens, &mut verifier_transcript, &commitments, 32)
            .is_ok()
    );
}
*/