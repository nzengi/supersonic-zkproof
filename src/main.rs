mod commit;
mod prove;
mod verify;
mod supersonic_ipa;

use commit::{commit_poly, gen_rsa_modulus};
use num_bigint::{BigUint, RandBigInt};
use prove::{fiat_shamir_challenge};
use std::time::Instant;
use verify::verify_eval;

fn main() {
    // --- Klasik örnek ---
    let mut rng = rand::thread_rng();
    let n = gen_rsa_modulus();
    let g = BigUint::from(3u32);
    let coeffs_big: Vec<BigUint> = (0..32).map(|_| rng.gen_biguint(128)).collect();
    let t0 = Instant::now();
    let commitment_big = commit_poly(&coeffs_big, &g, &n);
    let t1 = Instant::now();
    let challenge_big = fiat_shamir_challenge(&commitment_big);
    let t2 = Instant::now();
    let y_big = prove::eval_poly(&coeffs_big, &challenge_big);
    let t3 = Instant::now();
    let result_big = verify_eval(&commitment_big, &g, &n, &challenge_big, &y_big);
    let t4 = Instant::now();
    println!("Commitment: {}", commitment_big);
    println!("Challenge (Fiat-Shamir): {}", challenge_big);
    println!("Evaluation at x=challenge: {}", y_big);
    println!("Proof verification result: {}", result_big);
    println!("\nSizes:");
    println!("  Commitment size: {} bits", commitment_big.bits());
    println!("  Challenge size: {} bits", challenge_big.bits());
    println!("  Evaluation result size: {} bits", y_big.bits());
    println!("  Modulus size: {} bits", n.bits());
    println!("\nTimings:");
    println!("  Commit time:  {:.6}s", (t1 - t0).as_secs_f64());
    println!("  Fiat-Shamir time: {:.6}s", (t2 - t1).as_secs_f64());
    println!("  Evaluation time: {:.6}s", (t3 - t2).as_secs_f64());
    println!("  Verify time: {:.6}s", (t4 - t3).as_secs_f64());

    // --- Supersonic IPA örneği ---
    use supersonic_ipa::*;
    use curve25519_dalek::scalar::Scalar;
    use rand::RngCore;
    println!("\n--- Supersonic IPA Example ---");
    let degree = 8;
    let mut rng = rand::thread_rng();
    let coeffs_scalar: Vec<Scalar> = (0..degree).map(|_| Scalar::from(rng.next_u64())).collect();
    let x_scalar = Scalar::from(42u64);
    
    // Gerçek Supersonic IPA
    let t5 = Instant::now();
    let supersonic_proof = supersonic_create_proof(&coeffs_scalar, &x_scalar);
    let t6 = Instant::now();
    let supersonic_verify = supersonic_verify_proof(&supersonic_proof);
    let t7 = Instant::now();
    
    println!("Supersonic IPA Commitment: {:?}", supersonic_proof.commitment.compress());
    println!("Supersonic IPA Evaluation at x=42: {:?}", supersonic_proof.value);
    println!("Supersonic IPA Proof verification result: {}", supersonic_verify);
    println!("Supersonic IPA Commitment size: {} bits", supersonic_proof.commitment.compress().as_bytes().len() * 8);
    println!("Supersonic IPA Evaluation result size: {} bits", supersonic_proof.value.to_bytes().len() * 8);
    println!("Supersonic IPA Proof size: {} commitments", supersonic_proof.evaluation_proof.l_vec.len());
    println!("Supersonic IPA Create proof time: {:.6}s", (t6 - t5).as_secs_f64());
    println!("Supersonic IPA Verify time: {:.6}s", (t7 - t6).as_secs_f64());
}
