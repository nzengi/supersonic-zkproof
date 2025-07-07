use crate::commit::hash_to_big;
use num_bigint::BigUint;

/// Fiat-Shamir yöntemiyle challenge oluşturur
pub fn fiat_shamir_challenge(commitment: &BigUint) -> BigUint {
    let c_bytes = commitment.to_bytes_be();
    hash_to_big(&c_bytes)
}

/// Polinom değerini x noktasında hesaplar
pub fn eval_poly(coeffs: &[BigUint], x: &BigUint) -> BigUint {
    let mut y = BigUint::default();
    let mut xp = BigUint::from(1u32);
    for c in coeffs {
        y += c * &xp;
        xp *= x;
    }
    y
}
