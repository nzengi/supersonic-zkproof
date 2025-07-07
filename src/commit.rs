use num_bigint::{BigUint};
use sha2::{Digest, Sha256};

/// SHA256 hashını BigUint olarak döner
pub fn hash_to_big(data: &[u8]) -> BigUint {
    BigUint::from_bytes_be(&Sha256::digest(data))
}

/// RSA benzeri modül (örnek olarak 2^2048)
pub fn gen_rsa_modulus() -> BigUint {
    BigUint::one() << 2048
}

/// Polinom katsayılarından polinom commit hesaplar: g^{hash(coeffs)} mod n
pub fn commit_poly(coeffs: &[BigUint], g: &BigUint, n: &BigUint) -> BigUint {
    let mut bytes = vec![];
    for c in coeffs {
        let mut b = c.to_bytes_be();
        // Sabit uzunluk için 32 byte a tamamla (eksikse 0 ekle)
        b.resize(32, 0);
        bytes.extend(b);
    }
    let h = hash_to_big(&bytes);
    g.modpow(&h, n)
}

use num_traits::One;
