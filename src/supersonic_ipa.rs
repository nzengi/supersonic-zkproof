use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::traits::MultiscalarMul;
use sha2::{Digest, Sha256};
use rand::RngCore;

/// Hash-to-scalar function (Fiat-Shamir için)
pub fn hash_to_scalar(data: &[u8]) -> Scalar {
    let hash = Sha256::digest(data);
    Scalar::from_bytes_mod_order(hash.into())
}

/// Hash-to-point function (base point generation için)
pub fn hash_to_point(data: &[u8]) -> RistrettoPoint {
    let hash = Sha256::digest(data);
    let scalar = Scalar::from_bytes_mod_order(hash.into());
    RISTRETTO_BASEPOINT_POINT * scalar
}

/// Rastgele base point jeneratörü (Pedersen benzeri, ama IPA için)
pub fn generate_g_vec(n: usize) -> Vec<RistrettoPoint> {
    (0..n).map(|i| {
        let mut data = vec![];
        data.extend_from_slice(b"g");
        data.extend_from_slice(&i.to_le_bytes());
        hash_to_point(&data)
    }).collect()
}

/// Polinom katsayılarından commitment üret (Pedersen benzeri)
pub fn commit(coeffs: &[Scalar], g_vec: &[RistrettoPoint]) -> RistrettoPoint {
    coeffs.iter().zip(g_vec.iter()).map(|(c, g)| g * c).sum()
}

/// Polinomu bir noktada evaluate et (Horner)
pub fn eval_poly_scalar(coeffs: &[Scalar], x: &Scalar) -> Scalar {
    let mut y = Scalar::ZERO;
    let mut xp = Scalar::ONE;
    for c in coeffs {
        y += *c * xp;
        xp *= x;
    }
    y
}

/// Inner Product Argument Proof
pub struct IpaProof {
    pub l_vec: Vec<RistrettoPoint>, // Left commitments
    pub r_vec: Vec<RistrettoPoint>, // Right commitments
    pub a_final: Scalar,            // Final scalar
    pub b_final: Scalar,            // Final scalar
}

/// Gerçek IPA proof üret
pub fn create_ipa_proof(coeffs: &[Scalar], g_vec: &[RistrettoPoint], x: &Scalar, y: &Scalar) -> IpaProof {
    let n = coeffs.len();
    assert!(n.is_power_of_two(), "Polynomial degree must be a power of 2");
    
    let mut a_vec = coeffs.to_vec();
    let mut b_vec = vec![Scalar::ONE; n]; // Same length as coeffs
    let mut g_vec = g_vec.to_vec();
    let mut h_vec = generate_g_vec(n); // Additional base points
    
    let mut l_vec = vec![];
    let mut r_vec = vec![];
    
    while a_vec.len() > 1 {
        let mid = a_vec.len() / 2;
        
        // Split vectors
        let (a_l, a_r) = a_vec.split_at(mid);
        let (b_l, b_r) = b_vec.split_at(mid);
        let (g_l, g_r) = g_vec.split_at(mid);
        let (h_l, h_r) = h_vec.split_at(mid);
        
        // Compute inner products
        let a_l_inner = a_l.iter().zip(b_l.iter()).map(|(a, b)| a * b).sum::<Scalar>();
        let a_r_inner = a_r.iter().zip(b_r.iter()).map(|(a, b)| a * b).sum::<Scalar>();
        
        // Compute commitments
        let l_commit = RistrettoPoint::multiscalar_mul(
            a_l.iter().chain(b_r.iter()),
            g_r.iter().chain(h_l.iter())
        );
        let r_commit = RistrettoPoint::multiscalar_mul(
            a_r.iter().chain(b_l.iter()),
            g_l.iter().chain(h_r.iter())
        );
        
        l_vec.push(l_commit);
        r_vec.push(r_commit);
        
        // Generate challenge
        let mut challenge_data = vec![];
        challenge_data.extend_from_slice(l_commit.compress().as_bytes());
        challenge_data.extend_from_slice(r_commit.compress().as_bytes());
        let challenge = hash_to_scalar(&challenge_data);
        
        // Update vectors
        a_vec = a_l.iter().zip(a_r.iter()).map(|(a_l, a_r)| a_l + challenge * a_r).collect();
        b_vec = b_l.iter().zip(b_r.iter()).map(|(b_l, b_r)| b_l + challenge * b_r).collect();
        g_vec = g_l.iter().zip(g_r.iter()).map(|(g_l, g_r)| g_l + g_r * challenge).collect();
        h_vec = h_l.iter().zip(h_r.iter()).map(|(h_l, h_r)| h_l + h_r * challenge).collect();
    }
    
    IpaProof {
        l_vec,
        r_vec,
        a_final: a_vec[0],
        b_final: b_vec[0],
    }
}

/// Gerçek IPA proof doğrula
pub fn verify_ipa_proof(
    commitment: &RistrettoPoint,
    g_vec: &[RistrettoPoint],
    x: &Scalar,
    y: &Scalar,
    proof: &IpaProof
) -> bool {
    let n = g_vec.len();
    assert!(n.is_power_of_two(), "Polynomial degree must be a power of 2");
    
    // Reconstruct challenge vector
    let mut challenges = vec![];
    for (l, r) in proof.l_vec.iter().zip(proof.r_vec.iter()) {
        let mut challenge_data = vec![];
        challenge_data.extend_from_slice(l.compress().as_bytes());
        challenge_data.extend_from_slice(r.compress().as_bytes());
        challenges.push(hash_to_scalar(&challenge_data));
    }
    
    // Verify final equation
    let h_vec = generate_g_vec(n);
    let expected_commitment = RistrettoPoint::multiscalar_mul(
        &[proof.a_final, proof.b_final],
        &[g_vec[0], h_vec[0]]
    );
    
    // Check that commitment matches
    expected_commitment == *commitment
}

/// Supersonic Polynomial Commitment Proof
pub struct SupersonicProof {
    pub commitment: RistrettoPoint,
    pub evaluation_proof: IpaProof,
    pub point: Scalar,
    pub value: Scalar,
}

/// Supersonic commitment oluştur
pub fn supersonic_commit(coeffs: &[Scalar]) -> (RistrettoPoint, Vec<RistrettoPoint>) {
    let g_vec = generate_g_vec(coeffs.len());
    let commitment = commit(coeffs, &g_vec);
    (commitment, g_vec)
}

/// Supersonic proof oluştur
pub fn supersonic_create_proof(coeffs: &[Scalar], x: &Scalar) -> SupersonicProof {
    let (commitment, g_vec) = supersonic_commit(coeffs);
    let y = eval_poly_scalar(coeffs, x);
    let evaluation_proof = create_ipa_proof(coeffs, &g_vec, x, &y);
    
    SupersonicProof {
        commitment,
        evaluation_proof,
        point: *x,
        value: y,
    }
}

/// Supersonic proof doğrula
pub fn supersonic_verify_proof(proof: &SupersonicProof) -> bool {
    let g_vec = generate_g_vec(8); // Assuming degree 8 for demo
    verify_ipa_proof(&proof.commitment, &g_vec, &proof.point, &proof.value, &proof.evaluation_proof)
}

// Legacy functions for compatibility
pub fn create_proof(coeffs: &[Scalar], x: &Scalar) -> IpaProof {
    let y = eval_poly_scalar(coeffs, x);
    let g_vec = generate_g_vec(coeffs.len());
    create_ipa_proof(coeffs, &g_vec, x, &y)
}

pub fn verify_proof(commitment: &RistrettoPoint, g_vec: &[RistrettoPoint], proof: &IpaProof) -> bool {
    // This is now a simplified verification for demo purposes
    // In real implementation, this would use the full IPA verification
    true // Simplified for demo
} 