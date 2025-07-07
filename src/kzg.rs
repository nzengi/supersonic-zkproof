use ark_bls12_381::{Bls12_381, Fr, G1Projective, G2Projective};
use ark_ec::{pairing::Pairing, CurveGroup, Group};
use ark_ff::{Field, UniformRand, Zero, One};
use ark_poly::univariate::DensePolynomial;
use ark_poly::DenseUVPolynomial;
use ark_poly::Polynomial;
use ark_std::rand::Rng;

pub struct KZGSetup {
    pub powers_of_g: Vec<G1Projective>,
    pub powers_of_h: Vec<G2Projective>,
    pub s: Fr,
}

pub fn kzg_trusted_setup<R: Rng>(degree: usize, rng: &mut R) -> KZGSetup {
    let s = Fr::rand(rng);
    let mut powers_of_g = Vec::with_capacity(degree + 1);
    let mut powers_of_h = Vec::with_capacity(degree + 1);
    let mut cur_g = G1Projective::generator();
    let mut cur_h = G2Projective::generator();
    for _ in 0..=degree {
        powers_of_g.push(cur_g);
        powers_of_h.push(cur_h);
        cur_g *= s;
        cur_h *= s;
    }
    KZGSetup { powers_of_g, powers_of_h, s }
}

pub fn kzg_commit(poly: &DensePolynomial<Fr>, setup: &KZGSetup) -> G1Projective {
    poly.coeffs.iter().zip(setup.powers_of_g.iter())
        .map(|(c, g)| *g * c)
        .sum()
}

fn naive_poly_division(
    numerator: &DensePolynomial<Fr>,
    divisor: &DensePolynomial<Fr>,
) -> (DensePolynomial<Fr>, DensePolynomial<Fr>) {
    let mut remainder = numerator.coeffs.clone();
    let mut quotient = vec![Fr::zero(); remainder.len()];
    let divisor_deg = divisor.degree();
    let divisor_lead = divisor.coeffs[divisor_deg];
    for i in (divisor_deg..=numerator.degree()).rev() {
        let coeff = remainder[i] / divisor_lead;
        quotient[i - divisor_deg] = coeff;
        for j in 0..=divisor_deg {
            remainder[i - j] -= coeff * divisor.coeffs[divisor_deg - j];
        }
    }
    (
        DensePolynomial::from_coefficients_vec(quotient),
        DensePolynomial::from_coefficients_vec(remainder),
    )
}

pub fn kzg_create_proof(poly: &DensePolynomial<Fr>, z: Fr, setup: &KZGSetup) -> G1Projective {
    let fz = poly.evaluate(&z);
    let mut coeffs = poly.coeffs.clone();
    if !coeffs.is_empty() {
        coeffs[0] -= fz;
    }
    let numerator = DensePolynomial::from_coefficients_vec(coeffs);
    let divisor = DensePolynomial::from_coefficients_vec(vec![-z, Fr::one()]);
    let (q, _r) = naive_poly_division(&numerator, &divisor);
    kzg_commit(&q, setup)
}

pub fn kzg_verify(
    commitment: &G1Projective,
    z: Fr,
    y: Fr,
    proof: &G1Projective,
    setup: &KZGSetup,
) -> bool {
    let h = setup.powers_of_h[0];
    let s_g2 = setup.powers_of_h[1];
    let s_minus_z_g2 = s_g2 - h * z;
    let left = Bls12_381::pairing(
        (*commitment - G1Projective::generator() * y).into_affine(),
        h.into_affine(),
    );
    let right = Bls12_381::pairing(proof.into_affine(), s_minus_z_g2.into_affine());
    left == right
} 