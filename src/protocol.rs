#![allow(non_snake_case)]

//! Implementation of protocol 5 in https://eprint.iacr.org/2020/152.pdf

use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::CanonicalSerialize;
use ark_std::{ops::Add, rand::RngCore, UniformRand};
use merlin::Transcript;

use crate::{error::SigmaError, relation::LinearForm};

pub struct Witness<G: AffineRepr> {
    x: Vec<G::ScalarField>,
    gamma: G::ScalarField,
}

pub struct Proof<G: AffineRepr> {
    //pub r: Vec<G::ScalarField>,
    //pub rho: G::ScalarField,
    pub t: G::ScalarField,
    pub A_hat: G,
    //pub z0_prime: G::ScalarField,
    //pub z1_prime: G::ScalarField,
    //pub A: Vec<G>,
    //pub B: Vec<G>,
    pub z: Vec<G::ScalarField>,
    pub phi: G::ScalarField,
}

impl<G: AffineRepr> Witness<G> {
    fn prove<R: RngCore, L: LinearForm<G::ScalarField>>(
        &self,
        rng: &mut R,
        g: &[G],
        h: &G,
        linear_form: &L,
    ) -> Result<Proof<G>, SigmaError> {
        if !(g.len() + 1).is_power_of_two() {
            return Err(SigmaError::NotPowerOfTwo);
        }
        if !linear_form.size().is_power_of_two() {
            return Err(SigmaError::NotPowerOfTwo);
        }
        if g.len() != self.x.len() {
            return Err(SigmaError::VectorLenMismatch);
        }
        if g.len() + 1 != linear_form.size() {
            return Err(SigmaError::VectorLenMismatch);
        }
        let rho = G::ScalarField::rand(rng);
        let blindings: Vec<G::ScalarField> =
            (0..g.len()).map(|_| G::ScalarField::rand(rng)).collect();
        let t = linear_form.eval(&blindings);
        let A_hat: <G as AffineRepr>::Group =
            G::Group::msm_unchecked(g, &blindings).add(&h.mul_bigint(rho.into_bigint()));

        let mut A_hat_bytes = Vec::new();
        A_hat.serialize_compressed(&mut A_hat_bytes).unwrap();
        let mut transcript = Transcript::new(b"Fiat-Shamir transcript!");
        transcript.append_message(
            b"first message, the linear form eval t",
            &t.into_bigint().to_bytes_le(),
        );
        transcript.append_message(b"first message, the msm eval A_hat", &A_hat_bytes);

        let c0: G::ScalarField = {
            let mut buf = Vec::new();
            transcript.challenge_bytes(b"c0", &mut buf);
            G::ScalarField::from_le_bytes_mod_order(&buf)
        };
        let c1: G::ScalarField = {
            let mut buf = Vec::new();
            transcript.challenge_bytes(b"c1", &mut buf);
            G::ScalarField::from_le_bytes_mod_order(&buf)
        };

        let z_temp: Vec<G::ScalarField> = self.x.iter().map(|v| c0 * v).collect();
        let z: Vec<G::ScalarField> = z_temp
            .iter()
            .zip(blindings.iter())
            .map(|(a, b)| *a + *b)
            .collect();
        let phi = c0 * self.gamma + rho;

        Ok(Proof {
            t,
            A_hat: A_hat.into_affine(),
            z,
            phi,
        })
    }
}

impl<G: AffineRepr> Proof<G> {
    fn verify<L: LinearForm<G::ScalarField>>(
        &self,
        g: &[G],
        h: &G,
        k: &G,
        linear_form: &L,
        P: &G,
        y: &G::ScalarField,
    ) -> Result<(), SigmaError> {
        if !(g.len() + 1).is_power_of_two() {
            return Err(SigmaError::NotPowerOfTwo);
        }
        if !linear_form.size().is_power_of_two() {
            return Err(SigmaError::NotPowerOfTwo);
        }
        if g.len() + 1 != linear_form.size() {
            return Err(SigmaError::VectorLenMismatch);
        }

        let mut A_hat_bytes = Vec::new();
        self.A_hat.serialize_compressed(&mut A_hat_bytes).unwrap();
        let mut transcript = Transcript::new(b"Fiat-Shamir transcript!");
        transcript.append_message(
            b"first message, the linear form eval t",
            &self.t.into_bigint().to_bytes_le(),
        );
        transcript.append_message(b"first message, the msm eval A_hat", &A_hat_bytes);

        let c0: G::ScalarField = {
            let mut buf = Vec::new();
            transcript.challenge_bytes(b"c0", &mut buf);
            G::ScalarField::from_le_bytes_mod_order(&buf)
        };

        let lhs1: <G as AffineRepr>::Group =
            G::Group::msm_unchecked(g, &self.z).add(&h.mul_bigint(self.phi.into_bigint()));
        let rhs1: <G as AffineRepr>::Group = P.mul(c0).add(self.A_hat);

        let lhs2 = linear_form.eval(&self.z);
        let rhs2 = c0 * y + self.t;

        if (lhs1 == rhs1) && (lhs2 == rhs2) {
            Ok(())
        } else {
            Err(SigmaError::InvalidResponse)
        }
    }
}
