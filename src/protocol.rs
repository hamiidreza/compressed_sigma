#![allow(non_snake_case)]

//! Implementation of protocol 5 in https://eprint.iacr.org/2020/152.pdf


use ark_ec::{AffineRepr, VariableBaseMSM, CurveGroup};
use ark_ff::PrimeField;
use ark_std::ops::Add;
use digest::Digest;

use crate::{relation::LinearForm, error::SigmaError};

pub struct FirstMessage<G: AffineRepr> {
    pub r: Vec<G::ScalarField>,
    pub rho: G::ScalarField,
    pub t: G::ScalarField,
    pub A_hat: G,
}

pub struct Response<G: AffineRepr> {
    pub z0_prime: G::ScalarField,
    pub z1_prime: G::ScalarField,
    pub A: Vec<G>,
    pub B: Vec<G>,
}

impl<G: AffineRepr> FirstMessage<G> {
    fn new<L: LinearForm<G::ScalarField>>(
        g: &[G],
        h: &G,
        linear_form: &L,
        rho: G::ScalarField,
        blindings: Vec<G::ScalarField>,
    ) -> Result<Self, SigmaError> {
        if !(g.len() + 1).is_power_of_two(){
            return Err(SigmaError::NotPowerOfTwo);
        } 
        if blindings.len() != g.len(){
            return Err(SigmaError::VectorLenMismatch);
        }
        if !linear_form.size().is_power_of_two(){
            return Err(SigmaError::NotPowerOfTwo);
        }
        let t = linear_form.eval(&blindings);
        let A_hat = G::Group::msm_unchecked(g, &blindings).add(&h.mul_bigint(rho.into_bigint()));
        Ok(Self {
            r: blindings,
            rho,
            t,
            A_hat: A_hat.into_affine(),
        })
    }
    pub fn response<D: Digest, L: LinearForm<G::ScalarField>>(
        &self,
        g: &[G],
        h: &G,
        k: &G,
        linear_form: &L,
        wit_x: &[G::ScalarField],
        wit_gamma: &G::ScalarField,
    ) -> Result<Response<G>, SigmaError> {
        if !(g.len() +1).is_power_of_two(){
            return Err(SigmaError::NotPowerOfTwo);
        }
        if !linear_form.size().is_power_of_two(){
            return Err(SigmaError::NotPowerOfTwo);
        }
        if !(g.len() != wit_x.len()){
            return Err(SigmaError::VectorLenMismatch)
        }
        if !(g.len() + 1 != linear_form.size()){
            return Err(SigmaError::VectorLenMismatch)
        }

        todo!()
    }
}