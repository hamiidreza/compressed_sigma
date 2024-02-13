// Copied from https://github.com/docknetwork/crypto/blob/main/compressed_sigma/src/transforms.rs
use ark_ff::Field;

/// For a linear form, i.e. for a form `L` and a vector `x` of size `n`, `L(x) = a_0*x_0 + a_1*x_1 + ... + a_n*x_n`
/// for constants `a_0`, `a_1`, etc
pub trait LinearForm<F: Field>: Sized {
    fn eval(&self, x: &[F]) -> F;

    fn scale(&self, scalar: &F) -> Self;

    fn add(&self, other: &Self) -> Self;

    fn split_in_half(&self) -> (Self, Self);

    fn size(&self) -> usize;

    fn pad(&self, new_size: u32) -> Self;
}

