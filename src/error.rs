// Copied from https://github.com/docknetwork/crypto/blob/main/compressed_sigma/src/error.rs
use ark_serialize::SerializationError;
use ark_std::fmt::Debug;

#[derive(Debug)]
pub enum SigmaError {
    InvalidResponse,
    VectorTooShort,
    VectorLenMismatch,
    NotPowerOfTwo,
    Serialization(SerializationError),
    WrongRecursionLevel,
    FaultyParameterSize,
}

impl From<SerializationError> for SigmaError {
    fn from(e: SerializationError) -> Self {
        Self::Serialization(e)
    }
}