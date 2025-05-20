use thiserror::Error;

#[derive(Clone, Debug, Error)]
pub enum KesError {
    #[error("KES initialization failed: {0}")]
    InitializationError(String),
}
