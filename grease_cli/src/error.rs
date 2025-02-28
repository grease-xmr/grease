use thiserror::Error;

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("IO Error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Invalid configuration file: {0}")]
    InvalidConfig(#[from] serde_yml::Error),
}
