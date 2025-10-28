use thiserror::Error;

#[derive(Debug, Error)]
#[error("error reading field '{field}': {error}")]
pub struct ReadError {
    field: String,
    error: String,
}

impl ReadError {
    pub fn new(field: impl Into<String>, error: impl Into<String>) -> Self {
        Self { field: field.into(), error: error.into() }
    }
}
