use thiserror::Error;

#[derive(Debug, Error)]
#[error("Delegate error: {0}")]
pub struct DelegateError(pub String);

impl From<&str> for DelegateError {
    fn from(s: &str) -> Self {
        DelegateError(s.to_string())
    }
}
