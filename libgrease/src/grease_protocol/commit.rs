use flexible_transcript::{SecureDigest, Transcript};
use modular_frost::sign::Writable;

pub trait Commit<D: SecureDigest> {
    type Committed: Clone + Writable;
    type Transcript: Transcript;
    fn commit(&self) -> Self::Committed;
    fn verify(&self, commitment: &Self::Committed) -> bool;
}
