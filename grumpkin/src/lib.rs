pub mod constants;
mod curve;

#[cfg(feature = "serai")]
pub mod serai;

pub use ark_grumpkin::{Affine as Point, Fq, Fr, GrumpkinConfig, Projective as ProjectivePoint};
pub use curve::*;

#[cfg(feature = "serai")]
pub use serai::{Grumpkin, GrumpkinPoint, Scalar, generators};
