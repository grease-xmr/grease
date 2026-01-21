//! Grumpkin curve constants
//!
//! Grumpkin is a prime-order elliptic curve that forms a cycle with BN254.
//! - Base field Fq = BN254 scalar field
//! - Scalar field Fr = BN254 base field

/// The prime modulus of the base field $F_q$ (= BN254 scalar field).
pub const MODULUS_STR_FQ: &str = "21888242871839275222246405745257275088548364400416034343698204186575808495617";
/// The prime modulus of the scalar field $F_r$ (= BN254 base field).
pub const MODULUS_STR_FR: &str = "21888242871839275222246405745257275088696311157297823662689037894645226208583";
/// The size in bytes of a field element or scalar.
pub const SCALAR_SIZE: usize = 32;

/// Grumpkin has cofactor 1 (prime order curve).
pub const COFACTOR: u64 = 1;

#[cfg(feature = "serai")]
pub mod serai {
    //! Constants for Serai's `PrimeField` trait on Grumpkin's scalar field.
    //!
    //! For Grumpkin Fr (= BN254 base field q):
    //! - q = 21888242871839275222246405745257275088696311157297823662689037894645226208583
    //! - q - 1 = 2^1 * t, so S = 1
    //!
    //! Calculated in SageMath:
    //! ```sage
    //! q = 21888242871839275222246405745257275088696311157297823662689037894645226208583
    //! F = GF(q)
    //! s = 1  # Number of trailing zeros in q-1
    //! Ss = 1 << s  # 2
    //! t = (q - 1) // Ss
    //! # t = 10944121435919637611123202872628637544348155578648911831344518947322613104291
    //!
    //! # Find multiplicative generator (arkworks uses 3 for BN254 base field)
    //! g = F(3)
    //! assert g.multiplicative_order() == q - 1
    //!
    //! # Root of unity (primitive 2nd root)
    //! u = g**t
    //! # u = q - 1 (which is -1 in the field)
    //! u_inv = u.inverse()
    //! # u_inv = q - 1 (same as u since (-1)^(-1) = -1)
    //!
    //! # delta = g^(2^s) = g^2 = 9
    //! delta = g ** Ss
    //!
    //! # TWO_INV = (q + 1) / 2
    //! two_inv = F(2).inverse()
    //! # two_inv = 10944121435919637611123202872628637544348155578648911831344518947322613104292
    //! ```
    use crate::Fr;
    use ark_ff::MontFp;

    /// Multiplicative inverse of 2 in Fr.
    pub const INV_2: Fr = MontFp!("10944121435919637611123202872628637544348155578648911831344518947322613104292");

    /// Primitive 2^S-th root of unity (where S=1, so this is -1).
    pub const ROOT_OF_UNITY: Fr =
        MontFp!("21888242871839275222246405745257275088696311157297823662689037894645226208582");

    /// Inverse of ROOT_OF_UNITY (same as ROOT_OF_UNITY since (-1)^(-1) = -1).
    pub const ROOT_OF_UNITY_INV: Fr =
        MontFp!("21888242871839275222246405745257275088696311157297823662689037894645226208582");

    /// delta = generator^(2^S) = 3^2 = 9.
    pub const DELTA: Fr = MontFp!("9");
}

#[cfg(feature = "serai")]
pub use serai::*;
