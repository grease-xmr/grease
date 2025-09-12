//! Baby Jubjub constants
//!
//! Refer to <https://eips.ethereum.org/EIPS/eip-2494>

use crate::Fq;
use ark_ff::biginteger::BigInteger256;
use ark_ff::{BigInt, MontFp};

/// The prime modulus of the base field $F_q$.
pub const MODULUS_STR_FQ: &str = "21888242871839275222246405745257275088548364400416034343698204186575808495617";
/// The prime modulus of the scalar field $F_r$.
pub const MODULUS_STR_FR: &str = "2736030358979909402780800718157159386076813972158567259200215660948447373041";
/// The size in bytes of a field element or scalar.
pub const SCALAR_SIZE: usize = 32;

/// The BabyJubJub curve has order n.
///
/// $n = 21888242871839275222246405745257275088614511777268538073601725287587578984328$
pub const ORDER_BJJ: BigInteger256 =
    BigInt!("21888242871839275222246405745257275088614511777268538073601725287587578984328");

/// The largest prime factor of n, called l, determines the security of the curve.
///
/// $l = 2736030358979909402780800718157159386076813972158567259200215660948447373041$ and is 251 bits.
pub const SUBORDER_BJJ: BigInteger256 =
    BigInt!("2736030358979909402780800718157159386076813972158567259200215660948447373041");

/// The cofactor of the curve, $h = 8$. $h \cdot l = n$.
pub const COFACTOR_BJJ: u64 = 8;

/// The base point $B = (x,y)$ with the coordinates below generates the subgroup of points $P$ of Baby Jubjub satisfying
/// $\ell \cdot P = \mathcal{O}$. That is, it generates the set of points of order $\ell$ and origin $\mathcal{O}$.
///
/// $x = 5299619240641551281634865583518297030282874472190772894086521144482721001553$
/// $y = 16950150798460657717958625567821834550301663161624707787222815936182638968203$
pub const B_X_BJJ: Fq = MontFp!("5299619240641551281634865583518297030282874472190772894086521144482721001553");
/// The y-coordinate of the base point B.
pub const B_Y_BJJ: Fq = MontFp!("16950150798460657717958625567821834550301663161624707787222815936182638968203");

/// The point $G = (x,y)$ with coordinates below generates all $n$ points of the curve.
///
/// $x = 995203441582195749578291179787384436505546430278305826713579947235728471134$
/// $y = 5472060717959818805561601436314318772137091100104008585924551046643952123905$
pub const G_X_BJJ: Fq = MontFp!("995203441582195749578291179787384436505546430278305826713579947235728471134");
pub const G_Y_BJJ: Fq = MontFp!("5472060717959818805561601436314318772137091100104008585924551046643952123905");

#[cfg(feature = "serai")]
pub mod serai {
    //! These constants are used in Serai's `PrimeField` trait.
    //!
    //! They were calculated in SageMath as follows:
    //! ```sage
    //! # Modulus (prime)
    //! r = 2736030358979909402780800718157159386076813972158567259200215660948447373041
    //! # Prime field
    //! F = GF(r)
    //! # Generator
    //! g = F(31)
    //! s = 4 #The number of consecutive zeroes in the least consectuive bits of r-1
    //! Ss = 1 << s
    //! t = F(r-1) / Ss
    //! # Root of Unity
    //! u = g**t
    //! u_inv = u.inverse()
    //! print(u, u_inv)
    //! # 660854635938548466034658205324789272997681163813030924457091119852551226483
    //! 1043224705284028335988439394520573142339627108237299665735065585269676699527
    //! delta = g ** Ss
    //! print(delta)
    //! # 727423121747185263828481
    //! ```
    use crate::Fr;
    use ark_ff::MontFp;

    pub const INV_2: Fr = MontFp!("1368015179489954701390400359078579693038406986079283629600107830474223686521");
    pub const ROOT_OF_UNITY: Fr =
        MontFp!("660854635938548466034658205324789272997681163813030924457091119852551226483");
    pub const ROOT_OF_UNITY_INV: Fr =
        MontFp!("1043224705284028335988439394520573142339627108237299665735065585269676699527");
    pub const DELTA: Fr = MontFp!("727423121747185263828481");
}

#[cfg(feature = "serai")]
pub use serai::*;
