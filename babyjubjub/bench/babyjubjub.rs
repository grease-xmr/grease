use ark_algebra_bench_templates::*;
use grease_babyjubjub::{ProjectivePoint, Fq, Fr};

bench!(
    Name = "BabyJubJub",
    Group = ProjectivePoint,
    ScalarField = Fr,
    PrimeBaseField = Fq,
);