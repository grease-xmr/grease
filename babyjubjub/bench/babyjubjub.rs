use ark_algebra_bench_templates::*;
use grease_babyjubjub::{Fq, Fr, ProjectivePoint};

bench!(
    Name = "BabyJubJub",
    Group = ProjectivePoint,
    ScalarField = Fr,
    PrimeBaseField = Fq,
);
