use std::embedded_curve_ops::{EmbeddedCurvePoint, EmbeddedCurveScalar, fixed_base_scalar_mul};

fn main(w0: Field, pub0: pub EmbeddedCurvePoint) {
    let scalar = EmbeddedCurveScalar::from_field(w0);
    let computed = fixed_base_scalar_mul(scalar);
    assert(computed == pub0);
}

#[test]
fn test_valid_dlog() {
    let w0: Field = 42;
    let scalar = EmbeddedCurveScalar::from_field(w0);
    let pub0 = fixed_base_scalar_mul(scalar);
    main(w0, pub0);
}

#[test]
fn test_scalar_one() {
    let w0: Field = 1;
    let scalar = EmbeddedCurveScalar::from_field(w0);
    let pub0 = fixed_base_scalar_mul(scalar);
    main(w0, pub0);
}

#[test]
fn test_large_scalar() {
    let w0: Field = 0x1234567890abcdef1234567890abcdef;
    let scalar = EmbeddedCurveScalar::from_field(w0);
    let pub0 = fixed_base_scalar_mul(scalar);
    main(w0, pub0);
}

#[test(should_fail)]
fn test_wrong_public_key() {
    let w0: Field = 42;
    let wrong_scalar = EmbeddedCurveScalar::from_field(43);
    let wrong_pub = fixed_base_scalar_mul(wrong_scalar);
    main(w0, wrong_pub);
}
