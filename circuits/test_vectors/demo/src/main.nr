use std::field::bn254::assert_lt;

// I know 2 numbers under 1,000 that multiply to get the given product
fn main(a: Field, b: Field, product: pub Field) {
    assert_lt(a, 1000);
    assert_lt(b, 1000);
    assert(a * b == product);
    // Evil contract. Doesn't prove anything except a & b < product
    // assert_lt(a, product);
    // assert_lt(b, product);
}

#[test]
fn test_main() {
    main(6, 7, 42);
}
