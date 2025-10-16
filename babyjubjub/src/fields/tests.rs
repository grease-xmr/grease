use super::{Fq, Fr};
use crate::SCALAR_SIZE;
use ark_algebra_test_templates::*;
use ark_ff::{Field, One};
use ark_serialize::{CanonicalSerialize, Compress};

test_field!(fr; Fr; mont_prime_field);
test_field!(fq; Fq; mont_prime_field);

#[test]
fn inverse_2() {
    let two = Fr::from(2u64);
    let inv_two = two.inverse().unwrap();
    assert_eq!(
        inv_two.to_string(),
        "1368015179489954701390400359078579693038406986079283629600107830474223686521"
    );
}

#[test]
fn serialization_size() {
    // If this fails, update SCALAR_SIZE constant
    let s = Fr::one();
    assert_eq!(s.serialized_size(Compress::Yes), SCALAR_SIZE);
    assert_eq!(s.serialized_size(Compress::No), SCALAR_SIZE);
    let s = Fq::one();
    assert_eq!(s.serialized_size(Compress::Yes), SCALAR_SIZE);
    assert_eq!(s.serialized_size(Compress::No), SCALAR_SIZE);
}

#[test]
fn hash_to_fq() {
    let msg = b"Hello, World!";
    let elems: [Fq; 2] = super::hash_to_fq(msg);
    assert_eq!(
        elems[0].to_string(),
        "7902606182048578660389777045020343910782629982389567686397286624274568409573"
    );
    assert_eq!(
        elems[1].to_string(),
        "8039809235765642334910189346221311706232212386441248790318087536716405903319"
    );
}

#[test]
fn hash_to_fr() {
    let msg = b"Hello, World!";
    let elems: [Fr; 2] = super::hash_to_fr(msg);
    assert_eq!(
        elems[0].to_string(),
        "731150853953985181655208374830668176031668198075341157136715258944788578683"
    );
    assert_eq!(
        elems[1].to_string(),
        "889931313573050842348294786004079739575884208304950175386400570029816794733"
    );
}
