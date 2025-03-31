use crate::cas::{CasError, Statement, StatementWitnessPair, StatementWitnessProof, Witness, VCOF};
use crate::hashes::{Blake512, HashToScalar};
use crate::keys::{PublicKey, SecretKey};
use crate::monero_impl::{MoneroStatement, MoneroWitness, SchnorrProof};
use blake::Blake;
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::Scalar;

pub struct Vcof25519;

impl Vcof25519 {
    fn construct_challenge(public_nonce: &PublicKey, statement_prev: &PublicKey, statement: &PublicKey) -> Scalar {
        let mut hasher = Blake::new(256).expect("Should be able to create Blake instance");
        hasher.update(public_nonce.as_compressed().as_bytes());
        hasher.update(statement_prev.as_compressed().as_bytes());
        hasher.update(statement.as_compressed().as_bytes());
        let mut challenge = [0u8; 32];
        hasher.finalise(&mut challenge);
        let challenge = Scalar::from_bytes_mod_order(challenge);
        challenge
    }
}

impl VCOF for Vcof25519 {
    type W = MoneroWitness;
    type Proof = SchnorrProof;

    fn generate(&self) -> (MoneroWitness, MoneroStatement) {
        let mut rng = rand::rng();
        let (sk, pk) = PublicKey::keypair(&mut rng);
        let witness = MoneroWitness::from_scalar(sk.to_scalar());
        let statement = MoneroStatement::from_public_key(pk);
        (witness, statement)
    }

    /// Generate a statement-witness pair
    ///
    /// Using Schnorr proofs.
    ///
    /// ** NB ** I do not know if this satisfies the security guarantees of the VCOF
    fn next_statement_witness(
        &self,
        witness: &MoneroWitness,
        statement: &MoneroStatement,
    ) -> Result<StatementWitnessProof<Self>, CasError> {
        // Check that witness and statement correspond
        if &witness.generate_statement() != statement {
            return Err(CasError::WitnessStatementMismatch);
        }

        let mut rng = rand::rng();
        let witness_prev = witness.as_scalar();
        let statement_prev = statement.as_public_key();

        // Generate the next witness - y_{i+1} = H(y_i)
        let mut hasher = Blake512;
        let witness_next = hasher.hash_to_scalar(witness_prev.as_bytes());
        let witness_next = SecretKey::from(witness_next);
        let statement_next = PublicKey::from_secret(&witness_next);
        // Generate a Schnorr proof for the next witness committing to the consecutive statements
        let (r, public_nonce) = PublicKey::keypair(&mut rng);
        let challenge = Vcof25519::construct_challenge(&public_nonce, &statement_prev, &statement_next);
        let s = r.as_scalar() + challenge * witness_next.as_scalar();

        let witness_next = MoneroWitness::from_scalar(witness_next.to_scalar());
        let statement_next = MoneroStatement::from_public_key(statement_next);

        let proof = SchnorrProof { public_nonce, s };
        let pair = StatementWitnessPair { witness: witness_next, statement: statement_next };
        Ok(StatementWitnessProof { pair, proof })
    }

    fn verify_consecutive(&self, prev: &MoneroStatement, current: &MoneroStatement, proof: &SchnorrProof) -> bool {
        let s = &proof.s;
        let pub_r = &proof.public_nonce;
        let challenge = Vcof25519::construct_challenge(pub_r, prev.as_public_key(), current.as_public_key());
        let lhs = s * ED25519_BASEPOINT_TABLE;
        let rhs = pub_r.as_point() + challenge * current.as_public_key().as_point();
        lhs == rhs
    }
}

#[cfg(test)]
mod test {
    use crate::cas::{StatementWitnessProof, VCOF};
    use crate::vcof_25519::Vcof25519;

    #[test]
    #[allow(non_snake_case)]
    fn vcof_gen_and_verify() {
        let vcof = Vcof25519;
        let (y0, Y0) = vcof.generate();
        let proof_1 = vcof.next_statement_witness(&y0, &Y0).unwrap();
        let StatementWitnessProof { pair, proof: proof_1 } = proof_1;
        let y1 = pair.witness;
        let Y1 = pair.statement;
        assert!(
            vcof.verify_consecutive(&Y0, &Y1, &proof_1),
            "Consecutive proof verification failed"
        );

        let proof_2 = vcof.next_statement_witness(&y1, &Y1).unwrap();
        let StatementWitnessProof { pair, proof: proof_2 } = proof_2;
        let y2 = pair.witness;
        let Y2 = pair.statement;
        assert!(
            vcof.verify_consecutive(&Y1, &Y2, &proof_2),
            "Consecutive proof verification failed"
        );
        // Y2 does not follow Y1
        assert!(
            !vcof.verify_consecutive(&Y0, &Y2, &proof_1),
            "Y2 should not follow Y0 using proof 1"
        );
        assert!(
            !vcof.verify_consecutive(&Y0, &Y2, &proof_2),
            "Y2 should not follow Y0 using proof 2"
        );
        // Cannot generate next pair with mismatched statement and witness
        assert!(
            vcof.next_statement_witness(&y1, &Y0).is_err(),
            "Should not be able to generate next pair with mismatched statement and witness"
        );
    }
}
