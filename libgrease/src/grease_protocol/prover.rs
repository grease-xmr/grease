//! Step 1 of the initialization phase of the Channel State Prover (CSP).
//! This step requires the merchant to provide commitments to data that will be supplied to the customer at step 2.

use crate::grease_protocol::commit::Commit;
use crate::grease_protocol::error::WitnessProofError;
use flexible_transcript::SecureDigest;
use modular_frost::curve::Curve;
use modular_frost::sign::Writable;

pub trait WitnessProofPreprocess<C: Curve, D: SecureDigest> {
    /// The pre-preprocess data that will be shared with the peer, which they need to generate the witness proof.
    type PublicWitnessProofInfo: Writable + Commit<D>;
    type CommitmentContext;
}

pub trait ProveWitness<C: Curve, D: SecureDigest> {
    type PublicInputs;
    type PrivateInputs;
    type PublicOutputs: Writable;
    type PrivateOutputs: Writable;
    type Proof;

    /// Generate a proof that the witness has been correctly generated according to the protocol, using the provided
    /// public and private inputs.
    fn prove_witness(
        &mut self,
        public_inputs: &Self::PublicInputs,
        private_inputs: &Self::PrivateInputs,
    ) -> Result<(Self::PublicOutputs, Self::PrivateOutputs, Self::Proof), WitnessProofError>;
}
