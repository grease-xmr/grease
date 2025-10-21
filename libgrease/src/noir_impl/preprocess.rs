use crate::crypto::common_types::HashCommitment256;
use flexible_transcript::SecureDigest;
use modular_frost::curve::Curve;
use std::marker::PhantomData;

#[derive(Clone)]
pub struct MerchantCommitments<D: SecureDigest> {
    commitments: HashCommitment256<D>,
}

#[derive(Debug, Clone)]
pub struct GreasePreprocessor<C: Curve> {
    _phantom: PhantomData<C>,
}

// impl<C, D> WitnessProofPreprocess<C, D> for GreasePreprocessor<C>
// where
//     C: Curve,
//     D: SecureDigest + Send + Clone,
// {
//     type PublicWitnessProofInfo = ();
//     type CommitmentContext = ();
//     type WitnessGenerator = ();
//
//     fn generate_witness_proof_data<R: RngCore + CryptoRng>(&self, rng: &mut R, witness: &ZkWitness<C>, ctx: &Self::CommitmentContext) -> Result<Self::PublicWitnessProofInfo, WitnessError> {
//         todo!()
//     }
// }

pub struct GreaseProver<C: Curve> {
    _phantom_curve: PhantomData<C>,
}

// impl<C> ProveWitness for GreaseProver<C>
// where
//     C: Curve,
// {
//     type PublicInputs = ();
//     type PrivateInputs = ();
//     type PublicOutputs = ();
//     type PrivateOutputs = ();
//     type Proof = ();
//
//     fn prove_witness(&mut self, public_inputs: &Self::PublicInputs, private_inputs: &Self::PrivateInputs) -> (Self::PublicOutputs, Self::PrivateOutputs, Self::Proof) {
//         todo!()
//     }
// }
