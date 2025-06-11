use crate::channel_metadata::ChannelMetadata;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

pub trait SecretKey: Clone + Send + Sync + Serialize + for<'de> Deserialize<'de> {}

pub trait PublicKey: Clone + PartialEq + Eq + Send + Sync + Serialize + for<'de> Deserialize<'de> {
    type SecretKey: SecretKey + Debug;

    fn keypair<R: CryptoRng + RngCore>(rng: &mut R) -> (Self::SecretKey, Self);
    fn from_secret(secret_key: &Self::SecretKey) -> Self;
}

pub trait ZkProofOutput {
    type PrivateOutputs;
    type PublicOutputs;
    type Proofs;

    fn private_outputs(&self) -> &Self::PrivateOutputs;
    fn public_outputs(&self) -> &Self::PublicOutputs;
    fn proofs(&self) -> &Self::Proofs;
}

pub trait ZkInput {
    type PrivateInputs;
    type PublicInputs;

    fn private_inputs(&self) -> &Self::PrivateInputs;
    fn public_inputs(&self) -> &Self::PublicInputs;
}

pub trait ZkProver {
    type Input: ZkInput;
    type Outputs: ZkProofOutput;
    async fn prove(&self, inputs: Self::Input, context: &ChannelMetadata) -> Self::Outputs;
}
