use crate::crypto::shard_encryption::EncryptedShard;
use crate::grease_protocol::dleq::{Dleq, DleqProof};
use crate::grease_protocol::error::WitnessError;
use crate::payment_channel::{ChannelRole, HasRole};
use ciphersuite::group::ff::Field;
use ciphersuite::group::Group;
use ciphersuite::{Ciphersuite, Ed25519};
use dalek_ff_group::{EdwardsPoint, Scalar as XmrScalar};
use grease_babyjubjub::BabyJubJub;
use modular_frost::curve::Curve as FrostCurve;
use rand_core::{CryptoRng, RngCore};
use std::ops::Neg;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub type BjjWitness = Witness<BabyJubJub>;

/// Each party's 1-of-2 spend key for the Grease channel multi-sig wallet is split into two shards:
/// - A peer key shard (XmrScalar), which is handed over to the peer.
/// - A KES key shard (C::F), which is a point on the KES curve corresponding to the local shard.
///
/// Each party also provides a proof that the KES shard and local shard correspond to the same secret scalar.
pub struct Witness<C: FrostCurve> {
    /// The 1-of-4 piece of the channel wallet's spend key that is held locally be each party.
    local_shard: XmrScalar,
    /// The 1-of-4 piece of the channel wallet's spend key that is handed to the peer.
    peer_shard: XmrScalar,
    /// The KES key shard, $\sigma_k$ is the corresponding key on the KES equivalent to the local shard.
    kes_shard: <C as Ciphersuite>::F,
    /// The point $\sigma_k \cdot G$ on the KES curve.
    kes_public_point: <C as Ciphersuite>::G,
    /// The role of this witness in the payment channel.
    channel_role: ChannelRole,
}

impl<C: FrostCurve> HasRole for Witness<C> {
    fn role(&self) -> ChannelRole {
        self.channel_role
    }
}

impl<C: FrostCurve> Zeroize for Witness<C> {
    fn zeroize(&mut self) {
        self.local_shard.zeroize();
        self.peer_shard.zeroize();
        self.kes_shard.zeroize();
    }
}

impl<C: FrostCurve> Drop for Witness<C> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<C: FrostCurve> ZeroizeOnDrop for Witness<C> {}

impl<C: FrostCurve> Witness<C> {
    /// Make this constructor private since you should only create witness via the DLEQ generation functions.
    pub(crate) fn new(
        local_shard: XmrScalar,
        peer_shard: XmrScalar,
        kes_shard: C::F,
        channel_role: ChannelRole,
    ) -> Self {
        let g = C::generator();
        let kes_public_point = g * kes_shard;
        Self { local_shard, peer_shard, kes_shard, channel_role, kes_public_point }
    }

    /// Reconstruct the full wallet spend key by adding the local and peer shards.
    pub fn reconstruct_wallet_spend_key(&self) -> XmrScalar {
        self.local_shard + self.peer_shard
    }
}

/// A convenience struct holding initial shard information
pub struct InitialShards<C, D>
where
    C: FrostCurve,
    D: Dleq<C>,
{
    /// The shard given to the peer, $\sigma_1$.
    peer_shard: XmrScalar,
    /// The peer shard handed to the KES, $\sigma_2$. There is an accompanying DLEQ proof that proces that the little-
    /// endian bit representation of this scalar matches the shard given to the KES in $\Xi_2$.
    kes_shard: XmrScalar,
    /// The KES shard on the KES curve, $\sigma_k$. Provided for convenience
    kes_shard_fk: <C as Ciphersuite>::F,
    /// The public commitment to the witness, $T_0 = \omega \cdot G$
    public_commitment: EdwardsPoint,
    /// The public commitment to the blinding factor, $C_0 = a \cdot G$
    blinding_commitment: EdwardsPoint,
    /// The DLEQ proof that the shard given to the KES corresponds to the shard in Monero.
    proof: D::Proof,
    /// The role of this witness in the payment channel.
    channel_role: ChannelRole,
}

impl<C: FrostCurve, D: Dleq<C>> ZeroizeOnDrop for InitialShards<C, D> {}

impl<C: FrostCurve, D: Dleq<C>> Zeroize for InitialShards<C, D> {
    fn zeroize(&mut self) {
        self.peer_shard.zeroize();
        self.kes_shard.zeroize();
        self.kes_shard_fk.zeroize();
        self.public_commitment.zeroize();
        self.blinding_commitment.zeroize();
    }
}

impl<C: FrostCurve, D: Dleq<C>> Drop for InitialShards<C, D> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<C, D> InitialShards<C, D>
where
    C: FrostCurve,
    D: Dleq<C>,
{
    pub fn reconstruct_wallet_spend_key(&self) -> XmrScalar {
        self.peer_shard + self.kes_shard
    }

    pub fn peer_shard(&self) -> &XmrScalar {
        &self.peer_shard
    }

    pub fn kes_shard(&self) -> &XmrScalar {
        &self.kes_shard
    }

    pub fn foreign_kes_shard(&self) -> &<C as Ciphersuite>::F {
        &self.kes_shard_fk
    }

    pub fn dleq_proof(&self) -> DleqProof<C, D> {
        let proof = self.proof.clone();
        let xmr_point = Ed25519::generator() * self.kes_shard;
        let foreign_point = C::generator() * &self.kes_shard_fk;
        DleqProof::new(proof, xmr_point, foreign_point)
    }

    pub fn blinding_commitment(&self) -> &EdwardsPoint {
        &self.blinding_commitment
    }

    pub fn encrypt_shards<R: RngCore + CryptoRng>(
        &self,
        peer: &EdwardsPoint,
        kes: &<C as Ciphersuite>::G,
        rng: &mut R,
    ) -> Result<(EncryptedShard<Ed25519>, EncryptedShard<C>), WitnessError> {
        let peer_shard = EncryptedShard::encrypt_shard(self.role(), false, &self.peer_shard, peer, rng);
        let kes_shard = EncryptedShard::encrypt_shard(self.role(), true, &self.kes_shard_fk, kes, rng);
        Ok((peer_shard, kes_shard))
    }
}

impl<C, D> HasRole for InitialShards<C, D>
where
    C: FrostCurve,
    D: Dleq<C>,
{
    fn role(&self) -> ChannelRole {
        self.channel_role
    }
}

/// Generate the initial shards from $\omega_0$, along with the DLEQ proof that the KES shard corresponds to the
/// Monero shard.
///
/// Since the DLEQ proof generation also produces a random scalar $\sigma_2$, we derive the blinding factor
/// as $a = \sigma_2 - 2 \cdot \omega_0$ and then compute $\sigma_1 = -(a + \omega_0)$.
/// This ensures that $\sigma_1 + \sigma_2 = \omega_0$ as required, and we have the necessary guarantees that $\sigma_2$
/// is a valid scalar on both chains.
pub fn generate_initial_shards<C, D, R>(
    role: ChannelRole,
    witness_0: &XmrScalar,
    rng: &mut R,
) -> Result<InitialShards<C, D>, WitnessError>
where
    R: RngCore + CryptoRng,
    C: FrostCurve,
    D: Dleq<C>,
{
    let (proof, (sigma2, fk)) = D::generate_dleq(rng).map_err(|e| e.into())?;
    let mut blinding_factor = sigma2 - witness_0.double();
    let public_commitment = EdwardsPoint::generator() * witness_0;
    let blinding_commitment = EdwardsPoint::generator() * &blinding_factor;
    let sigma1 = (blinding_factor + witness_0).neg();
    blinding_factor.zeroize();
    Ok(InitialShards {
        peer_shard: sigma1,
        kes_shard: sigma2,
        kes_shard_fk: fk,
        public_commitment,
        blinding_commitment,
        proof,
        channel_role: role,
    })
}
