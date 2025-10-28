use crate::crypto::dleq::{Dleq, DleqProof};
use crate::crypto::shard_encryption::{EncryptedShard, Shard};
use crate::error::ReadError;
use crate::grease_protocol::error::WitnessError;
use crate::grease_protocol::open_channel::OpenProtocolError;
use crate::grease_protocol::utils::{read_group_element, write_group_element};
use crate::payment_channel::{ChannelRole, HasRole};
use crate::XmrPoint;
use ciphersuite::group::ff::Field;
use ciphersuite::group::Group;
use ciphersuite::{Ciphersuite, Ed25519};
use dalek_ff_group::{EdwardsPoint, Scalar as XmrScalar};
use grease_babyjubjub::BabyJubJub;
use modular_frost::curve::Curve as FrostCurve;
use modular_frost::sign::Writable;
use rand_core::{CryptoRng, RngCore};
use std::io::{Read, Write};
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

    /// Returns the point $\sigma_k \cdot G$ on the KES curve.
    pub fn kes_public_point(&self) -> &<C as Ciphersuite>::G {
        &self.kes_public_point
    }
}

/// A convenience struct holding initial shard information
pub struct InitialShards<C, D>
where
    C: FrostCurve,
    D: Dleq<C>,
{
    /// The shard given to the peer, $\sigma_1$.
    peer_shard: Shard<Ed25519>,
    /// The peer shard handed to the KES, $\sigma_2$. There is an accompanying DLEQ proof that proces that the little-
    /// endian bit representation of this scalar matches the shard given to the KES in $\Xi_2$.
    kes_shard: Shard<Ed25519>,
    /// The KES shard on the KES curve, $\sigma_k$. Provided for convenience
    kes_shard_fk: Shard<C>,
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
    pub fn new<R: RngCore + CryptoRng>(
        rng: &mut R,
        role: ChannelRole,
        witness_0: &XmrScalar,
    ) -> Result<Self, WitnessError> {
        let (proof, (sigma2, fk)) = D::generate_dleq(rng).map_err(|e| e.into())?;
        let mut blinding_factor = sigma2 - witness_0.double();
        let public_commitment = Ed25519::generator() * witness_0;
        let blinding_commitment = Ed25519::generator() * &blinding_factor;
        let sigma1 = (blinding_factor + witness_0).neg();
        let peer_shard = Shard::new(sigma1, false, role.other());
        let kes_shard = Shard::new(sigma2, true, role);
        let kes_shard_fk = Shard::new(fk, true, role);
        blinding_factor.zeroize();
        Ok(InitialShards {
            peer_shard,
            kes_shard,
            kes_shard_fk,
            public_commitment,
            blinding_commitment,
            proof,
            channel_role: role,
        })
    }

    pub fn reconstruct_wallet_spend_key(&self) -> XmrScalar {
        *self.peer_shard.shard() + self.kes_shard.shard()
    }

    pub fn peer_shard(&self) -> &Shard<Ed25519> {
        &self.peer_shard
    }

    pub fn kes_shard(&self) -> &Shard<Ed25519> {
        &self.kes_shard
    }

    pub fn foreign_kes_shard(&self) -> &Shard<C> {
        &self.kes_shard_fk
    }

    pub fn dleq_proof(&self) -> DleqProof<C, D> {
        let proof = self.proof.clone();
        let xmr_point = Ed25519::generator() * self.kes_shard.shard();
        let foreign_point = C::generator() * self.kes_shard_fk.shard();
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
        let peer_shard = EncryptedShard::encrypt_shard(&self.peer_shard, peer, rng);
        let kes_shard = EncryptedShard::encrypt_shard(&self.kes_shard_fk, kes, rng);
        Ok((peer_shard, kes_shard))
    }

    /// Generates a new public Shard record that can be shared with the peer.
    ///
    /// As part of this, this function:
    /// 1. encrypts both the peer shard and the KES shard for the recipient,
    /// 2. generates a DLEQ proof that the KES shard corresponds to the Monero shard,
    /// 3. packages the public commitments needed to verify the shards.
    pub fn generate_public_shard_info<R: RngCore + CryptoRng>(
        &self,
        peer_public_key: &XmrPoint,
        kes_public_key: &<C as Ciphersuite>::G,
        rng: &mut R,
    ) -> PublicShardInfo<C, D> {
        let dleq_proof = self.dleq_proof();
        let peer_shard = EncryptedShard::<Ed25519>::encrypt_shard(&self.peer_shard, peer_public_key, rng);
        let kes_shard = EncryptedShard::encrypt_shard(&self.kes_shard_fk, kes_public_key, rng);
        PublicShardInfo {
            channel_role: self.role(),
            peer_shard,
            kes_shard,
            public_witness: self.public_commitment.clone(),
            blinding_commitment: self.blinding_commitment.clone(),
            dleq_proof,
        }
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
    let public_commitment = Ed25519::generator() * witness_0;
    let blinding_commitment = Ed25519::generator() * &blinding_factor;
    let sigma1 = (blinding_factor + witness_0).neg();
    blinding_factor.zeroize();
    let peer_shard = Shard::new(sigma1, false, role.other());
    let kes_shard = Shard::new(sigma2, true, role);
    let kes_shard_fk = Shard::new(fk, true, role);
    Ok(InitialShards {
        peer_shard,
        kes_shard,
        kes_shard_fk,
        public_commitment,
        blinding_commitment,
        proof,
        channel_role: role,
    })
}

pub struct PublicShardInfo<C: FrostCurve, D: Dleq<C>> {
    /// The role of this witness in the payment channel.
    channel_role: ChannelRole,
    /// The encrypted shard given to the peer, $\Xi_1$.
    peer_shard: EncryptedShard<Ed25519>,
    /// The peer shard handed to the KES, $\Xi_2$.
    kes_shard: EncryptedShard<C>,
    /// The public commitment to the witness, $T_0 = \omega \cdot G$
    public_witness: EdwardsPoint,
    /// The public commitment to the blinding factor, $C_0 = a \cdot G$
    blinding_commitment: EdwardsPoint,
    /// The DLEQ proof that the shard given to the KES corresponds to the shard in Monero.
    dleq_proof: DleqProof<C, D>,
}

impl<C: FrostCurve, D: Dleq<C>> PublicShardInfo<C, D> {
    pub fn peer_shard(&self) -> &EncryptedShard<Ed25519> {
        &self.peer_shard
    }

    pub fn decrypt_and_verify(&self, secret: &XmrScalar) -> Result<Shard<Ed25519>, WitnessError> {
        let shard = self.peer_shard.decrypt_shard(secret);
        match self.verify_peer_shard(&shard) {
            true => Ok(shard),
            false => Err(WitnessError::IncorrectShard),
        }
    }

    /// Verify the that the peer's shard corresponds to the public witness point,
    /// $T_0 = \omega_0 \cdot G$,
    /// and the blinding_commitment commitment $C_0 = a \cdot G$.
    pub fn verify_peer_shard(&self, shard: &Shard<Ed25519>) -> bool {
        // peer shard is sigma_1, so verification is G * sigma_1 + (a * G + omega_0 * G) == 0
        let lhs = Ed25519::generator() * shard.shard();
        let rhs = -(self.blinding_commitment + self.public_witness);
        lhs == rhs
    }

    /// Verify that the KES shard (using Ed25519 coordinates) corresponds to the public witness point,
    /// $T_0 = \omega_0 \cdot G$, and the blinding_commitment commitment $C_0 = a \cdot G$.
    fn verify_kes_shard(&self, shard: Shard<Ed25519>) -> bool {
        // kes shard is sigma_2, so verification is G * sigma_2 ?== 2T0 + C0
        let lhs = Ed25519::generator() * shard.shard();
        let rhs = self.public_witness.double() + self.blinding_commitment;
        lhs == rhs
    }

    pub fn kes_shard(&self) -> &EncryptedShard<C> {
        &self.kes_shard
    }

    pub fn public_commitment(&self) -> &EdwardsPoint {
        &self.public_witness
    }

    pub fn blinding_commitment(&self) -> &EdwardsPoint {
        &self.blinding_commitment
    }

    pub fn dleq_proof(&self) -> &DleqProof<C, D> {
        &self.dleq_proof
    }

    pub fn verify_dleq_proof(&self) -> Result<(XmrPoint, C::G), OpenProtocolError> {
        if !self.dleq_proof.verify() {
            return Err(OpenProtocolError::InvalidDataFromPeer("DLEQ proof verification failed".into()));
        }
        let xmr_point = self.dleq_proof.xmr_point;
        let foreign_point = self.dleq_proof.foreign_point;
        Ok((xmr_point, foreign_point))
    }

    pub fn read<R: Read>(reader: &mut R) -> Result<Self, OpenProtocolError> {
        let channel_role = ChannelRole::read(reader)?;
        let peer_shard = EncryptedShard::<Ed25519>::read(reader)?;
        let kes_shard = EncryptedShard::<C>::read(reader)?;
        let public_commitment = read_group_element::<Ed25519, _>(reader)
            .map_err(|e| ReadError::new("PublicShardInfo.public_commitment", e.to_string()))?;
        let blinding_commitment = read_group_element::<Ed25519, _>(reader)
            .map_err(|e| ReadError::new("PublicShardInfo.blinding_commitment", e.to_string()))?;
        let dleq_proof = DleqProof::<C, D>::read(reader)
            .map_err(|e| OpenProtocolError::InvalidDataFromPeer(format!("Failed to read DLEQ proof: {}", e)))?;
        Ok(Self {
            channel_role,
            peer_shard,
            kes_shard,
            public_witness: public_commitment,
            blinding_commitment,
            dleq_proof,
        })
    }
}

impl<C: FrostCurve, D: Dleq<C>> HasRole for PublicShardInfo<C, D> {
    fn role(&self) -> ChannelRole {
        self.channel_role
    }
}

impl<C: FrostCurve, D: Dleq<C>> Writable for PublicShardInfo<C, D> {
    fn write<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        self.channel_role.write(writer)?;
        self.peer_shard.write(writer)?;
        self.kes_shard.write(writer)?;
        write_group_element::<Ed25519, _>(writer, &self.public_witness)?;
        write_group_element::<Ed25519, _>(writer, &self.blinding_commitment)?;
        self.dleq_proof.write(writer)?;
        Ok(())
    }
}
