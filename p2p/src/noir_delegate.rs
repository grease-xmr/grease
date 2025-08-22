use crate::delegates::*;
use crate::message_types::NewChannelProposal;
use crate::Client;
use circuits::*;
use curve25519_dalek::montgomery::MontgomeryPoint;
use libgrease::amount::MoneroDelta;
use libgrease::channel_metadata::ChannelMetadata;
use libgrease::crypto::keys::{Curve25519PublicKey, Curve25519Secret};
use libgrease::crypto::zk_objects::AdaptedSignature;
use libgrease::crypto::zk_objects::GenericScalar;
use libgrease::crypto::zk_objects::{
    Comm0PrivateInputs, Comm0PrivateOutputs, Comm0PublicInputs, Comm0PublicOutputs, GenericPoint, KesProof,
    PartialEncryptedKey, PrivateUpdateOutputs, Proofs0, PublicProof0, PublicUpdateOutputs, PublicUpdateProof,
    UpdateProofs,
};
use libgrease::monero::data_objects::MultisigSplitSecrets;
use libgrease::state_machine::error::InvalidProposal;
use log::*;
use num_bigint::BigUint;
use std::path::Path;
use std::time::Duration;

//----------------------------------------   Noir Delegate ------------------------------------------------------------
#[derive(Debug, Clone)]
pub struct NoirDelegate {
    dummy: DummyDelegate,
}

impl Default for NoirDelegate {
    fn default() -> Self {
        Self { dummy: DummyDelegate::default() }
    }
}

impl ProposalVerifier for NoirDelegate {
    async fn verify_proposal(&self, _data: &NewChannelProposal) -> Result<(), InvalidProposal> {
        info!("NoirDelegate: Verifying proposal with key {}", _data.seed.key_id);

        //TODO: Implement basic checks
        Ok(())
    }
}

impl GreaseInitializer for NoirDelegate {
    async fn generate_initial_proofs(
        &self,
        input_public: &Comm0PublicInputs,
        input_private: &Comm0PrivateInputs,
        metadata: &ChannelMetadata,
        nargo_path: &Path,
    ) -> Result<Proofs0, DelegateError> {
        info!("NoirDelegate: Generating initial proofs for {}", metadata.channel_id().name());

        let nonce_peer: BigUint = input_public.nonce_peer.clone().into();
        let blinding: BigUint = input_private.random_blinding.clone().into();
        let a_1: BigUint = input_private.a1.clone().into();
        let r_1: BigUint = input_private.r1.clone().into();
        let public_key_bjj_peer: babyjubjub_rs::Point = input_public.public_key_bjj_peer.try_into()?;
        let r_2: BigUint = input_private.r2.clone().into();
        let kes_public_key: babyjubjub_rs::Point = metadata.kes_public_key().try_into()?;
        let blinding_dleq: BigUint = input_private.blinding_dleq.clone().into();

        let initial_proof = circuits::generate_initial_proofs(
            &nonce_peer,
            &blinding,
            &a_1,
            &r_1,
            &public_key_bjj_peer,
            &r_2,
            &kes_public_key,
            &blinding_dleq,
            &nargo_path,
        )?;

        let p = Proofs0 {
            public_input: input_public.clone(),
            public_outputs: Comm0PublicOutputs {
                T_0: initial_proof.t_0.compress().into(),
                c_1: initial_proof.c_1.compress().into(),
                phi_1: initial_proof.phi_1.compress().into(),
                enc_1: initial_proof.enc_1.into(),
                phi_2: initial_proof.phi_2.compress().into(),
                enc_2: initial_proof.enc_2.into(),
                S_0: initial_proof.s_0.to_bytes().into(),
                c: initial_proof.challenge_bytes.into(),
                rho_bjj: initial_proof.rho_bjj.into(),
                rho_ed: initial_proof.rho_ed.into(),
                R1: initial_proof.r1.compress().into(),
                R2: initial_proof.r2.to_bytes().into(),
            },
            private_outputs: Comm0PrivateOutputs {
                witness_0: initial_proof.witness_0.into(),
                peer_share: initial_proof.share_1.into(),
                kes_share: initial_proof.share_2.into(),
                delta_bjj: initial_proof.response_div_baby_jub_jub.into(),
                delta_ed: initial_proof.response_div_ed25519.into(),
            },
            zero_knowledge_proof_init: initial_proof.zero_knowledge_proof_init,
        };

        Ok(p)
    }

    async fn verify_initial_proofs(
        &self,
        nonce_peer: &BigUint,
        public_key_bjj_peer: &babyjubjub_rs::Point,
        kes_public_key: &babyjubjub_rs::Point,
        proof: &PublicProof0,
        metadata: &ChannelMetadata,
    ) -> Result<(), DelegateError> {
        info!("NoirDelegate: Verifying initial proofs for {}", metadata.channel_id().name());

        //Verify SNARKs
        let public_init = PublicInit::new(
            &babyjubjub_rs::Point::try_from(&proof.public_outputs.T_0)?,
            &babyjubjub_rs::Point::try_from(&proof.public_outputs.c_1)?,
            &babyjubjub_rs::Point::try_from(&proof.public_outputs.phi_1)?,
            &proof.public_outputs.enc_1.into(),
            &babyjubjub_rs::Point::try_from(&proof.public_outputs.phi_2)?,
            &proof.public_outputs.enc_2.into(),
            &proof.public_outputs.S_0.into(),
            &proof.public_outputs.c.into(),
            &proof.public_outputs.rho_bjj.into(),
            &proof.public_outputs.rho_ed.into(),
            &babyjubjub_rs::Point::try_from(&proof.public_outputs.R1)?,
            &proof.public_outputs.R2.into(),
        );

        let verification = bb_verify_init(
            nonce_peer,
            &public_key_bjj_peer,
            &kes_public_key,
            &public_init,
            &proof.zero_knowledge_proof_init,
        )?;
        if !verification {
            return Err(DelegateError::Verify);
        }

        //Verify DLEQ
        let t_0: babyjubjub_rs::Point =
            proof.public_outputs.T_0.clone().try_into().map_err(|e| DelegateError::String(e))?;
        let s_0: MontgomeryPoint = proof.public_outputs.S_0.clone().into();
        let challenge_bytes: [u8; 32] = proof.public_outputs.c.clone().into();
        let response_baby_jub_jub: BigUint = proof.public_outputs.rho_bjj.clone().into();
        let response_ed25519: BigUint = proof.public_outputs.rho_ed.clone().into();
        let r1: babyjubjub_rs::Point =
            proof.public_outputs.R1.clone().try_into().map_err(|e| DelegateError::String(e))?;
        let r2: MontgomeryPoint = proof.public_outputs.R2.clone().into();

        let verified = verify_dleq_simple(
            &t_0,
            &s_0,
            &challenge_bytes,
            &response_baby_jub_jub,
            &response_ed25519,
            &r1,
            &r2,
        )?;
        if verified {
            info!("DLEQ verified");
        } else {
            info!("DLEQ failed to verify!");
            return Err(DelegateError::DLEQVerify);
        }

        Ok(())
    }
}

impl Updater for NoirDelegate {
    async fn generate_update(
        &self,
        index: u64,
        _delta: MoneroDelta,
        witness: &GenericScalar,
        blinding_dleq: &GenericScalar,
        metadata: &ChannelMetadata,
        nargo_path: &Path,
    ) -> Result<UpdateProofs, DelegateError> {
        info!("NoirDelegate: Generating update proofs for {}", metadata.channel_id().name());

        let witness_im1: BigUint = witness.into();
        let blinding_dleq: BigUint = blinding_dleq.into();

        let t_im1: babyjubjub_rs::Point = get_scalar_to_point_bjj(&witness_im1);

        let update_proof = circuits::generate_update(&witness_im1, &blinding_dleq, &t_im1, nargo_path)?;

        let p = UpdateProofs {
            public_outputs: PublicUpdateOutputs {
                T_prev: t_im1.compress().into(),
                T_current: update_proof.t_current.compress().into(),
                S_current: update_proof.s_current.to_bytes().into(),
                challenge: update_proof.challenge_bytes.into(),
                rho_bjj: update_proof.rho_bjj.into(),
                rho_ed: update_proof.rho_ed.into(),
                R_bjj: update_proof.r_bjj.compress().into(),
                R_ed: update_proof.r_ed.to_bytes().into(),
            },
            private_outputs: PrivateUpdateOutputs {
                update_count: index + 1u64,
                witness_i: update_proof.witness_i.into(),
                delta_bjj: update_proof.response_div_baby_jub_jub.into(),
                delta_ed: update_proof.response_div_ed25519.into(),
            },
            zero_knowledge_proof_update: update_proof.zero_knowledge_proof_update,
        };

        Ok(p)
    }

    async fn verify_update(
        &self,
        _index: u64,
        _delta: MoneroDelta,
        proof: &PublicUpdateProof,
        metadata: &ChannelMetadata,
    ) -> Result<(), DelegateError> {
        info!("NoirDelegate: Verifying update proofs for {}", metadata.channel_id().name());

        //Verify SNARKs
        let public_update = PublicUpdate::new(
            &babyjubjub_rs::Point::try_from(&proof.public_outputs.T_prev)?,
            &babyjubjub_rs::Point::try_from(&proof.public_outputs.T_current)?,
            &proof.public_outputs.S_current.into(),
            &proof.public_outputs.challenge.into(),
            &proof.public_outputs.rho_bjj.into(),
            &proof.public_outputs.rho_ed.into(),
            &babyjubjub_rs::Point::try_from(&proof.public_outputs.R_bjj)?,
            &proof.public_outputs.R_ed.into(),
        );

        let verification = bb_verify_update(&public_update, &proof.zero_knowledge_proof_update)?;
        if !verification {
            return Err(DelegateError::Verify);
        }

        //Verify DLEQ
        let t_i: babyjubjub_rs::Point =
            proof.public_outputs.T_current.clone().try_into().map_err(|e| DelegateError::String(e))?;
        let s_i: MontgomeryPoint = proof.public_outputs.S_current.clone().into();
        let challenge_bytes: [u8; 32] = proof.public_outputs.challenge.clone().into();
        let response_baby_jub_jub: BigUint = proof.public_outputs.rho_bjj.clone().into();
        let response_ed25519: BigUint = proof.public_outputs.rho_ed.clone().into();
        let r1: babyjubjub_rs::Point =
            proof.public_outputs.R_bjj.clone().try_into().map_err(|e| DelegateError::String(e))?;
        let r2: MontgomeryPoint = proof.public_outputs.R_ed.clone().into();

        let verified = verify_dleq_simple(
            &t_i,
            &s_i,
            &challenge_bytes,
            &response_baby_jub_jub,
            &response_ed25519,
            &r1,
            &r2,
        )?;
        if verified {
            info!("DLEQ verified");
        } else {
            info!("DLEQ failed to verify!");
            return Err(DelegateError::DLEQVerify);
        }

        Ok(())
    }

    async fn verify_adapted_signature(
        &self,
        _index: u64,
        _proof: &PublicUpdateProof,
        _sig: &AdaptedSignature,
    ) -> Result<(), DelegateError> {
        info!("NoirDelegate: Verifying adapted signature");

        //TODO: Implement
        error!("TODO: NoirDelegate: Verifying adapted signature");
        Ok(())
    }
}

impl KesProver for NoirDelegate {
    async fn create_kes_proofs(
        &self,
        _channel_name: String,
        _cust_key: PartialEncryptedKey,
        _m_key: PartialEncryptedKey,
        _kes_public_key: GenericPoint,
    ) -> Result<KesProof, DelegateError> {
        info!("NoirDelegate: Creating KES proofs");

        //TODO: Implement
        error!("TODO: create_kes_proofs");
        todo!();
    }

    async fn verify_kes_proofs(
        &self,
        _channel_name: String,
        _c_key: PartialEncryptedKey,
        _m_key: PartialEncryptedKey,
        __kes_public_key: &GenericPoint,
        _proofs: KesProof,
    ) -> Result<(), DelegateError> {
        info!("NoirDelegate: Verifying KES proofs");

        //TODO: Implement
        error!("TODO: verify_kes_proofs");
        todo!();
    }
}

impl VerifiableSecretShare for NoirDelegate {
    fn split_secret_share(
        &self,
        _secret: &Curve25519Secret,
        _kes: &GenericPoint,
        _peer: &Curve25519PublicKey,
    ) -> Result<MultisigSplitSecrets, DelegateError> {
        info!("NoirDelegate: Splitting secret share");

        //TODO: Implement
        error!("TODO: split_secret_share");
        todo!();
    }

    fn verify_my_shards(&self, _share: &Curve25519Secret, _shards: &MultisigSplitSecrets) -> Result<(), DelegateError> {
        info!("NoirDelegate: Verifying my shards");

        //TODO: Implement
        error!("TODO: verify_my_shards");
        todo!();
    }
}

impl FundChannel for NoirDelegate {
    async fn register_watcher(
        &self,
        name: String,
        client: Client,
        private_view_key: Curve25519Secret,
        public_spend_key: Curve25519PublicKey,
        birthday: Option<u64>,
        poll_interval: Duration,
    ) -> Result<(), DelegateError> {
        self.dummy.register_watcher(name, client, private_view_key, public_spend_key, birthday, poll_interval).await
    }
}

impl ChannelClosure for NoirDelegate {
    async fn verify_peer_witness(
        &self,
        _w: &GenericScalar,
        _c: &GenericPoint,
        metadata: &ChannelMetadata,
    ) -> Result<(), DelegateError> {
        self.dummy.verify_peer_witness(_w, _c, metadata).await
    }
}

impl GreaseChannelDelegate for NoirDelegate {}
