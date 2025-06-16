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

//----------------------------------------   Noir Delegate ------------------------------------------------------------
#[derive(Debug, Clone)]
pub struct NoirDelegate {
    #[cfg(debug_assertions)]
    dummy: DummyDelegate,
}

impl Default for NoirDelegate {
    fn default() -> Self {
        #[cfg(not(debug_assertions))]
        todo!();
        Self {
            #[cfg(debug_assertions)]
            dummy: DummyDelegate::default(),
        }
    }
}

impl ProposalVerifier for NoirDelegate {
    async fn verify_proposal(&self, _data: &NewChannelProposal) -> Result<(), InvalidProposal> {
        //TODO: Implement
        Err(InvalidProposal::TODO())
    }
}

impl GreaseInitializer for NoirDelegate {
    async fn generate_initial_proofs(
        &self,
        input_public: &Comm0PublicInputs,
        input_private: &Comm0PrivateInputs,
        metadata: &ChannelMetadata,
    ) -> Result<Proofs0, DelegateError> {
        info!("NoirDelegate: Generating initial proofs for {}", metadata.channel_id().name());

        let (major, minor, build) = get_bb_version().unwrap();
        info!("`bb` version: {}.{}.{}", major, minor, build);

        let nargo_version = get_nargo_version().unwrap();
        info!("`nargo` version: {}", nargo_version);

        let nonce_peer: BigUint = input_public.nonce_peer.clone().into();

        let blinding: BigUint = input_private.random_blinding.clone().into();

        let (witness_0, t_0, s_0) = make_witness0(&nonce_peer, &blinding)?;

        let a_1: BigUint = input_private.a1.clone().into();

        let (c_1, share_1, share_2) = feldman_secret_share_2_of_2(&witness_0, &a_1)?;

        let r_1: BigUint = input_private.r1.clone().into();

        let pubkey_peer: babyjubjub_rs::Point = input_public.pubkey_peer.try_into()?;

        let (fi_1, enc_1) = encrypt_message_ecdh(&share_1, &r_1, &pubkey_peer, None)?;

        let r_2: BigUint = input_private.r2.clone().into();

        let pubkey_kes: babyjubjub_rs::Point = metadata.kes_public_key().try_into()?;

        let (fi_2, enc_2) = encrypt_message_ecdh(&share_2, &r_2, &pubkey_kes, None)?;

        //NIZK DLEQ
        let blinding_dleq: BigUint = input_private.blinding_dleq.clone().into();

        let (
            challenge_bytes,
            response_baby_jub_jub,
            response_ed25519,
            r1,
            r2,
            response_div_baby_jub_jub,
            response_div_ed25519,
        ) = generate_dleqproof_simple(&witness_0, &blinding_dleq)?;

        //Verify
        {
            let res = verify_dleq_simple(
                &t_0,
                &s_0,
                &challenge_bytes,
                &response_baby_jub_jub,
                &response_ed25519,
                &r1,
                &r2,
            );
            match res {
                Ok(verified) => {
                    if verified {
                        info!("DLEQ verified");
                    } else {
                        info!("DLEQ failed to verify!");
                        return Err(DelegateError::DLEQVerify);
                    }
                }
                Err(e) => {
                    info!("DLEQ failed to verify with error: {e}");
                    return Err(DelegateError::BBError(e));
                }
            };
        }

        //Prove
        let proof_init = bb_prove_init(
            &a_1,
            &blinding,
            &blinding_dleq,
            &challenge_bytes,
            &enc_1,
            &enc_2,
            &nonce_peer,
            &r_1,
            &r_2,
            &left_pad_bytes_32_vec(&response_div_baby_jub_jub.to_bytes_be()),
            &left_pad_bytes_32_vec(&response_div_ed25519.to_bytes_be()),
            &response_baby_jub_jub,
            &left_pad_bytes_32_vec(&response_ed25519.to_bytes_be()),
            &share_1,
            &share_2,
            &witness_0,
            &t_0,
            &c_1,
            &fi_1,
            &fi_2,
            &pubkey_kes,
            &pubkey_peer,
        )?;

        //Verify
        let _verification = bb_verify_init(&proof_init)?;

        let p = Proofs0 {
            public_input: input_public.clone(),
            public_outputs: Comm0PublicOutputs {
                T_0: t_0.compress().into(),
                c_1: c_1.compress().into(),
                phi_1: fi_1.compress().into(),
                enc_1: enc_1.into(),
                phi_2: fi_2.compress().into(),
                enc_2: enc_2.into(),
                S_0: s_0.to_bytes().into(),
                c: challenge_bytes.into(),
                rho_bjj: response_baby_jub_jub.into(),
                rho_ed: response_ed25519.into(),
                R1: r1.compress().into(),
                R2: r2.to_bytes().into(),
            },
            private_outputs: Comm0PrivateOutputs {
                witness_0: witness_0.into(),
                peer_share: share_1.into(),
                kes_share: share_2.into(),
                delta_bjj: response_div_baby_jub_jub.into(),
                delta_ed: response_div_ed25519.into(),
            },
            proofs: proof_init,
        };

        Ok(p)
    }

    async fn verify_initial_proofs(
        &self,
        proof: &PublicProof0,
        metadata: &ChannelMetadata,
    ) -> Result<(), DelegateError> {
        info!("NoirDelegate: Verifying initial proofs for {}", metadata.channel_id().name());

        //Verify SNARKs
        let _verification = bb_verify_init(&proof.proofs)?;

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
    ) -> Result<UpdateProofs, DelegateError> {
        info!("NoirDelegate: Generating update proofs for {}", metadata.channel_id().name());

        let witness_im1 = witness.into();

        let t_im1 = get_scalar_to_point_bjj(&witness_im1);

        let (witness_i, t_i, s_i) = make_vcof(&witness_im1)?;

        //NIZK DLEQ
        let blinding_dleq = blinding_dleq.into();

        let (
            challenge_bytes,
            response_baby_jub_jub,
            response_ed25519,
            r1,
            r2,
            response_div_baby_jub_jub,
            response_div_ed25519,
        ) = generate_dleqproof_simple(&witness_i, &blinding_dleq)?;

        //Verify
        {
            let res = verify_dleq_simple(
                &t_i,
                &s_i,
                &challenge_bytes,
                &response_baby_jub_jub,
                &response_ed25519,
                &r1,
                &r2,
            );
            match res {
                Ok(verified) => {
                    if verified {
                        info!("DLEQ verified");
                    } else {
                        info!("DLEQ failed to verify!");
                        return Err(DelegateError::DLEQVerify);
                    }
                }
                Err(e) => {
                    info!("DLEQ failed to verify with error: {e}");
                    return Err(DelegateError::BBError(e));
                }
            };
        }

        //Prove
        let proof_update = bb_prove_update(
            &blinding_dleq,
            &challenge_bytes,
            &left_pad_bytes_32_vec(&response_div_baby_jub_jub.to_bytes_be()),
            &left_pad_bytes_32_vec(&response_div_ed25519.to_bytes_be()),
            &response_baby_jub_jub,
            &left_pad_bytes_32_vec(&response_ed25519.to_bytes_be()),
            &witness_i,
            &witness_im1,
            &t_i,
            &t_im1,
        )?;

        //Verify
        let _verification = bb_verify_update(&proof_update)?;

        let p = UpdateProofs {
            public_outputs: PublicUpdateOutputs {
                T_prev: t_im1.compress().into(),
                T_current: t_i.compress().into(),
                S_current: s_i.to_bytes().into(),
                challenge: challenge_bytes.into(),
                rho_bjj: response_baby_jub_jub.into(),
                rho_ed: response_ed25519.into(),
                R_bjj: r1.compress().into(),
                R_ed: r2.to_bytes().into(),
            },
            private_outputs: PrivateUpdateOutputs {
                update_count: index + 1u64,
                witness_i: witness_i.into(),
                delta_bjj: response_div_baby_jub_jub.into(),
                delta_ed: response_div_ed25519.into(),
            },
            proof: proof_update,
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
        let _verification = bb_verify_update(&proof.proof)?;

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

        todo!();

        Ok(())
    }
}

impl KesProver for NoirDelegate {
    async fn create_kes_proofs(
        &self,
        _channel_name: String,
        _cust_key: PartialEncryptedKey,
        _m_key: PartialEncryptedKey,
        _kes_pubkey: GenericPoint,
    ) -> Result<KesProof, DelegateError> {
        //TODO: Implement
        Err(DelegateError::TODO())
    }

    async fn verify_kes_proofs(
        &self,
        _channel_name: String,
        _c_key: PartialEncryptedKey,
        _m_key: PartialEncryptedKey,
        _kes_pubkey: &GenericPoint,
        _proofs: KesProof,
    ) -> Result<(), DelegateError> {
        //TODO: Implement
        Err(DelegateError::TODO())
    }
}

impl VerifiableSecretShare for NoirDelegate {
    fn split_secret_share(
        &self,
        _secret: &Curve25519Secret,
        _kes: &GenericPoint,
        _peer: &Curve25519PublicKey,
    ) -> Result<MultisigSplitSecrets, DelegateError> {
        //TODO: Implement
        Err(DelegateError::TODO())
    }

    fn verify_my_shards(&self, _share: &Curve25519Secret, _shards: &MultisigSplitSecrets) -> Result<(), DelegateError> {
        //TODO: Implement
        Err(DelegateError::TODO())
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
    ) {
        #[cfg(not(debug_assertions))]
        todo!();
        #[cfg(debug_assertions)]
        self.dummy.register_watcher(name, client, private_view_key, public_spend_key, birthday).await
    }
}

impl ChannelClosure for NoirDelegate {
    async fn verify_peer_witness(
        &self,
        _w: &GenericScalar,
        _c: &GenericPoint,
        metadata: &ChannelMetadata,
    ) -> Result<(), DelegateError> {
        #[cfg(not(debug_assertions))]
        todo!();
        #[cfg(debug_assertions)]
        self.dummy.verify_peer_witness(_w, _c, metadata).await
    }
}

impl GreaseChannelDelegate for NoirDelegate {}
