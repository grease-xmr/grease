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

        // nonce_peer = "867303429418806279313526868407228138995734763278095857482747693606556032536"
        // blinding = "1194608745245961475824979247056446722984763446987071492294235640987034156744"
        // witness_0 = "2300713427460276953780870141649614997452366291219964647997231433928304383861"
        // [T_0]
        //   x="0x0ef59b243ee8819f82a6da86c875508d0e786c7453ef791beae4fcf0ae88c933"
        //   y="0x2a8a23239d91f7c2ff94c2b094bb91ff6751c03b76fd69a8770186628753ad4f"
        // let nonce_peer: BigUint = BigUint::parse_bytes(b"867303429418806279313526868407228138995734763278095857482747693606556032536", 10).unwrap();
        let nonce_peer: BigUint = input_public.nonce_peer.clone().into();

        // let blinding = BigUint::parse_bytes(b"1194608745245961475824979247056446722984763446987071492294235640987034156744", 10).unwrap();
        let blinding: BigUint = input_private.random_blinding.clone().into();

        let (witness_0, t_0, s_0) = make_witness0(&nonce_peer, &blinding).unwrap();

        assert_eq!(
            witness_0,
            BigUint::parse_bytes(
                b"2300713427460276953780870141649614997452366291219964647997231433928304383861",
                10
            )
            .unwrap()
        );
        assert_eq!(
            t_0.x.to_string(),
            "Fr(0x0ef59b243ee8819f82a6da86c875508d0e786c7453ef791beae4fcf0ae88c933)"
        );
        assert_eq!(
            t_0.y.to_string(),
            "Fr(0x2a8a23239d91f7c2ff94c2b094bb91ff6751c03b76fd69a8770186628753ad4f)"
        );

        // a_1 = "70143195093839929636068986763442859911856008756585124285077086015668936144"
        // let a_1: BigUint = BigUint::parse_bytes(b"70143195093839929636068986763442859911856008756585124285077086015668936144", 10).unwrap();
        let a_1: BigUint = input_private.a1.clone().into();

        // share_1 = "365173736425792519363861589744101528712591672182017486917907141004474053036"
        // share_2 = "1935539691034484434417008551905513468739774619037947161079324292923830330825"
        // [c_1]
        //   x="0x2c5e461e413c866bcf8a62d8cdff41e557f79c0629b7383dbe91b18096e09540"
        //   y="0x13a5434cda8f9d6c64724d2171ac4f9bb873b26c175e87c5dd5473b502b85312"

        let (c_1, share_1, share_2) = feldman_secret_share_2_of_2(&witness_0, &a_1).unwrap();

        assert_eq!(
            c_1.x.to_string(),
            "Fr(0x2c5e461e413c866bcf8a62d8cdff41e557f79c0629b7383dbe91b18096e09540)"
        );
        assert_eq!(
            c_1.y.to_string(),
            "Fr(0x13a5434cda8f9d6c64724d2171ac4f9bb873b26c175e87c5dd5473b502b85312)"
        );
        assert_eq!(
            share_1,
            BigUint::parse_bytes(
                b"365173736425792519363861589744101528712591672182017486917907141004474053036",
                10
            )
            .unwrap()
        );
        assert_eq!(
            share_2,
            BigUint::parse_bytes(
                b"1935539691034484434417008551905513468739774619037947161079324292923830330825",
                10
            )
            .unwrap()
        );

        // r_1 = "2422852404430683902810753577573102653260911761556849713949680014072177383950"
        // [pubkey_peer]
        //   x="0x1529458aa75b635e1f96ece9c2ef9aa44cb019f519a979cd85fce0080b8e2417"
        //   y="0x033da4d76cfae27f8360bd4681609681fdcb09ece4ead5c88113c143a9a20c69"
        // let r_1: BigUint = BigUint::parse_bytes(b"2422852404430683902810753577573102653260911761556849713949680014072177383950", 10).unwrap();
        let r_1: BigUint = input_private.r1.clone().into();

        // let pubkey_peer: Point = GetBJJPointFromHexPoints(
        //         "1529458aa75b635e1f96ece9c2ef9aa44cb019f519a979cd85fce0080b8e2417",
        //         "033da4d76cfae27f8360bd4681609681fdcb09ece4ead5c88113c143a9a20c69");
        let private_key_peer: BigUint = BigUint::parse_bytes(b"1", 10).unwrap();
        let pubkey_peer = get_bjjpoint_from_scalar(&private_key_peer);

        // enc_1 = "1220122097491108282229984040904504012545109624322527294624787674340936491877"
        // [fi_1]
        //   x="0x09d58da0c2ab2b11cc1f8579f739e7e463235185753ab5d4719e8db6aa476a23"
        //   y="0x1bc9eb7eab983bfd017433c4ed524b8bfde9db0abda7c7940e9c43822268b4ce"

        let (fi_1, enc_1) = encrypt_message_ecdh(&share_1, &r_1, &pubkey_peer, &private_key_peer).unwrap();

        assert_eq!(
            fi_1.x.to_string(),
            "Fr(0x09d58da0c2ab2b11cc1f8579f739e7e463235185753ab5d4719e8db6aa476a23)"
        );
        assert_eq!(
            fi_1.y.to_string(),
            "Fr(0x1bc9eb7eab983bfd017433c4ed524b8bfde9db0abda7c7940e9c43822268b4ce)"
        );
        // assert_eq!(enc_1, BigUint::parse_bytes(b"1220122097491108282229984040904504012545109624322527294624787674340936491877", 10).unwrap());

        // r_2 = "2044680745167638013838014513951032949701446715960700123553928808460151041757"
        // let r_2: BigUint = BigUint::parse_bytes(b"2044680745167638013838014513951032949701446715960700123553928808460151041757", 10).unwrap();
        let r_2: BigUint = input_private.r2.clone().into();

        // [pubkey_KES]
        //   x="0x12f87860325f2ba2d84d9332a0bedc25edd93736776e818d8993a1da678958bf"
        //   y="0x105900362a575a29943602c90d432768f271ffb8f06af513dcd81d05c3a2c4a3"
        let private_key_kes: BigUint = BigUint::parse_bytes(b"1", 10).unwrap();
        let pubkey_kes = get_bjjpoint_from_scalar(&private_key_kes);

        // enc_2 = "321084871571726505169933431313947177118001726846734186078876149279016535274"
        // [fi_2]
        //   x="0x0ac31edd3af81f177137239a950c8f70662c4b6fbbeec57dae63bfcb61d931ee"
        //   y="0x1975e7e9cbe0f2ed7a06a09e320036ea1a73862ee2614d2a9a6452d8f7c9aff0"

        let (fi_2, enc_2) = encrypt_message_ecdh(&share_2, &r_2, &pubkey_kes, &private_key_kes).unwrap();

        assert_eq!(
            fi_2.x.to_string(),
            "Fr(0x0ac31edd3af81f177137239a950c8f70662c4b6fbbeec57dae63bfcb61d931ee)"
        );
        assert_eq!(
            fi_2.y.to_string(),
            "Fr(0x1975e7e9cbe0f2ed7a06a09e320036ea1a73862ee2614d2a9a6452d8f7c9aff0)"
        );
        // assert_eq!(enc_2, BigUint::parse_bytes(b"321084871571726505169933431313947177118001726846734186078876149279016535274", 10).unwrap());

        //NIZK DLEQ
        //witness_0 = "2300713427460276953780870141649614997452366291219964647997231433928304383861"
        //blinding_DLEQ = "2124419834422738134599198304606394937234744825834207315619962749021962198236"
        // let blinding_DLEQ: BigUint = BigUint::parse_bytes(b"2124419834422738134599198304606394937234744825834207315619962749021962198236", 10).unwrap();
        let blinding_dleq: BigUint = input_private.blinding_dleq.clone().into();

        // challenge_bytes = ["70", "175", "116", "95", "222", "182", "167", "46", "250", "55", "224", "163", "151", "38", "249", "118", "164", "60", "161", "13", "51", "180", "44", "130", "88", "112", "39", "95", "199", "211", "205", "170"]
        // response_div_BabyJubJub = ["59", "112", "95", "49", "212", "50", "147", "95", "65", "212", "106", "163", "115", "202", "43", "9", "237", "146", "95", "42", "154", "192", "240", "97", "48", "16", "62", "89", "208", "218", "231", "122"]
        // response_div_ed25519 = ["22", "120", "183", "234", "225", "42", "119", "48", "136", "156", "27", "246", "45", "74", "146", "179", "21", "185", "166", "143", "57", "60", "44", "4", "13", "124", "185", "146", "8", "243", "13", "71"]
        // response_BabyJubJub = "1211850493455143960510207598095808109935776728332172864532400139827493102076"
        // response_ed25519 = ["3", "121", "103", "121", "181", "67", "31", "235", "146", "100", "96", "34", "64", "223", "93", "249", "211", "176", "61", "162", "126", "47", "95", "136", "157", "106", "192", "62", "33", "72", "152", "27"]

        let (
            challenge_bytes,
            response_baby_jub_jub,
            response_ed25519,
            r1,
            r2,
            response_div_baby_jub_jub,
            response_div_ed25519,
        ) = generate_dleqproof_simple(&witness_0, &blinding_dleq).unwrap();

        // assert_eq!(challenge_bytes, BigUint::parse_bytes(b"", 10).unwrap());
        // assert_eq!(response_div_BabyJubJub, BigUint::parse_bytes(b"", 10).unwrap());
        // assert_eq!(response_div_ed25519, BigUint::parse_bytes(b"", 10).unwrap());
        // assert_eq!(response_BabyJubJub, BigUint::parse_bytes(b"1211850493455143960510207598095808109935776728332172864532400139827493102076", 10).unwrap());
        // assert_eq!(response_ed25519, BigUint::parse_bytes(b"", 10).unwrap());

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
        )
        .unwrap();

        //Verify
        let _verification = bb_verify_init(&proof_init).unwrap();

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

        let t_im1 = get_bjjpoint_from_scalar(&witness_im1);

        //witness_i = "1012694528770316483559205215366203370757356884565651608309268621249697619247"
        // [T_i]
        //   x="0x1801440d7cc296b99d80ddbf15bdb5ae311bb2f95bce3baa58a6fae05554d4d5"
        //   y="0x030d84e498313c8dec9339118da693fff141cc5db8c3773daaf1980cb7b3d654"
        let (witness_i, t_i, s_i) = make_vcof(&witness_im1).unwrap();

        assert_eq!(
            witness_i,
            BigUint::parse_bytes(
                b"1012694528770316483559205215366203370757356884565651608309268621249697619247",
                10
            )
            .unwrap()
        );
        assert_eq!(
            t_i.x.to_string(),
            "Fr(0x1801440d7cc296b99d80ddbf15bdb5ae311bb2f95bce3baa58a6fae05554d4d5)"
        );
        assert_eq!(
            t_i.y.to_string(),
            "Fr(0x030d84e498313c8dec9339118da693fff141cc5db8c3773daaf1980cb7b3d654)"
        );

        //NIZK DLEQ
        //witness_i = "1012694528770316483559205215366203370757356884565651608309268621249697619247"
        //blinding_DLEQ = "2725795056938475204625712545454751566443431544642757859965717362752762117487"
        // let blinding_DLEQ_1: BigUint = BigUint::parse_bytes(b"2725795056938475204625712545454751566443431544642757859965717362752762117487", 10).unwrap();
        let blinding_dleq = blinding_dleq.into();

        // challenge_bytes = ["173", "177", "148", "180", "137", "70", "241", "143", "132", "241", "114", "212", "56", "49", "45", "192", "249", "176", "190", "143", "43", "192", "90", "61", "171", "183", "234", "227", "149", "245", "14", "127"]
        // response_div_BabyJubJub = ["64", "74", "43", "78", "21", "50", "143", "116", "56", "136", "47", "130", "159", "25", "232", "118", "110", "84", "144", "7", "93", "93", "99", "123", "21", "7", "21", "76", "4", "5", "135", "150"]
        // response_div_ed25519 = ["24", "78", "49", "150", "2", "128", "248", "182", "216", "15", "56", "209", "152", "115", "125", "71", "219", "162", "159", "226", "115", "116", "208", "211", "176", "90", "239", "55", "108", "6", "182", "60"]
        // response_BabyJubJub = "665215325844649228417070916130511037968741095567000659557494451588541621932"
        // response_ed25519 = ["14", "254", "72", "212", "229", "12", "54", "141", "103", "181", "191", "236", "63", "129", "185", "181", "85", "56", "102", "106", "13", "21", "59", "225", "113", "165", "17", "187", "121", "239", "101", "86"]

        let (
            challenge_bytes,
            response_baby_jub_jub,
            response_ed25519,
            r1,
            r2,
            response_div_baby_jub_jub,
            response_div_ed25519,
        ) = generate_dleqproof_simple(&witness_i, &blinding_dleq).unwrap();

        // assert_eq!(challenge_bytes_1, BigUint::parse_bytes(b"", 10).unwrap());
        // assert_eq!(response_div_BabyJubJub_1, BigUint::parse_bytes(b"", 10).unwrap());
        // assert_eq!(response_div_ed25519_1, BigUint::parse_bytes(b"", 10).unwrap());
        // assert_eq!(response_BabyJubJub_1, BigUint::parse_bytes(b"665215325844649228417070916130511037968741095567000659557494451588541621932", 10).unwrap());
        // assert_eq!(response_ed25519_1, BigUint::parse_bytes(b"", 10).unwrap());

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
        )
        .unwrap();

        //Verify
        let _verification = bb_verify_update(&proof_update).unwrap();

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
        info!("Dummy delegate: Verifying adapted signature");
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
        _kes_pubkey: GenericPoint,
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
        #[cfg(debug_assertions)]
        self.dummy.verify_peer_witness(_w, _c, metadata).await
    }
}

impl GreaseChannelDelegate for NoirDelegate {}
