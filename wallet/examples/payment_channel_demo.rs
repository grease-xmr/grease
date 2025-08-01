use ciphersuite::group::ff::PrimeField;
use circuits::*;
use dalek_ff_group::Scalar;
use libgrease::crypto::keys::Curve25519PublicKey;
use log::info;
use modular_frost::curve::Ed25519;
use modular_frost::sign::{SignatureShare, Writable};
use monero_rpc::RpcError;
use monero_serai::transaction::Transaction;
use monero_simple_request_rpc::SimpleRequestRpc;
use monero_wallet::address::{MoneroAddress, Network};
use num_bigint::BigUint;
use rand_core::OsRng;
use std::mem;
use std::ptr;
use wallet::errors::WalletError;
use wallet::multisig_wallet::MultisigWallet;
use wallet::publish_transaction;
use wallet::utils::scalar_from;

#[tokio::main]
async fn main() -> Result<(), WalletError> {
    env_logger::try_init().unwrap_or_else(|_| {
        eprintln!("Failed to initialize logger, using default settings");
    });

    {
        // let result: String= call_greet("Rust").unwrap();
        // println!("Result from JavaScript: {}", result);

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
        let nonce_peer = BigUint::parse_bytes(
            b"867303429418806279313526868407228138995734763278095857482747693606556032536",
            10,
        )
        .unwrap();
        let blinding = BigUint::parse_bytes(
            b"1194608745245961475824979247056446722984763446987071492294235640987034156744",
            10,
        )
        .unwrap();

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
        let a_1: BigUint = BigUint::parse_bytes(
            b"70143195093839929636068986763442859911856008756585124285077086015668936144",
            10,
        )
        .unwrap();

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
        let r_1: BigUint = BigUint::parse_bytes(
            b"2422852404430683902810753577573102653260911761556849713949680014072177383950",
            10,
        )
        .unwrap();
        // let pubkey_peer: Point = GetBJJPointFromHexPoints(
        //         "1529458aa75b635e1f96ece9c2ef9aa44cb019f519a979cd85fce0080b8e2417",
        //         "033da4d76cfae27f8360bd4681609681fdcb09ece4ead5c88113c143a9a20c69");
        let private_key_peer: BigUint = BigUint::parse_bytes(b"1", 10).unwrap();
        let pubkey_peer = get_scalar_to_point_bjj(&private_key_peer);

        // enc_1 = "1220122097491108282229984040904504012545109624322527294624787674340936491877"
        // [fi_1]
        //   x="0x09d58da0c2ab2b11cc1f8579f739e7e463235185753ab5d4719e8db6aa476a23"
        //   y="0x1bc9eb7eab983bfd017433c4ed524b8bfde9db0abda7c7940e9c43822268b4ce"

        let (fi_1, enc_1) = encrypt_message_ecdh(&share_1, &r_1, &pubkey_peer, Some(&private_key_peer)).unwrap();

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
        let r_2: BigUint = BigUint::parse_bytes(
            b"2044680745167638013838014513951032949701446715960700123553928808460151041757",
            10,
        )
        .unwrap();
        // [pubkey_KES]
        //   x="0x12f87860325f2ba2d84d9332a0bedc25edd93736776e818d8993a1da678958bf"
        //   y="0x105900362a575a29943602c90d432768f271ffb8f06af513dcd81d05c3a2c4a3"
        let private_key_kes: BigUint = BigUint::parse_bytes(b"1", 10).unwrap();
        let pubkey_kes = get_scalar_to_point_bjj(&private_key_kes);

        // enc_2 = "321084871571726505169933431313947177118001726846734186078876149279016535274"
        // [fi_2]
        //   x="0x0ac31edd3af81f177137239a950c8f70662c4b6fbbeec57dae63bfcb61d931ee"
        //   y="0x1975e7e9cbe0f2ed7a06a09e320036ea1a73862ee2614d2a9a6452d8f7c9aff0"

        let (fi_2, enc_2) = encrypt_message_ecdh(&share_2, &r_2, &pubkey_kes, Some(&private_key_kes)).unwrap();

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
        let blinding_dleq: BigUint = BigUint::parse_bytes(
            b"2124419834422738134599198304606394937234744825834207315619962749021962198236",
            10,
        )
        .unwrap();

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
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    info!("DLEQ failed to verify with error: {e}");
                    std::process::exit(1);
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
        let public_outputs = PublicInit::new(
            &t_0,
            &c_1,
            &fi_1,
            &enc_1,
            &fi_2,
            &enc_2,
            &s_0,
            &challenge_bytes,
            &response_baby_jub_jub,
            &response_ed25519,
            &r1,
            &r2,
        );

        let verification = bb_verify_init(&public_outputs, &proof_init).unwrap();
        assert!(verification);

        //witness_i = "1012694528770316483559205215366203370757356884565651608309268621249697619247"
        // [T_i]
        //   x="0x1801440d7cc296b99d80ddbf15bdb5ae311bb2f95bce3baa58a6fae05554d4d5"
        //   y="0x030d84e498313c8dec9339118da693fff141cc5db8c3773daaf1980cb7b3d654"
        let (witness_1, t_1, s_1) = make_vcof(&witness_0).unwrap();

        assert_eq!(
            witness_1,
            BigUint::parse_bytes(
                b"1012694528770316483559205215366203370757356884565651608309268621249697619247",
                10
            )
            .unwrap()
        );
        assert_eq!(
            t_1.x.to_string(),
            "Fr(0x1801440d7cc296b99d80ddbf15bdb5ae311bb2f95bce3baa58a6fae05554d4d5)"
        );
        assert_eq!(
            t_1.y.to_string(),
            "Fr(0x030d84e498313c8dec9339118da693fff141cc5db8c3773daaf1980cb7b3d654)"
        );

        //NIZK DLEQ
        //witness_i = "1012694528770316483559205215366203370757356884565651608309268621249697619247"
        //blinding_DLEQ = "2725795056938475204625712545454751566443431544642757859965717362752762117487"
        let blinding_dleq_1: BigUint = BigUint::parse_bytes(
            b"2725795056938475204625712545454751566443431544642757859965717362752762117487",
            10,
        )
        .unwrap();

        // challenge_bytes = ["173", "177", "148", "180", "137", "70", "241", "143", "132", "241", "114", "212", "56", "49", "45", "192", "249", "176", "190", "143", "43", "192", "90", "61", "171", "183", "234", "227", "149", "245", "14", "127"]
        // response_div_BabyJubJub = ["64", "74", "43", "78", "21", "50", "143", "116", "56", "136", "47", "130", "159", "25", "232", "118", "110", "84", "144", "7", "93", "93", "99", "123", "21", "7", "21", "76", "4", "5", "135", "150"]
        // response_div_ed25519 = ["24", "78", "49", "150", "2", "128", "248", "182", "216", "15", "56", "209", "152", "115", "125", "71", "219", "162", "159", "226", "115", "116", "208", "211", "176", "90", "239", "55", "108", "6", "182", "60"]
        // response_BabyJubJub = "665215325844649228417070916130511037968741095567000659557494451588541621932"
        // response_ed25519 = ["14", "254", "72", "212", "229", "12", "54", "141", "103", "181", "191", "236", "63", "129", "185", "181", "85", "56", "102", "106", "13", "21", "59", "225", "113", "165", "17", "187", "121", "239", "101", "86"]

        let (
            challenge_bytes_1,
            response_baby_jub_jub_1,
            response_ed25519_1,
            r1_1,
            r2_1,
            response_div_baby_jub_jub_1,
            response_div_ed25519_1,
        ) = generate_dleqproof_simple(&witness_1, &blinding_dleq_1).unwrap();

        // assert_eq!(challenge_bytes_1, BigUint::parse_bytes(b"", 10).unwrap());
        // assert_eq!(response_div_BabyJubJub_1, BigUint::parse_bytes(b"", 10).unwrap());
        // assert_eq!(response_div_ed25519_1, BigUint::parse_bytes(b"", 10).unwrap());
        // assert_eq!(response_BabyJubJub_1, BigUint::parse_bytes(b"665215325844649228417070916130511037968741095567000659557494451588541621932", 10).unwrap());
        // assert_eq!(response_ed25519_1, BigUint::parse_bytes(b"", 10).unwrap());

        //Verify
        {
            let res = verify_dleq_simple(
                &t_1,
                &s_1,
                &challenge_bytes_1,
                &response_baby_jub_jub_1,
                &response_ed25519_1,
                &r1_1,
                &r2_1,
            );
            match res {
                Ok(verified) => {
                    if verified {
                        info!("DLEQ verified");
                    } else {
                        info!("DLEQ failed to verify!");
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    info!("DLEQ failed to verify with error: {e}");
                    std::process::exit(1);
                }
            };
        }

        //Prove
        let proof_update = bb_prove_update(
            &blinding_dleq_1,
            &challenge_bytes_1,
            &left_pad_bytes_32_vec(&response_div_baby_jub_jub_1.to_bytes_be()),
            &left_pad_bytes_32_vec(&response_div_ed25519_1.to_bytes_be()),
            &response_baby_jub_jub_1,
            &left_pad_bytes_32_vec(&response_ed25519_1.to_bytes_be()),
            &witness_1,
            &witness_0,
            &t_1,
            &t_0,
        )
        .unwrap();

        //Verify
        let public_outputs = crate::PublicUpdate::new(
            &t_0,
            &t_1,
            &s_1,
            &challenge_bytes,
            &response_div_baby_jub_jub,
            &response_div_ed25519,
            &r1_1,
            &r2_1,
        );

        let verification = bb_verify_update(&public_outputs, &proof_update).unwrap();
        assert!(verification);

        println!("Success!");
    }

    //Top:
    //Mainnet: 46PAiPrNjr2XS82k2ovp5EUYLzBt9pYNW2LXUFsZiv8S3Mt21FZ5qQaAroko1enzw3eGr9qC7X1D7Geoo2RrAotYPvzt9vB
    //Testnet: 9wviCeWe2D8XS82k2ovp5EUYLzBt9pYNW2LXUFsZiv8S3Mt21FZ5qQaAroko1enzw3eGr9qC7X1D7Geoo2RrAotYPwq9Gm8
    const ALICE_ADDRESS: &str =
        "9wviCeWe2D8XS82k2ovp5EUYLzBt9pYNW2LXUFsZiv8S3Mt21FZ5qQaAroko1enzw3eGr9qC7X1D7Geoo2RrAotYPwq9Gm8";

    //Bottom:
    //9wq792k9sxVZiLn66S3Qzv8QfmtcwkdXgM5cWGsXAPxoQeMQ79md51PLPCijvzk1iHbuHi91pws5B7iajTX9KTtJ4bh2tCh
    const BOB_ADDRESS: &str =
        "9wq792k9sxVZiLn66S3Qzv8QfmtcwkdXgM5cWGsXAPxoQeMQ79md51PLPCijvzk1iHbuHi91pws5B7iajTX9KTtJ4bh2tCh";

    //Shared:
    //Mainnet: 4ASsE7j5vthM2QB3k2EvV4UqRUsjsrUXF5Sr4s1ZYmvj5MJNpmF44TDgbeMwk1ifxWYStS3wBRv5YHcnPyRtP7Rh7CDYGdW
    //Testnet: A1zQiNPMDFoM2QB3k2EvV4UqRUsjsrUXF5Sr4s1ZYmvj5MJNpmF44TDgbeMwk1ifxWYStS3wBRv5YHcnPyRtP7Rh77ETMQF
    const SHARED_ADDRESS: &str =
        "4ASsE7j5vthM2QB3k2EvV4UqRUsjsrUXF5Sr4s1ZYmvj5MJNpmF44TDgbeMwk1ifxWYStS3wBRv5YHcnPyRtP7Rh7CDYGdW";
    //Mainnet or Testnet: Multisig wallet joint private view key: 182767d3437c2d4638a6d007c55bd73f60c13a49883f87b2087e77cc89a5c901
    const JOINT_PRIVATE_VIEW_KEY: &str = "182767d3437c2d4638a6d007c55bd73f60c13a49883f87b2087e77cc89a5c901";

    // Alice generates a keypair
    let (k_a, p_a) =
        Curve25519PublicKey::keypair_from_hex("8eb8a1fd0f2c42fa7508a8883addb0860a0c5e44c1c14605abb385375c533609")
            .unwrap();
    println!("Alice: {} / {}", k_a.as_hex(), p_a.as_hex());
    // Bob generates a keypair
    let (k_b, p_b) =
        Curve25519PublicKey::keypair_from_hex("73ee459dd8a774afdbffafe6879ebc3b925fb23ceec9ac631f4ae02acff05f07")
            .unwrap();
    println!("Bob  : {} / {}", k_b.as_hex(), p_b.as_hex());

    let secret_a = scalar_from("0000000000000000000000000000000000000000000000000000000000000001");
    let secret_b = scalar_from("0000000000000000000000000000000000000000000000000000000000000001");

    // They exchange their public keys and create multisig wallets
    let rpc = SimpleRequestRpc::new("http://localhost:25070".into()).await?;
    let mut wallet_a = MultisigWallet::new(rpc.clone(), k_a.clone(), &p_a, &p_b, None)?;
    let mut wallet_b = MultisigWallet::new(rpc.clone(), k_b.clone(), &p_b, &p_a, None)?;

    assert_eq!(
        wallet_a.joint_public_spend_key(),
        wallet_b.joint_public_spend_key(),
        "Shared spend keys should be identical"
    );
    println!("Multisig wallet address for Alice: {}", wallet_a.address().to_string());
    println!("Multisig wallet address for Bob  : {}", wallet_b.address().to_string());
    assert_eq!(
        wallet_a.address().to_string(),
        SHARED_ADDRESS,
        "Shared spend keys should be deterministic"
    );
    println!(
        "Multisig wallet joint private view key: {}",
        wallet_a.joint_private_view_key().as_hex()
    );
    assert_eq!(
        wallet_a.joint_private_view_key().as_hex(),
        JOINT_PRIVATE_VIEW_KEY,
        "Shared joint private view key should be deterministic"
    );

    println!("Joint Secret view key: {}", wallet_a.joint_private_view_key().as_hex());
    println!("Joint Public view key: {}", wallet_a.joint_public_view_key().as_hex());
    println!("Joint Public spend key: {}", wallet_a.joint_public_view_key().as_hex());
    println!("Creating signing state machine...");

    // Try load outputs
    for wallet in [&mut wallet_a, &mut wallet_b] {
        let must_scan = match wallet.load("demo_wallet.bin") {
            Ok(loaded) if loaded > 0 => {
                info!("Wallet loaded successfully. {loaded} outputs found");
                false
            }
            Ok(_) => {
                info!("No outputs in wallet, starting fresh. This will take a while...");
                true
            }
            Err(e) => {
                info!("Failed to load wallet: {e}, starting fresh. This will take a while...");
                true
            }
        };
        if must_scan {
            info!("must_scan");
            let outputs = wallet.scan(None).await?;
            info!("{outputs} outputs found in scan");
            let saved = wallet.save("demo_wallet.bin").map_err(|e| RpcError::InternalError(e.to_string()))?;
            info!("Saved {saved} outputs to disk");
        }
    }
    info!("Outputs loaded");

    //INIT/UPDATE
    // Pay Alice's external wallet
    let alice_wallet = MoneroAddress::from_str(Network::Testnet, ALICE_ADDRESS).unwrap();
    let bob_wallet = MoneroAddress::from_str(Network::Testnet, BOB_ADDRESS).unwrap();
    let payment = vec![(alice_wallet, 1_000u64), (bob_wallet, 1_000u64)]; // Placeholder for payment, should be replaced with actual payment data

    info!("Alice preparing...");
    wallet_a.prepare(payment.clone(), &mut OsRng).await?;
    info!("Alice prepared");

    info!("Bob preparing...");
    wallet_b.prepare(payment, &mut OsRng).await?;
    info!("Bob prepared");

    info!("Preprocessing step completed for both wallets");

    let pp_b = wallet_b.my_pre_process_data().unwrap();
    let pp_a = wallet_a.my_pre_process_data().unwrap();

    wallet_a.partial_sign(&pp_b)?;
    info!("Partial Signing completed for Alice");

    wallet_b.partial_sign(&pp_a)?;
    info!("Partial Signing completed for Bob");

    let ss_a_real: Vec<modular_frost::sign::SignatureShare<ciphersuite::Ed25519>> =
        vec![wallet_a.my_signing_share().unwrap()];
    info!("Signing shares prepared for Alice: {}", ss_a_real.len());
    info!("Signing shares for Alice: {}", ss_a_real.len());
    for share in &ss_a_real {
        info!("{:?}", get_signatureshare_scalar(share));
    }

    let ss_b_real: Vec<SignatureShare<Ed25519>> = vec![wallet_b.my_signing_share().unwrap()];
    info!("Signing shares prepared for Bob: {}", ss_b_real.len());
    info!("Signing shares for Bob: {}", ss_b_real.len());
    for share in &ss_b_real {
        info!("{:?}", get_signatureshare_scalar(share));
    }

    let mut ss_a_encrypted = ss_a_real.clone();
    make_adapted_shares(&ss_a_real, &mut ss_a_encrypted, secret_a).unwrap();
    info!("Encrypted signing shares for Alice: {}", ss_a_encrypted.len());
    for share in &ss_a_encrypted {
        info!("{:?}", get_signatureshare_scalar(share));
    }
    //Verify changed
    for (i, _) in ss_a_real.iter().enumerate() {
        assert_ne!(
            get_signatureshare_scalar(&ss_a_real[i]),
            get_signatureshare_scalar(&ss_a_encrypted[i])
        );
    }

    let mut ss_b_encrypted = ss_b_real.clone();
    make_adapted_shares(&ss_b_real, &mut ss_b_encrypted, secret_b).unwrap();
    info!("Encrypted signing shares for Bob: {}", ss_b_encrypted.len());
    for share in &ss_b_encrypted {
        info!("{:?}", get_signatureshare_scalar(share));
    }
    //Verify changed
    for (i, _) in ss_b_real.iter().enumerate() {
        assert_ne!(
            get_signatureshare_scalar(&ss_b_real[i]),
            get_signatureshare_scalar(&ss_b_encrypted[i])
        );
    }

    //CLOSE
    // They exchange their adaptor secrets
    let ss_b_adapted = adapt_shares(ss_b_encrypted, secret_b);
    info!("Alice adapted Bob's shares: {}", ss_b_adapted.len());
    for share in &ss_b_adapted {
        info!("{:?}", get_signatureshare_scalar(share));
    }
    //Verify unchanged
    for (i, _) in ss_b_adapted.iter().enumerate() {
        assert_eq!(
            get_signatureshare_scalar(&ss_b_real[i]),
            get_signatureshare_scalar(&ss_b_adapted[i])
        );
    }

    let tx_a: Transaction = wallet_a.sign(&ss_b_adapted[0])?;
    info!("Alice's transaction signed successfully");

    let ss_a_adapted = adapt_shares(ss_a_encrypted, secret_a);
    info!("Bob adapted Alice's shares");

    let tx_b: Transaction = wallet_b.sign(&ss_a_adapted[0])?;
    info!("Bob's transaction signed successfully");

    println!("Wallet transaction from Alice: {}", hex::encode(tx_a.hash()));
    println!("Wallet transaction from Bob: {}", hex::encode(tx_b.hash()));

    println!("Sighash A: {}", hex::encode(tx_a.signature_hash().unwrap()));
    println!("Sighash B: {}", hex::encode(tx_b.signature_hash().unwrap()));

    println!("weight A: {}", tx_a.weight());
    println!("weight B: {}", tx_b.weight());

    publish_transaction(wallet_a.rpc(), &tx_a).await?;
    Ok(())
}

fn get_signatureshare_scalar(share: &SignatureShare<Ed25519>) -> Scalar {
    //Read
    let mut buf = vec![];
    share.write(&mut buf).unwrap();
    let mut repr: [u8; 32] = [0u8; 32];
    repr.copy_from_slice(&buf[0..32]);
    let s = Scalar::from_repr(repr).unwrap();
    s
}
unsafe fn update_signatureshare(original: &mut SignatureShare<Ed25519>, new_value: Scalar) {
    // Safety: This function transmutes between SignatureShare<Ed25519> and Scalar.
    // The caller must ensure that:
    // 1. The types have the same size and alignment (checked by assertions)
    // 2. The Scalar value represents a valid SignatureShare<Ed25519>    // Ensure the types are compatible for transmute
    assert_eq!(mem::size_of::<SignatureShare<Ed25519>>(), mem::size_of::<Scalar>());
    assert_eq!(mem::align_of::<SignatureShare<Ed25519>>(), mem::align_of::<Scalar>());

    // Transmute the Scalar to SignatureShare<Ed25519>
    let new_struct: SignatureShare<Ed25519> = mem::transmute_copy(&new_value);

    // Write the new value directly into the target's memory
    ptr::write(original as *mut SignatureShare<Ed25519>, new_struct);
}

fn make_adapted_shares(
    signature_shares: &Vec<SignatureShare<Ed25519>>,
    adapted_shares: &mut Vec<SignatureShare<Ed25519>>,
    secret: Scalar,
) -> Result<(), RpcError> {
    assert_eq!(signature_shares.len(), adapted_shares.len());
    let length = signature_shares.len();

    for i in 0..length {
        //Read
        let mut buf = vec![];
        signature_shares[i].write(&mut buf).unwrap();
        let mut repr: [u8; 32] = [0u8; 32];
        repr.copy_from_slice(&buf[0..32]);
        let s = Scalar::from_repr(repr).unwrap();

        //Update
        let s_adapted = s + secret;
        assert_ne!(s, s_adapted);

        //Write
        //adapted_shares[i] = s_adapted;
        unsafe {
            update_signatureshare(&mut adapted_shares[i], s_adapted);
        }
    }

    //Verify changed
    for i in 0..length {
        assert_ne!(
            get_signatureshare_scalar(&signature_shares[i]),
            get_signatureshare_scalar(&adapted_shares[i])
        );
    }

    Ok(())
}

fn adapt_shares(
    adapted_signature_shares: Vec<SignatureShare<Ed25519>>,
    secret: Scalar,
) -> Vec<SignatureShare<Ed25519>> {
    let mut real_shares = adapted_signature_shares.clone();

    //Read
    let mut buf = vec![];
    real_shares.write(&mut buf).unwrap();
    let mut repr: [u8; 32] = [0u8; 32];
    repr.copy_from_slice(&buf[0..32]);
    let s = Scalar::from_repr(repr).unwrap();

    //Update
    let s_adapted = s - secret;

    //Write
    //real_shares[i] = s_adapted;
    unsafe {
        update_signatureshare(&mut real_shares[0], s_adapted);
    }
    real_shares
}
