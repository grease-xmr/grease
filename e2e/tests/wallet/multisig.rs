use crate::wallet::world::MultisigWalletWrapper;
use crate::wallet::WalletWorld;
use cucumber::{given, then, when};
use e2e::MONEROD_RPC;
use libgrease::amount::{MoneroAmount, MoneroDelta};
use libgrease::cryptography::keys::{Curve25519PublicKey, Curve25519Secret, PublicKey};
use libgrease::payment_channel::ChannelRole;
use log::*;
use monero_rpc::Rpc;
use rand_core::OsRng;
use wallet::multisig_wallet::signature_share_to_bytes;
use wallet::{connect_to_rpc, publish_transaction, MultisigWallet};

// ============ Wallet Creation ============

#[given(expr = "{word} and {word} create a multisig wallet")]
async fn create_multisig_wallet(world: &mut WalletWorld, user1: String, user2: String) {
    let u1 = world.users.get(&user1).expect("User not found");
    let u2 = world.users.get(&user2).expect("User not found");

    let rpc1 = connect_to_rpc(MONEROD_RPC).await.expect("Failed to connect to RPC");
    let rpc2 = connect_to_rpc(MONEROD_RPC).await.expect("Failed to connect to RPC");

    // First user is Customer, second is Merchant (arbitrary but consistent)
    let mut wallet1 = MultisigWallet::new(
        rpc1,
        u1.secret_key.clone(),
        &u1.public_key,
        &u2.public_key,
        None,
        ChannelRole::Customer,
    )
    .expect("Failed to create multisig wallet for user1");

    let mut wallet2 = MultisigWallet::new(
        rpc2,
        u2.secret_key.clone(),
        &u2.public_key,
        &u1.public_key,
        None,
        ChannelRole::Merchant,
    )
    .expect("Failed to create multisig wallet for user2");

    // Reset birthday to current height so we only scan new blocks
    let height = wallet1.reset_birthday().await.expect("Failed to reset birthday");
    wallet2.reset_birthday().await.expect("Failed to reset birthday");
    info!("Wallet birthday set to block {height}");

    info!("Created multisig wallets for {user1} and {user2}");
    info!("{user1} address: {}", wallet1.address());
    info!("{user2} address: {}", wallet2.address());

    world.multisig_wallets.insert(user1, MultisigWalletWrapper(wallet1));
    world.multisig_wallets.insert(user2, MultisigWalletWrapper(wallet2));
}

// ============ Address Verification ============

#[then("the multisig wallet address is valid")]
async fn verify_multisig_address_valid(world: &mut WalletWorld) {
    let wallet = world.multisig_wallets.values().next().expect("No multisig wallet found");
    let address = wallet.0.address();
    let addr_str = address.to_string();
    // Monero mainnet addresses start with '4'
    assert!(
        addr_str.starts_with('4'),
        "Expected mainnet address starting with '4', got: {addr_str}"
    );
    assert!(addr_str.len() == 95, "Expected address length of 95, got: {}", addr_str.len());
    info!("Multisig wallet address is valid: {addr_str}");
}

#[then(expr = "{word} and {word} have the same multisig address")]
async fn verify_same_multisig_address(world: &mut WalletWorld, user1: String, user2: String) {
    let wallet1 = world.multisig_wallets.get(&user1).expect("User1 wallet not found");
    let wallet2 = world.multisig_wallets.get(&user2).expect("User2 wallet not found");
    let addr1 = wallet1.0.address().to_string();
    let addr2 = wallet2.0.address().to_string();
    assert_eq!(addr1, addr2, "Expected {user1} and {user2} to have the same multisig address");
    info!("{user1} and {user2} have the same multisig address: {addr1}");
}

// ============ Funding & Scanning ============

#[when(expr = "{word} mines {int} block(s) to the multisig wallet")]
async fn mine_to_multisig(world: &mut WalletWorld, who: String, count: usize) {
    let wallet = world.multisig_wallets.get(&who).expect("User wallet not found");
    let address = wallet.0.address();
    let rpc = world.monero_node.as_ref().unwrap().rpc_client().await.expect("Failed to get RPC client");
    let (blocks, last_block) = rpc.generate_blocks(&address, count).await.expect("Failed to mine blocks");
    info!("Mined {} blocks to multisig wallet. Last block: {}", blocks.len(), last_block);
}

#[when(expr = "{word} scans the multisig wallet")]
async fn scan_multisig_wallet(world: &mut WalletWorld, who: String) {
    let wallet = world.multisig_wallets.get_mut(&who).expect("User wallet not found");
    let found = wallet.0.scan(None).await.expect("Failed to scan multisig wallet");
    info!("{who} scanned multisig wallet and found {found} outputs");
}

#[then(expr = "{word}'s multisig wallet has {int} output(s)")]
async fn verify_output_count(world: &mut WalletWorld, who: String, expected: usize) {
    let wallet = world.multisig_wallets.get(&who).expect("User wallet not found");
    let actual = wallet.0.outputs().len();
    assert_eq!(actual, expected, "Expected {expected} outputs, but found {actual}");
}

#[then(expr = "{word}'s multisig wallet has at least {float} XMR")]
async fn verify_minimum_balance(world: &mut WalletWorld, who: String, min_xmr: f64) {
    let wallet = world.multisig_wallets.get(&who).expect("User wallet not found");
    let total: u64 = wallet.0.outputs().iter().map(|o| o.commitment().amount).sum();
    let balance = MoneroAmount::from_piconero(total);
    let min_amount = MoneroAmount::from_xmr(&format!("{min_xmr}")).expect("Invalid XMR amount");
    assert!(
        balance >= min_amount,
        "Expected at least {min_amount} XMR, but balance is {balance}"
    );
    info!("{who}'s multisig wallet balance: {balance}");
}

/// Checks the LAST 10 blocks for a user receiving a specific amount of XMR.
/// Prefixes: `~` for fuzzy match, `>` for greater than, `<` for less than.
#[then(regex = r"^(\w+) receives ([~><])?(\d+\.?\d*) XMR$")]
async fn user_receives_xmr(world: &mut WalletWorld, who: String, fuzzy: String, amount: String) {
    let user = world.users.get(&who).expect("User not found");
    let amount = MoneroAmount::from_xmr(&amount).expect("Failed to parse amount");
    let delta = MoneroDelta::from(100_000_000_000); // 0.1 XMR tolerance
    let (min, max) = match fuzzy.as_str() {
        "~" => (
            amount.checked_apply_delta(-delta).unwrap(),
            amount.checked_apply_delta(delta).unwrap(),
        ),
        ">" => (amount, MoneroAmount::from_piconero(u64::MAX)),
        "<" => (MoneroAmount::from_piconero(0), amount),
        _ => (amount, amount),
    };
    let rpc = world.monero_node.as_ref().unwrap().rpc_client().await.expect("Failed to get RPC client");
    let height = rpc.get_height().await.expect("Failed to get height") as u64;
    let mut wallet = user.wallet().await;
    let output_count = wallet.scan(Some(height - 10), Some(height)).await.unwrap();
    let result = wallet.outputs().iter().rev().take(output_count as usize).any(|output| {
        let output_amount = MoneroAmount::from(output.commitment().amount);
        if output_amount >= min && output_amount <= max {
            info!("{who} received {output_amount} XMR");
            true
        } else {
            false
        }
    });
    assert!(result, "{who} did not receive a payment in the expected range");
}

// ============ Transaction Flow ============

#[when(expr = "{word} prepares a multisig transaction sending {float} XMR to {word}")]
async fn prepare_multisig_transaction(world: &mut WalletWorld, sender: String, amount: f64, recipient: String) {
    let recipient_address = world.users.get(&recipient).expect("Recipient not found").address();
    let piconero = (amount * 1_000_000_000_000.0) as u64;
    let payments = vec![(recipient_address, piconero)];

    let wallet = world.multisig_wallets.get_mut(&sender).expect("Sender wallet not found");
    // Use deterministic RNG so both parties create identical transactions (same decoys, same ordering)
    let mut rng = wallet.0.deterministic_rng();
    wallet.0.prepare(payments, &mut rng).await.expect("Failed to prepare transaction");

    let preprocess = wallet.0.my_pre_process_data().expect("No preprocess data generated");
    info!(
        "{sender} prepared transaction, preprocess data size: {} bytes",
        preprocess.len()
    );
    world.pending_preprocess.insert(sender, preprocess);
}

#[when(expr = "{word} and {word} exchange preprocess data")]
async fn exchange_preprocess_data(world: &mut WalletWorld, user1: String, user2: String) {
    let preprocess1 = world.pending_preprocess.get(&user1).expect("User1 preprocess not found").clone();
    let preprocess2 = world.pending_preprocess.get(&user2).expect("User2 preprocess not found").clone();

    // User1 receives User2's preprocess and partial signs
    let wallet1 = world.multisig_wallets.get_mut(&user1).expect("User1 wallet not found");
    wallet1.0.partial_sign(&preprocess2).expect("User1 failed to partial sign");
    let share1 = wallet1.0.my_signing_share().expect("User1 has no signing share");
    let share1_bytes = signature_share_to_bytes(&share1);
    info!("{user1} partial signed with {user2}'s preprocess data");

    // User2 receives User1's preprocess and partial signs
    let wallet2 = world.multisig_wallets.get_mut(&user2).expect("User2 wallet not found");
    wallet2.0.partial_sign(&preprocess1).expect("User2 failed to partial sign");
    let share2 = wallet2.0.my_signing_share().expect("User2 has no signing share");
    let share2_bytes = signature_share_to_bytes(&share2);
    info!("{user2} partial signed with {user1}'s preprocess data");

    world.pending_shares.insert(user1, share1_bytes);
    world.pending_shares.insert(user2, share2_bytes);
}

#[when(expr = "{word} and {word} exchange signature shares")]
async fn exchange_signature_shares(world: &mut WalletWorld, user1: String, user2: String) {
    // This step just confirms the shares are stored; actual exchange happened in previous step
    assert!(world.pending_shares.contains_key(&user1), "User1 share not found");
    assert!(world.pending_shares.contains_key(&user2), "User2 share not found");
    info!("{user1} and {user2} have exchanged signature shares");
}

#[when(expr = "{word} finalizes the multisig transaction with {word}'s share")]
async fn finalize_multisig_transaction(world: &mut WalletWorld, finalizer: String, peer: String) {
    let peer_share_bytes = world.pending_shares.get(&peer).expect("Peer share not found").clone();
    let wallet = world.multisig_wallets.get_mut(&finalizer).expect("Finalizer wallet not found");

    let peer_share = wallet.0.bytes_to_signature_share(&peer_share_bytes).expect("Failed to deserialize peer share");
    let tx = wallet.0.sign(peer_share).expect("Failed to finalize transaction");
    info!("{finalizer} finalized transaction with {peer}'s share");

    let rpc = world.monero_node.as_ref().unwrap().rpc_client().await.expect("Failed to get RPC client");
    publish_transaction(&rpc, &tx).await.expect("Failed to publish transaction");
    info!("Transaction published successfully");
}

// ============ Error Handling ============

#[when(expr = "{word} tries to prepare a multisig transaction sending {float} XMR to {word}")]
async fn try_prepare_multisig_transaction(world: &mut WalletWorld, sender: String, amount: f64, recipient: String) {
    let recipient_address = world.users.get(&recipient).expect("Recipient not found").address();
    let piconero = (amount * 1_000_000_000_000.0) as u64;
    let payments = vec![(recipient_address, piconero)];

    let wallet = world.multisig_wallets.get_mut(&sender).expect("Sender wallet not found");
    // Use deterministic RNG so both parties create identical transactions
    let mut rng = wallet.0.deterministic_rng();
    match wallet.0.prepare(payments, &mut rng).await {
        Ok(_) => {
            world.last_error = None;
            info!("{sender} successfully prepared transaction");
        }
        Err(e) => {
            let err_msg = e.to_string();
            info!("{sender} failed to prepare transaction: {err_msg}");
            world.last_error = Some(err_msg);
        }
    }
}

#[then(expr = "the preparation fails with {string}")]
async fn verify_preparation_failure(world: &mut WalletWorld, expected_error: String) {
    let error = world.last_error.as_ref().expect("Expected an error but none occurred");
    assert!(
        error.contains(&expected_error),
        "Expected error containing '{expected_error}', got: {error}"
    );
    info!("Preparation failed as expected with: {error}");
}

#[when(expr = "{word} tries to partial sign with invalid data")]
async fn try_partial_sign_invalid(world: &mut WalletWorld, who: String) {
    let wallet = world.multisig_wallets.get_mut(&who).expect("User wallet not found");
    let invalid_data = vec![0u8; 32]; // Invalid preprocess data
    match wallet.0.partial_sign(&invalid_data) {
        Ok(_) => {
            world.last_error = None;
            info!("{who} unexpectedly succeeded with invalid data");
        }
        Err(e) => {
            let err_msg = e.to_string();
            info!("{who} failed to partial sign: {err_msg}");
            world.last_error = Some(err_msg);
        }
    }
}

#[then(expr = "the partial sign fails with {string}")]
async fn verify_partial_sign_failure(world: &mut WalletWorld, expected_error: String) {
    let error = world.last_error.as_ref().expect("Expected an error but none occurred");
    assert!(
        error.contains(&expected_error),
        "Expected error containing '{expected_error}', got: {error}"
    );
    info!("Partial sign failed as expected with: {error}");
}

// ============ Adversarial Scenarios ============

#[given(expr = "{word} creates a multisig wallet with a rogue key against {word}")]
async fn create_rogue_key_wallet(world: &mut WalletWorld, attacker: String, victim: String) {
    let attacker_user = world.users.get(&attacker).expect("Attacker not found");
    let victim_user = world.users.get(&victim).expect("Victim not found");

    // Attacker generates a separate "decoy" key to tell victim, while using their real key internally.
    // This simulates a dishonest setup where attacker lies about their public key.
    // The victim will create a wallet with the wrong peer key, resulting in different addresses.
    let decoy_secret = Curve25519Secret::random(&mut OsRng);
    let decoy_pubkey = Curve25519PublicKey::from_secret(&decoy_secret);

    let rpc1 = connect_to_rpc(MONEROD_RPC).await.expect("Failed to connect to RPC");
    let rpc2 = connect_to_rpc(MONEROD_RPC).await.expect("Failed to connect to RPC");

    // Attacker creates wallet with their REAL key, knowing victim's real key
    let attacker_wallet = MultisigWallet::new(
        rpc1,
        attacker_user.secret_key.clone(),
        &attacker_user.public_key,
        &victim_user.public_key,
        None,
        ChannelRole::Customer,
    )
    .expect("Failed to create attacker wallet");

    // Victim creates wallet with their real keys, but attacker lied and gave them decoy_pubkey
    let victim_wallet = MultisigWallet::new(
        rpc2,
        victim_user.secret_key.clone(),
        &victim_user.public_key,
        &decoy_pubkey, // Victim thinks attacker has this key
        None,
        ChannelRole::Merchant,
    )
    .expect("Failed to create victim wallet");

    info!(
        "Created rogue key wallets - attacker: {}, victim: {}",
        attacker_wallet.address(),
        victim_wallet.address()
    );
    info!("Attacker used real key, victim was given decoy - addresses should differ");

    world.multisig_wallets.insert(attacker, MultisigWalletWrapper(attacker_wallet));
    world.multisig_wallets.insert(victim, MultisigWalletWrapper(victim_wallet));
}

#[then(expr = "{word} and {word} have different multisig addresses")]
async fn verify_different_addresses(world: &mut WalletWorld, user1: String, user2: String) {
    let wallet1 = world.multisig_wallets.get(&user1).expect("User1 wallet not found");
    let wallet2 = world.multisig_wallets.get(&user2).expect("User2 wallet not found");
    let addr1 = wallet1.0.address().to_string();
    let addr2 = wallet2.0.address().to_string();
    assert_ne!(addr1, addr2, "Expected different addresses but both are: {addr1}");
    info!("Addresses differ as expected: {user1}={addr1}, {user2}={addr2}");
}

#[when(expr = "{word} tries to finalize with an invalid signature share")]
async fn try_finalize_invalid_share(world: &mut WalletWorld, who: String) {
    let wallet = world.multisig_wallets.get_mut(&who).expect("User wallet not found");

    // Create an invalid signature share (all zeros)
    let invalid_share_bytes = vec![0u8; 32];
    match wallet.0.bytes_to_signature_share(&invalid_share_bytes) {
        Ok(share) => match wallet.0.sign(share) {
            Ok(_) => {
                world.last_error = None;
                info!("{who} unexpectedly succeeded with invalid share");
            }
            Err(e) => {
                world.last_error = Some(e.to_string());
                info!("{who} failed to finalize: {e}");
            }
        },
        Err(e) => {
            world.last_error = Some(e.to_string());
            info!("{who} failed to deserialize invalid share: {e}");
        }
    }
}

#[then(expr = "the finalization fails with {string}")]
async fn verify_finalization_failure_with_msg(world: &mut WalletWorld, expected_error: String) {
    let error = world.last_error.as_ref().expect("Expected an error but none occurred");
    assert!(
        error.contains(&expected_error),
        "Expected error containing '{expected_error}', got: {error}"
    );
    info!("Finalization failed as expected with: {error}");
}

#[when(expr = "{word} tries to finalize the multisig transaction with {word}'s share")]
async fn try_finalize_multisig_transaction(world: &mut WalletWorld, finalizer: String, peer: String) {
    let peer_share_bytes = world.pending_shares.get(&peer).expect("Peer share not found").clone();
    let wallet = world.multisig_wallets.get_mut(&finalizer).expect("Finalizer wallet not found");

    match wallet.0.bytes_to_signature_share(&peer_share_bytes) {
        Ok(peer_share) => match wallet.0.sign(peer_share) {
            Ok(tx) => {
                world.last_error = None;
                let rpc = world.monero_node.as_ref().unwrap().rpc_client().await.expect("Failed to get RPC client");
                if let Err(e) = publish_transaction(&rpc, &tx).await {
                    world.last_error = Some(e.to_string());
                    info!("{finalizer} failed to publish: {e}");
                } else {
                    info!("{finalizer} successfully finalized and published");
                }
            }
            Err(e) => {
                world.last_error = Some(e.to_string());
                info!("{finalizer} failed to finalize: {e}");
            }
        },
        Err(e) => {
            world.last_error = Some(e.to_string());
            info!("{finalizer} failed to deserialize share: {e}");
        }
    }
}

#[then("the finalization fails")]
async fn verify_finalization_failure(world: &mut WalletWorld) {
    assert!(world.last_error.is_some(), "Expected finalization to fail but it succeeded");
    info!("Finalization failed as expected: {}", world.last_error.as_ref().unwrap());
}

/// Prepare with OsRng for tests that need unique nonces across sessions
#[when(expr = "{word} prepares another multisig transaction sending {float} XMR to {word}")]
async fn prepare_another_multisig_transaction(world: &mut WalletWorld, sender: String, amount: f64, recipient: String) {
    let recipient_address = world.users.get(&recipient).expect("Recipient not found").address();
    let piconero = (amount * 1_000_000_000_000.0) as u64;
    let payments = vec![(recipient_address, piconero)];

    let wallet = world.multisig_wallets.get_mut(&sender).expect("Sender wallet not found");
    // Use OsRng for this preparation to ensure nonces differ from previous preparations
    let mut rng = OsRng;
    wallet.0.prepare(payments, &mut rng).await.expect("Failed to prepare transaction");

    let preprocess = wallet.0.my_pre_process_data().expect("No preprocess data generated");
    info!(
        "{sender} prepared another transaction, preprocess data size: {} bytes",
        preprocess.len()
    );
    world.pending_preprocess.insert(sender, preprocess);
}

#[when(expr = "{word} stores her preprocess data")]
async fn store_preprocess_data(world: &mut WalletWorld, who: String) {
    let preprocess = world.pending_preprocess.get(&who).expect("No preprocess data found").clone();
    world.stored_preprocess = Some(preprocess);
    info!("{who} stored preprocess data for later comparison");
}

#[then(expr = "{word}'s preprocess data differs from stored")]
async fn verify_preprocess_differs(world: &mut WalletWorld, who: String) {
    let current = world.pending_preprocess.get(&who).expect("No current preprocess data");
    let stored = world.stored_preprocess.as_ref().expect("No stored preprocess data");
    assert_ne!(
        current, stored,
        "Preprocess data should differ between sessions (nonce uniqueness)"
    );
    info!("{who}'s preprocess data differs from stored - nonces are unique");
}

#[when(expr = "{word} tries to finalize without preparation")]
async fn try_finalize_without_preparation(world: &mut WalletWorld, who: String) {
    let wallet = world.multisig_wallets.get_mut(&who).expect("User wallet not found");

    // Try to create a dummy share and sign without proper preparation
    let dummy_share_bytes = vec![0u8; 32];
    match wallet.0.bytes_to_signature_share(&dummy_share_bytes) {
        Ok(share) => match wallet.0.sign(share) {
            Ok(_) => {
                world.last_error = None;
                info!("{who} unexpectedly succeeded without preparation");
            }
            Err(e) => {
                world.last_error = Some(e.to_string());
                info!("{who} failed to finalize without preparation: {e}");
            }
        },
        Err(e) => {
            world.last_error = Some(e.to_string());
            info!("{who} failed: {e}");
        }
    }
}

#[when(expr = "{word} tries to partial sign again with {word}'s preprocess")]
async fn try_partial_sign_again(world: &mut WalletWorld, who: String, peer: String) {
    let peer_preprocess = world.pending_preprocess.get(&peer).expect("Peer preprocess not found").clone();
    let wallet = world.multisig_wallets.get_mut(&who).expect("User wallet not found");

    match wallet.0.partial_sign(&peer_preprocess) {
        Ok(_) => {
            world.last_error = None;
            info!("{who} unexpectedly succeeded with second partial sign");
        }
        Err(e) => {
            world.last_error = Some(e.to_string());
            info!("{who} failed second partial sign: {e}");
        }
    }
}

#[when(expr = "{word} stores his signature share")]
async fn store_signature_share(world: &mut WalletWorld, who: String) {
    let share = world.pending_shares.get(&who).expect("No signature share found").clone();
    world.stored_share = Some(share);
    info!("{who} stored signature share for replay test");
}

#[when(expr = "{word} tries to finalize with {word}'s stored share")]
async fn try_finalize_with_stored_share(world: &mut WalletWorld, finalizer: String, peer: String) {
    let stored_share_bytes = world.stored_share.as_ref().expect("No stored share found").clone();
    let wallet = world.multisig_wallets.get_mut(&finalizer).expect("Finalizer wallet not found");

    info!("Attempting replay attack with {peer}'s stored share from previous session");
    match wallet.0.bytes_to_signature_share(&stored_share_bytes) {
        Ok(share) => match wallet.0.sign(share) {
            Ok(tx) => {
                let rpc = world.monero_node.as_ref().unwrap().rpc_client().await.expect("Failed to get RPC client");
                match publish_transaction(&rpc, &tx).await {
                    Ok(_) => {
                        world.last_error = None;
                        info!("Replay attack unexpectedly succeeded!");
                    }
                    Err(e) => {
                        world.last_error = Some(e.to_string());
                        info!("Replay attack failed at publish: {e}");
                    }
                }
            }
            Err(e) => {
                world.last_error = Some(e.to_string());
                info!("Replay attack failed at sign: {e}");
            }
        },
        Err(e) => {
            world.last_error = Some(e.to_string());
            info!("Replay attack failed at deserialization: {e}");
        }
    }
}
