@wallet
Feature: MultisigWallet with SimpleRequestRpc
  Test the 2-of-2 multisig wallet implementation against a real Monero regtest network.

  Background:
    Given a Monero regtest network
    # Mine enough blocks to have mature outputs for ring signature decoy selection
    When Alice mines 200 blocks

  Scenario: Create and verify multisig wallet address
    Given Alice and Bob create a multisig wallet
    Then the multisig wallet address is valid
    And Alice and Bob have the same multisig address

  Scenario: Fund and scan multisig wallet
    Given Alice and Bob create a multisig wallet
    When Alice mines 10 blocks to the multisig wallet
    And Alice scans the multisig wallet
    # Scan finds all 10 coinbase outputs paid to multisig address
    Then Alice's multisig wallet has 10 outputs
    And Alice's multisig wallet has at least 0.5 XMR

  Scenario: Complete multisig transaction
    Given Alice and Bob create a multisig wallet
    When Alice mines 10 blocks to the multisig wallet
    # Mine 61 more blocks to mature the coinbase outputs (60 block maturity period)
    And Alice mines 61 blocks
    And Alice scans the multisig wallet
    And Bob scans the multisig wallet
    When Alice prepares a multisig transaction sending 0.1 XMR to Bob
    And Bob prepares a multisig transaction sending 0.1 XMR to Bob
    And Alice and Bob exchange preprocess data
    And Alice and Bob exchange signature shares
    And Alice finalizes the multisig transaction with Bob's share
    And Alice mines 1 block
    Then Bob receives ~0.1 XMR

  Scenario: Insufficient funds error
    Given Alice and Bob create a multisig wallet
    When Alice scans the multisig wallet
    When Alice tries to prepare a multisig transaction sending 1.0 XMR to Bob
    Then the preparation fails with "Not enough funds"

  Scenario: Invalid partial sign data
    Given Alice and Bob create a multisig wallet
    When Alice mines 10 blocks to the multisig wallet
    And Alice mines 61 blocks
    And Alice scans the multisig wallet
    When Alice tries to partial sign with invalid data
    Then the partial sign fails with "not initialized"

  # ============ Adversarial Scenarios ============

  Scenario: Dishonest key exchange results in incompatible wallets
    # If an attacker lies about their public key during setup, the parties will
    # derive different combined keys via MuSig, resulting in incompatible wallets.
    # This demonstrates that both parties must honestly exchange keys to collaborate.
    Given Alice creates a multisig wallet with a rogue key against Bob
    Then Alice and Bob have different multisig addresses
    # Since the attacker lied about their key, they cannot sign transactions from
    # Bob's derived address, and vice versa - the attack is self-defeating

  Scenario: Invalid signature share is rejected
    Given Alice and Bob create a multisig wallet
    When Alice mines 10 blocks to the multisig wallet
    And Alice mines 61 blocks
    And Alice scans the multisig wallet
    And Bob scans the multisig wallet
    When Alice prepares a multisig transaction sending 0.1 XMR to Bob
    And Bob prepares a multisig transaction sending 0.1 XMR to Bob
    And Alice and Bob exchange preprocess data
    When Alice tries to finalize with an invalid signature share
    Then the finalization fails with "invalid share"

  Scenario: Mismatched transaction preparation fails
    # Alice and Bob prepare transactions with different payment destinations
    Given Alice and Bob create a multisig wallet
    When Alice mines 10 blocks to the multisig wallet
    And Alice mines 61 blocks
    And Alice scans the multisig wallet
    And Bob scans the multisig wallet
    When Alice prepares a multisig transaction sending 0.1 XMR to Alice
    And Bob prepares a multisig transaction sending 0.1 XMR to Bob
    And Alice and Bob exchange preprocess data
    When Alice tries to finalize the multisig transaction with Bob's share
    Then the finalization fails

  Scenario: Nonces are unique across signing sessions
    Given Alice and Bob create a multisig wallet
    When Alice mines 10 blocks to the multisig wallet
    And Alice mines 61 blocks
    And Alice scans the multisig wallet
    When Alice prepares a multisig transaction sending 0.1 XMR to Bob
    And Alice stores her preprocess data
    # Use random nonces for the second preparation to demonstrate uniqueness
    When Alice prepares another multisig transaction sending 0.1 XMR to Bob
    Then Alice's preprocess data differs from stored

  Scenario: Cannot sign without preparation
    Given Alice and Bob create a multisig wallet
    When Alice mines 10 blocks to the multisig wallet
    And Alice mines 61 blocks
    And Alice scans the multisig wallet
    When Alice tries to finalize without preparation
    Then the finalization fails with "partial_sign"

  Scenario: Cannot partial sign twice with same preprocess
    Given Alice and Bob create a multisig wallet
    When Alice mines 10 blocks to the multisig wallet
    And Alice mines 61 blocks
    And Alice scans the multisig wallet
    And Bob scans the multisig wallet
    When Alice prepares a multisig transaction sending 0.1 XMR to Bob
    And Bob prepares a multisig transaction sending 0.1 XMR to Bob
    And Alice and Bob exchange preprocess data
    When Alice tries to partial sign again with Bob's preprocess
    Then the partial sign fails with "not initialized"

  Scenario: Replayed signature share from previous session fails
    Given Alice and Bob create a multisig wallet
    When Alice mines 10 blocks to the multisig wallet
    And Alice mines 61 blocks
    And Alice scans the multisig wallet
    And Bob scans the multisig wallet
    # First signing session
    When Alice prepares a multisig transaction sending 0.05 XMR to Bob
    And Bob prepares a multisig transaction sending 0.05 XMR to Bob
    And Alice and Bob exchange preprocess data
    And Bob stores his signature share
    And Alice finalizes the multisig transaction with Bob's share
    And Alice mines 1 block
    # Second signing session - attacker tries to replay old share
    When Alice scans the multisig wallet
    And Bob scans the multisig wallet
    When Alice prepares a multisig transaction sending 0.05 XMR to Bob
    And Bob prepares a multisig transaction sending 0.05 XMR to Bob
    And Alice and Bob exchange preprocess data
    When Alice tries to finalize with Bob's stored share
    Then the finalization fails
