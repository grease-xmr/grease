== Establishing the Channel

Establishing a channel to accept payments requires the following preparatory steps:
1. Both parties collaboratively create a new shared multisig wallet to hold the channel funds.
2. Each party watches the Monero blockchain for the funding transaction to confirm it has been included in a block.
3. Each party encrypts their spend key to the KES.
4. The merchant creates a new KES commitment on the ZK-chain smart contract and commits the encrypted shares to it.
5. The merchant provides a proof of the KES commitment to the customer who can verify that the KES was set up correctly.
6. Each party creates the initial ZK proof for their initial secret (witness) and shares it with the counterparty.
7. The customer funds the multisig wallet with the agreed initial balance.
8. Once the funding transaction is confirmed, the channel is open and ready to use.

#include "../diagrams/establish_channel_sequence.md"
