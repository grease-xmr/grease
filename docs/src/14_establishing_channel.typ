#import "@preview/note-me:0.5.0": *

== Establishing the Channel <initProtocol>

Establishing a channel to accept payments requires the following preparatory steps:
1. Both parties collaboratively create a new shared multisig wallet to hold the channel funds.
2. Each party calculates a unique, shared secret for the channel, $kappa$ (see @channelKeys).
3. Each party watches the Monero blockchain for the funding transaction to confirm it has been included in a block.
4. Each party encrypts their initial adapter signature offset to the KES.
5. The merchant creates a new KES commitment on the ZK-chain smart contract and commits the encrypted shares to it.
6. The merchant provides a proof of the KES commitment to the customer who can verify that the KES was set up correctly.
7. Each party creates the initial proof for their initial secret (witness) and shares it with the counterparty.
8. The customer funds the multisig wallet with the agreed initial balance.
9. Once the funding transaction is confirmed, the channel is open and ready to use.

#note[No SNARKs are required for channel establishment. However, if the KES is deployed on a ZK-enabled chain, the KES proof of knowledge
  proofs should be calculated in a zero-knowledge manner.]

#include "../diagrams/establish_channel_sequence.md"
