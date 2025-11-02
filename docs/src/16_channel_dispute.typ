== Channel Dispute

In the event of a dispute, such as when one peer becomes unresponsive or attempts to close the channel with an outdated state, the aggrieved peer initiates a force-close procedure. This process leverages the KES to ensure fair resolution and allows the wronged peer to reclaim funds according to the latest agreed channel state.

Disputing a channel requires the following steps:

1. The plaintiff (e.g., the Merchant) submits the latest witness, zero-knowledge proof, and unadapted signatures to the KES to initiate the force close.
2. The KES verifies the submitted proof and signatures.
3. If verification succeeds, the KES opens a challenge window to allow the defendant (e.g., the Customer) an opportunity to respond.
4. During the challenge window, the KES monitors for any valid challenge from the defendant, such as evidence of a newer channel state.
5. If no valid challenge is submitted and the window expires, the plaintiff requests resolution from the KES.
6. The KES releases the defendant's encrypted KES-shard to the plaintiff.
7. The plaintiff reconstructs the defendant's secret using the peer-shard (already in possession) and the newly released KES-shard.
8. The plaintiff adapts the signatures to form a valid closing transaction.
9. The plaintiff broadcasts the closing transaction to the Monero blockchain.
10. Once the transaction is confirmed on the Monero blockchain, the channel transitions to the Closed state.

#include "../diagrams/channel_dispute_sequence.md"
