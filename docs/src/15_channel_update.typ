#import "@preview/note-me:0.5.0": *

== Channel Updates <updateProtocol>

Once a channel is open the parties may transact and update the XMR balance between themselves. This is done entirely off-chain, and happens
near-instantaneously.

#note[
  Under CLSAG, unbroadcast Monero transactions become stale after some time because of how decoy selection is mandated and thus channels
  need to be kept "fresh" by providing periodic zero-delta updates. This is not an issue with FCMP++.
]

Post-FCMP++, the signing mechanism for Monero transactions will be such that decoy selection can be deferred until channel closing@jeffro25.
This will simplify channel updates in two important ways:
- Updates will not need to query the Monero blockchain to select decoys at update time, which presents a significant performance
  improvement.
- Channels can stay open indefinitely, without risk of the closing transaction becoming stale.

#todo()[Complete this]

#include "../diagrams/channel_update_sequence.md"

=== The Verifiable Consecutive One-way Function (VCOF) <vcof>

#todo()[Coming soon (TM)]