#import "@preview/note-me:0.5.0": *
#import "metadata/front-matter.typ": algo
#import "metadata/nomenclature.typ": *

== Channel Updates <updateProtocol>

Once a channel is open the parties may transact and update the XMR balance between themselves. This is done entirely off-chain, and happens
near-instantaneously.

#note[
  Under FCMP++, the membership (decoy) set for a spend is chosen only when a transaction is finally broadcast@jeffro25,
  rather than when it is signed. This has two consequences for channel updates:
  - An update never needs to query the Monero blockchain to select decoys, a significant performance improvement.
  - A channel can stay open indefinitely: its pre-signed closing transaction can never become stale.
]

Either party can initiate a channel update. Since it is usually the merchant, we designate them as the initiator of the update, but the
labels can be switched without loss of generality.

The merchant decides on the delta value, which can be positive (customer pays merchant) or negative (merchant refunds customer). He then
carries out phase 1 on the transaction protocol to create a new Monero transaction reflecting the updated balances.

1. Privately, generate a fresh random offset $wn(i)$ for the counterparty's copy of the new state, and adapter-sign the counterparty's
  commitment transaction with it.
2. Encrypt $wn(i)$ to the statement $m_i = (#raw("id"), i)$ under the arbiter's public key, producing a _verifiably encrypted offset_ for the counterparty
  together with a binding proof that the ciphertext seals the offset of the adapter point used in this state (@attestation).
3. Cross-sign the update record $(#raw("id"), i, h_i)$, where $h_i$ is the canonical hash of the new state's closing transaction.
4. Send the update package — the adapter signature, the verifiably encrypted offset and its binding proof, and the signed record — to the peer.

Verification consists of:
1. Verify the adapter signature on the local party's commitment transaction.
2. Verify the binding proof on the counterparty's verifiably encrypted offset.
3. Verify the counterparty's signature on the update record, and countersign it.

#figure(include "../diagrams/channel_update_sequence.md", caption: [Updating a Channel]) <channel_update_sequence>

#note[
  The actual implementation may streamline communication rounds by batching messages together. In particular, the verifiably encrypted offset and update-record
  messages can be sent together with the transaction protocol messages to reduce the total number of round trips.
]

Each state's offset is generated independently at random, so no offset reveals anything about any other. A party that later closes the
channel at the agreed latest state learns nothing that would let it complete an _earlier_ state, and a stale state can never be closed
because the arbiter will never attest its statement (@arbiterDesign). There is therefore no need for the offsets to chain to one another,
and no zero-knowledge circuit is evaluated on an update — a channel update is a handful of Schnorr operations plus one verifiably encrypted
offset and its binding proof. The proof is essentially the whole of an update's bandwidth: 23,641 bytes at the parameters pinned in
@bindingProof (@proofSize), against well under a kilobyte for the adapter signature, the record and its two signatures combined.

