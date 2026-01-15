#import "@preview/note-me:0.5.0": *
#import "metadata/front-matter.typ": algo
#import "metadata/nomenclature.typ": *

== Channel Updates <updateProtocol>

Once a channel is open the parties may transact and update the XMR balance between themselves. This is done entirely off-chain, and happens
near-instantaneously.

#note[
  Under CLSAG, unbroadcast Monero transactions become stale after some time because of how decoy selection is mandated and thus channels
  need to be kept "fresh" by providing periodic zero-delta updates. This is not an issue with FCMP++.

  Post-FCMP++, the signing mechanism for Monero transactions will be such that decoy selection can be deferred until channel
  closing@jeffro25. This will simplify channel updates in two important ways:
  - Updates will not need to query the Monero blockchain to select decoys at update time, which presents a significant performance
    improvement.
  - Channels can stay open indefinitely, without risk of the closing transaction becoming stale.
]

Either party can initiate a channel update. Since it is usually the merchant, we designate them as the initiator of the update, but the
labels can be switched without loss of generality.

The merchant decides on the delta value, which can be positive (customer pays merchant) or negative (merchant refunds customer). He then
carries out phase 1 on the transaction protocol to create a new Monero transaction reflecting the updated balances.

1. Privately, compute $wn(i)$ using @vcofUpdate from the previous $wn(i-1)$.
2. Generate a DLEQ proof for $PubBjj(i)$ and $PubWEd(i)$.
3. Generate a ZK-SNARK proof $Pvcof(i)$ using @vcofProve.
4. Send the update package to the peer.

Verification consists of:
1. Verify the DLEQ proof for $PubBjj(i)$ and $PubWEd(i)$.
2. Verify the ZK-SNARK proof $Pvcof(i)$ using @vcofVerify.

#figure(include "../diagrams/channel_update_sequence.md", caption: [Updating a Channel]) <channel_update_sequence>

#note[
  The actual implementation may streamline communication rounds by batching messages together. In particular, the VCOF messages and
  transaction protocol messages can be sent together to reduce the total number of round trips.
]

=== The Verifiable Consecutive One-way Function (VCOF) <vcof>

The core idea behind AuxChannel is the Verifiable Consecutive One-way Function (VCOF). The VCOF is used to generate new adapter signature
offsets for each channel update in that only the party who generated the new offset can compute it, but both parties can verify that it is
valid and consecutive to the previous offset.

As such, the VCOF has the following security requirements:

- _validity_: It requires that for any message, the encrypted signature can be verified.
- _unforgeability_: It is hard to forge a valid encrypted signature.
- _recoverability_: Informally speaking, recoverability requires that it is easy to recover a decryption key by knowing the encrypted
  signature and its original signature.

These requirements are standard for any encrypted signature scheme. There are three additional requirements specific to the VCOF:

- _Consecutiveness_: requires that the decryption-encryption key-pair used in the $i^"th"$ update of the VCOF is derived from the decryption
  key of the $(i − 1)^"th"$ update.
- _Consecutive verifiability_: Given two VCOF outputs and the corresponding proof, anyone can be convinced that the outputs are consecutive,
  meaning that the new secret is generated from applying the VCOF to the previous secret.
- _One-wayness_: given $wn(i)$, no one can derive any $wn(j)$, where $0 ≤ j < i$. This is important because, without one-wayness, when a
  channel is closed co-operatively, a malicious counterparty could broadcast _any_ previous channel state to the blockchain by computing a
  previous state.

=== Grease VCOF

The Grease VCOF makes use of a ZK-SNARK to produce the following update algorithm (`KeyUpdate` using the AuxChannel parlance):

#algo(
  title: [VcofUpdate($i, wn(i)$)],
  caption: [Grease VCOF Update function],
)[
  + $wn(i+1)$ = H2F($wn(i)$, $i$)
  + return $( wn(i+1), i+1 )$
] #label("vcofUpdate")


#algo(
  title: [VcofProve($i, wn(i), wn(i+1), PubBjj(i), PubBjj(i+1)$)],
  caption: [The ZK-SNARK Grease `VCOFProve` function],
)[
  + $witness$ = H2F($wn(i)$, $i$)
  + `assert` $witness == wn(i+1)$
  + $P_1 = wn(i+1) dot.c Gbjj$
  + `assert` $PubBjj(i+1) == P_1$
  + $P_2 = wn(i+1) dot.c Gbjj$
  + `assert` $PubBjj(i+1) == P_2$
  + return $Pvcof(i+1)$
] #label("vcofProve")

#algo(
  title: [VcofVerify($i, PubBjj(i), PubBjj(i-1), Pvcof(i)$)],
  caption: [Grease VCOF Verify function],
)[
  + verify ZK-SNARK proof $Pvcof(i), PubBjj(i), PubBjj(i-1)$
  + verify DLEQ proof for $PubBjj(i), PubWEd(i)$
] #label("vcofVerify")

Informal security arguments for the Grease VCOF:
- One-wayness: If `H2F` is selected to be a suitable one-way hash function, then the Grease `KeyUpdate` function, @vcofUpdate, is also
  one-way.
- Consecutiveness: If @vcofUpdate is used to generate $wn(i+1)$ from $wn(i)$, then the proof generated by @vcofProve will verify under
  @vcofVerify. This is because the prover knows $wn(i)$ and can compute all the necessary values to satisfy the constraints in @vcofProve.
- Consecutive verifiability: The ZK-SNARK proof produced by @vcofProve convinces any verifier running @vcofVerify that $wn(i+1)$ was
  correctly derived from $wn(i)$ using @vcofUpdate without revealing either secret value.

