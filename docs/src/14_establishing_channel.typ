#import "@preview/note-me:0.5.0": *
#import "metadata/nomenclature.typ": *

== Establishing the Channel <initProtocol>

Establishment turns an agreed set of channel parameters into a funded 2-of-2 wallet and a channel that can accept payments. It runs in six
moves, and the arbiter plays no part in any of them:

1. *Shared wallet.* The two parties run the commit-then-reveal key exchange and end up holding the same 2-of-2 FROST wallet, with joint spend
  key $P = x dot G$ and a joint view key.
2. *Funding declaration.* Each funding party builds — but does not broadcast — the transaction that pays its contribution into the shared
  wallet, and declares the resulting funding output to the counterparty, which verifies it against the balance that party committed to
  (@fundingDeclaration).
3. *Final channel id.* The parties derive a linking tag for each declared funding output (@linkingTagExchange) and bind the channel id to
  them (@channelId): the provisional `XGT` id quoted during negotiation gives way to the final `XGC` id. They also agree on the arbiter that
  will resolve disputes (@arbiterDesign). The id is bound exactly once and cannot be re-bound.
4. *Pre-signing.* In one exchange the parties sign everything the channel needs before any money moves: state 0's exit transactions, the
  initial channel state — each party adapter-signs the counterparty's closing transaction with a fresh secret offset, and hands over that
  offset sealed to the statement that this is the channel's latest state, together with a binding proof — and the cross-signed update record
  for state 0 (@preSigning).
5. *Broadcast.* Only now do the funding parties broadcast, and only once each holds everything the counterparty owes it from step 4. Each
  already holds a signed exit for its own contribution and a record it can present to the arbiter, so neither is exposed to the other
  abandoning the channel.
6. *Open.* Each party confirms that every declared funding output appeared on chain as declared. Once it has, the channel is open and ready
  to use.

Finalization must precede step 4, because every signature exchanged there commits to the channel id.

#note[No SNARKs are required to establish or operate a channel. The arbiter is not contacted during establishment; it holds no state for a
  channel until a dispute is opened.]

#note[*Why signing precedes funding.* Under FCMP++ a spend proves membership against the whole set of outputs on the chain, and that
  membership proof is assembled when the transaction is broadcast rather than when it is signed@jeffro25. A transaction spending a funding
  output therefore needs that output only to be _determined_ — its one-time key and amount commitment fixed — not yet mined. Fixed-size ring
  signatures did not allow this: a spend had to name its decoys and its real input by their positions on the chain, so nothing could be
  signed until the funding output was already confirmed. That forced the funder to part with its money before holding any signature that
  could return it. Removing the constraint is what makes step 5 safe, and it is what lets a channel be funded by both parties at once.]

=== Funding the channel <fundingDeclaration>

A channel is funded by *one output per funding party*. In the common case the customer funds alone and the channel has a single funding
output. When the merchant also wants a balance to spend from — liquidity for refunds, or a genuinely two-sided channel — it contributes a
second. Who funds what is settled during the `New` phase, and the initial balances absorbed into the channel id transcript (@channelId) are
exactly those contributions.

Both funding transactions pay to the same shared address, so the shared wallet scans them identically. That is a problem worth being explicit
about: Monero conceals the sender, so nothing on chain says which output came from whom, and a party could otherwise sit back and claim its
counterparty's deposit as its own contribution. *Each funding party must therefore prove its contribution rather than assert it.*

A declaration names the transaction public key $R_j$ and the output index $i_j$ of the contribution. That is enough for the counterparty to
derive everything it needs about the output, since it holds the shared view key $a$: the one-time key

$ K_j = H_s (a R_j || i_j) dot G + P, $

the amount, and the commitment mask all follow from the same shared secret. What does _not_ follow is who created the transaction, and that is
the part that must be proved. The funder supplies an out-proof for the output — Monero's standard proof of authorship, which demonstrates
that the declaring party built the transaction paying this amount to this address.

#note[An out-proof, not the transaction private key $r_j$. Handing over $r_j$ would prove the same thing, but it would also let the
  counterparty derive every other output of that transaction, exposing the funder's change to a party that has no business seeing it.]

The counterparty checks the declaration against the balance the funder committed to during negotiation and refuses to proceed if the two
disagree. From that point the funding output is fully determined — key, commitment, amount and author — while still existing nowhere but in
the funder's unbroadcast transaction. That is all the remaining steps require.

=== Signing before the money moves <preSigning>

Once every funding output is declared, everything the channel needs can be signed. The parties do so in a single exchange, and only then
broadcast.

*State 0 is a set of exits, not a commitment transaction.* From state 1 onward a channel's closing transaction spends every funding output at
once and pays out the current balance split. State 0 does not: it is one transaction per funding output, each spending that output alone and
returning it to the party that contributed it. In a singly-funded channel that is one refund; in a dual-funded channel it is two independent
ones.

This is not a safety mechanism bolted onto the side. It is what state 0's balance already _is_: the channel's initial balances are exactly the
parties' contributions, so a close at state 0 pays each party its own deposit back either way. Splitting it across one transaction per output
only means that neither party's exit depends on the other party's output existing.

Each exit is adapter-signed like any other state, and completed the same way — cooperatively, when the counterparty hands over its offset, or
through the arbiter when the counterparty has stopped answering.

The same exchange also cross-signs the update record for state 0, $(#raw("id"), 0, h_0)$, exactly as an update cross-signs
$(#raw("id"), i, h_i)$ (@updateProtocol). Here $h_0$ is the canonical hash of state 0's exits taken together: a record carries one hash per
state, while the parties hold one exit each, so the record commits to the pair rather than to either party's own. That record is what an
abandoned party presents to the arbiter, and it is the only thing the arbiter adjudicates on — so without it the recovery described below has
nothing to run on. Two things follow.

*Before the channel opens, broadcast order stops mattering.* Each funding party holds an exit for its own contribution that does not depend on
the counterparty having broadcast anything. A party that publishes as declared and is then abandoned — the counterparty publishes nothing, or
publishes something other than what it declared — closes at state 0 and recovers its deposit, less fees. A party that deviates at broadcast
strands its own money in a wallet it cannot spend from alone, and gains nothing by it. Neither non-participation nor deviation can cost an
honest party its funds, so there is no advantage left in waiting to see what the counterparty does first.

That last claim holds only from the moment a party holds the counterparty's half of the exchange, and it is a binding condition on step 5
rather than a matter of taste: *a funding party must not broadcast until it holds the counterparty's adapted signature, its binding proof and
its record half.* A party that broadcasts earlier has parted with its deposit into a wallet it cannot spend from alone, while holding no exit
it can complete and no record it can present — precisely the exposure the ordering above is supposed to remove. The exchange is sequenced, so
the party that answers second reaches this point first; the party that sends first must wait for the answer.

*After the channel opens, a state-0 exit is simply a stale state.* Broadcasting one once the channel has advanced is the same offence as
broadcasting any superseded closing transaction, and the same machinery answers it: the exit's offset is sealed to the statement $m_0$, and an
attestation for a later state never unseals it (@arbiterDesign). Nothing extra is needed to revoke the exits once they have served their
purpose.

=== Deriving the funding linking tags <linkingTagExchange>

The channel id commits to the linking tag of every funding output (@channelId). For a funding output with one-time key $K_j$, that tag is the
key image its spend will publish:

$ L_j = (d_j + x) dot H_p (K_j), quad d_j = H_s (a R_j || i_j). $

The derivation offset $d_j$ falls out of the shared view key and the declared $R_j$, so both parties already hold it and that part of the tag
needs no protocol at all. The joint spend key $x$ is the part neither party holds alone. Each contributes a _partial tag_

$ T_j^i = lambda_i s_i dot H_p (K_j) $

for its own interpolated MuSig share $lambda_i s_i$, and the two partials are summed. This is the standard Monero multisig key-image
construction, run once per funding output.

*Each partial must be accompanied by a proof of correct contribution, and that proof must be verified before the partials are combined.* The
proof is a proof of equality of discrete logarithms across the two bases $G$ and $H_p (K_j)$,

$ "DLEQ"_(G, H_p (K_j)) (V_i, T_j^i): quad V_i = s dot G and T_j^i = s dot H_p (K_j) "for the same" s, $

against the contributor's interpolated MuSig verification share $V_i = lambda_i s_i dot G$. *The verifier derives $V_i$ itself*, from the two
wallet public keys it has already committed to in step 1; it must never be read from the message carrying the partial. That independence is
what makes the proof binding.

Without it, the exchange is unsafe in a way that is not recoverable. A verifier that holds $H_p (K_j)$ but not $x$ has no public check that a
sum is the true tag, and the exchange is not ordered — one partial necessarily arrives first, so the party that answers can send
$T^2 = L^* - T^1$ for any $L^*$ it likes, a perfectly well-formed group element, and drive the tag to a value of its choosing. A steered tag
lets two live channels share a final id, and therefore a single arbiter statement $m = (#raw("id"), i)$: the attestation obtained by disputing
one channel decrypts the counterparty's offset in the other. Finalization happens once and cannot be re-bound, so an unverified partial
accepted here is unrecoverable for the channel's lifetime.

A verifier must also reject a partial that is the identity or that carries a torsion component, and must reject a combined tag that is the
identity. The identity is the one tag two channels could be forced to share without the attacker knowing any secret, since it is the sum of
any partial and its negation.

#note[Because each tag is taken over its own funding output rather than over the wallet key, it is fresh for every channel without anyone
  having to arrange it: every funding transaction carries its own $R_j$, so $K_j$ and $H_p (K_j)$ differ even between two channels that shared
  a wallet spend key. Reusing a spend key across channels remains a bad idea for the reason given in @overallDesign, but it no longer
  collapses two channels onto one id.]

#note[How the offset composes with the FCMP++ SA+L spend proof, and which base the tag is ultimately fixed against — the key-image generator
  itself or a per-broadcast re-randomization — is the open design item recorded in @arbiterDesign. The construction above states the shape the
  exchange must have; the choice of base follows that decision.]

#figure(include "../diagrams/establish_channel_sequence_a.md", caption: [Establishing a new Channel]) <establish_channel_sequence_a>
#figure(include "../diagrams/establish_channel_sequence_b.md", caption: [Establishing a new Channel, continued])
<establish_channel_sequence_b>


== Wallet transaction protocol <walletTxProtocol>

=== Overview

Grease uses 2-of-2 multisig transactions generated using FROST (Flexible Round-Optimized Schnorr Threshold signatures) combined with adapter
signatures. The roles of customer and merchant are interchangeable, but for simplicity we will refer to the customer as the party initiating
the protocol.

A transaction spending the channel's funding outputs is signed once and assembled later: the parties produce the spend authorization here,
and the membership proof that accompanies it is built at broadcast time against whatever the chain looks like then. A channel funded by two
parties spends two outputs, so the protocol below runs per input — one set of nonces, one partial signature and one adapter signature for
each — and the resulting transaction is complete only when every input's signature is.

==== Phase 1: Customer Preprocessing

The Customer initiates the protocol by generating preprocessing data based on transaction details. This preprocessing step is fundamental to
FROST and involves:

- Creating commitments for the signing process
- Generating nonce values that will be used during signature creation
- Producing data (denoted as $preC$) that encapsulates these commitments.

The Customer then transmits both the preprocessing data and the transaction details to the Merchant.

==== Phase 2: Merchant Preprocessing and Partial Signing

Upon receiving the Customer's data, the Merchant carries out:

1. *Generates its own preprocessing data* ($preM$) using the same transaction details
2. *Creates a partial signature* on the transaction using:
  - The transaction details
  - Its own preprocessing commitments
  - This produces a partial signature, $partialSig(merchant, 0)$.
3. *Adapts the signature* by converting the partial signature into an adapter signature format:
  - Produces an adapted signature tuple $adapterSig(merchant, 0)$
  - For every state — the initial one and each subsequent update — it generates a fresh random witness value ($omega_0^#merchant$ for the
    initial state) that serves as the secret offset for that state.

The adapter signature is a cryptographic construct that allows the Merchant to create a valid-looking signature that is "locked" by a secret
witness value. This signature appears complete but cannot be verified as a standard signature without knowledge of the witness.

The Merchant transmits its preprocessing data and the adapted signature back to the Customer, but notably *withholds* the witness value
$omega_0^#merchant$.

#note[One offset gates a whole state, not a single input. Where a state's transaction spends more than one funding output, the same witness
  $omega_i$ adapts every input's signature, so the state is completed or not completed as a unit and a single sealed offset still opens
  exactly one state. The per-input nonces remain independent.]

==== Phase 3: Customer Verification and Signing

The Customer now performs verification and, if successful, creates its own adapted signature:

- *Verifies the adapter signature* $adapterSig(merchant, 0)$ using the Merchant's public key
- If verification succeeds:
  - Creates its own partial signature $partialSig(cust, 0)$ on the transaction
  - Adapts this signature to produce $adapterSig(cust, 0)$ and witness $omega_0^#cust$
  - Transmits the adapted signature to the Merchant
- If verification fails:
  - Sends an error message to the Merchant
  - Aborts the protocol

==== Phase 4: Final Verification

The Merchant receives the Customer's adapted signature and performs the final verification:

- *Verifies the adapter signature* $adapterSig(cust, 0)$ using the Customer's public key
- If verification succeeds:
  - Sends confirmation to the Customer
  - Both parties now hold valid adapted signatures
- If verification fails:
  - Sends an error message to the Customer
  - Aborts the protocol

#figure(include "../diagrams/multisig_tx_preparation.md", caption: [Creating a new multisig wallet]) <multisig_tx_preparation>
