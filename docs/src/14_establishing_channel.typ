#import "@preview/note-me:0.5.0": *
#import "metadata/nomenclature.typ": *

== Establishing the Channel <initProtocol>

Establishing a channel to accept payments requires the following preparatory steps:
1. Both parties collaboratively create a new shared multisig wallet to hold the channel funds.
2. The parties exchange their shares of the funding output's linking tag $L_F$ and finalize the channel id (@channelId): the provisional
  `XGT` id quoted during negotiation gives way to the final `XGC` id, which commits to the funding output. They also agree on the arbiter to
  be used for disputes (@arbiterDesign). Finalization precedes step 4, because every signature in the initial-state package commits to the
  channel id, and it happens exactly once — an id that is already final cannot be re-bound.
3. Each party watches the Monero blockchain for the funding transaction to confirm it has been included in a block.
4. The parties prepare the initial channel state: each adapter-signs the counterparty's closing transaction with a fresh secret offset, and
  hands the counterparty a _verifiably encrypted offset_ — that offset encrypted to the statement that this is the channel's latest state.
5. Each party verifies the binding proof accompanying the counterparty's verifiably encrypted offset before accepting the initial state.
6. The customer funds the multisig wallet with the agreed initial balance.
7. Once the funding transaction is confirmed, the channel is open and ready to use.

#note[No SNARKs are required to establish or operate a channel. The arbiter is not contacted during establishment; it holds no state for a
  channel until a dispute is opened.]

#figure(include "../diagrams/establish_channel_sequence_a.md", caption: [Establishing a new Channel]) <establish_channel_sequence_a>
#figure(include "../diagrams/establish_channel_sequence_b.md", caption: [Establishing a new Channel, continued])
<establish_channel_sequence_b>


== Wallet transaction protocol <walletTxProtocol>

=== Overview

Grease uses 2-of-2 multisig transactions generated using FROST (Flexible Round-Optimized Schnorr Threshold signatures) combined with adapter
signatures. The roles of customer and merchant are interchangeable, but for simplicity we will refer to the customer as the party initiating
the protocol.

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
