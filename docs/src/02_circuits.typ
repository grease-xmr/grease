#import "metadata/nomenclature.typ":*

= The Zero-Knowledge Contracts

== Grease payment channel lifetime

=== Channel Initialization

At *initialization*, two peers will:
+ communicate out-of-band, share connection information and agree to a fixed balance amount in XMR,
+ connect over a dedicated private communication channel,
+ create a new temporary Monero 2-of-2 multisignature wallet where each peer has full view access and 1-of-2 spend access,
+ create a KES subscription,
+ create proofs of randomizing a new root secret,
+ create proofs of using that root secret for an adaptor signature,
+ create proofs of sharing that root secret with the KES,
+ verify those proofs from the peer,
+ create a shared closing transaction where both peers receive a $v_"out"$ output to their private Monero wallet with
the exact amount of their starting balance using the adaptor signature, so that each peer has 3-of-4 pieces of information needed to broadcast the transaction,
+ verify the correctness of the closing transaction using the shared view key, the unadapted signatures and the adaptor statements,
+ create a shared funding transaction where both peers provide a $v_"in"$ input from their private Monero wallet with the exact amount of their balance,
+ verify the correctness of the funding transaction using the shared view key,
+ activate the KES with the root secret shares,
+ and finally broadcast the funding transaction to Monero.

=== Channel Update

When updating the channel balance, the two peers will:
+ update the balance out-of-band,
+ create proofs of deterministically updating the previous secret,
+ create proofs of using the updated secret for a new adaptor signature,
+ verify those proofs from the peer,
+ update the shared closing transaction where both peers receive an updated $v_"out"$ output to their private Monero wallet with the new amount of their balance using the new adaptor signature, so that each peer has the new 3-of-4 pieces of information needed to broadcast the transaction,
+ and finally verify the correctness of the updated closing transaction using the shared view key, the new unadapted signatures and the new adaptor statements.
+ Repeat as often as desired.

=== Channel Closure

When closing the channel, the two peers will:
+ share their most recent secret,
+ adapt the unadapted signature of the closing transaction to gain the 4-of-4 pieces of information needed to broadcast the transaction,
+ and finally broadcast the closing transaction to Monero.

=== Channel Dispute

In case of a *dispute* a plaintiff will:
+ provide the unadapted signatures of the closing transaction to the KES.

If a dispute is detected the other peer will:
+ respond with the adapted signature of the closing transaction to the KES,
+ or simply broadcast the closing transaction to Monero.

If a dispute is lodged and the other peer does not respond within the dispute period:
+ the KES will provide the saved root secret share of the violating peer to the wronged peer,
+ the wronged peer will reconstruct the violating peer's root secret,
+ the wronged peer may deterministically update the the secret to find _any_ shared secret that can be used to create a valid Monero transaction.
#footnote[Under CLSAG, older transactions may become stale and be rejected by the network. This limitation will be lifted post-FCMP++.],
+ the wronged peer will adapt the unadapted signature of the closing transaction using the most recent secret to gain the 4-of-4 pieces of information needed to broadcast the transaction,
+ and finally the wronged will broadcast the closing transaction to Monero.



== Grease Protocol

The Grease protocol operates in four stages: initialization, update, closure and dispute. The ZKPs are used only in the initialization and update stage, as the closure and dispute do not need further verification to complete.

=== Initialization

==== Motivation

The two peers will decide to lock their declared XMR value and create a Grease payment channel so that they can begin transacting in the channel and not on the Monero network.

==== Preliminary

For the initialization stage to begin, the peers must agree upon a small amount of information:

#table(
  columns: 2,
  [*Resource*], [],
  [Channel ID], [The identifier of the private communications channel. This will include the public key identifier of the peers and information about the means of communications between them.],
  [Locked Amount], [The two values in XMR (with either but not both allowed as zero) that the peers will lock into the channel during its lifetime.],
)

At the start of the initialization stage the peers provide each other with the following resources and information:

#table(
  columns: 3,
  table.cell(colspan: 3, [*Before Initialization*]),
  [*Resource*], [*Visibility*], [],
  [$PubBjj("peer")$], [Public], [The public key/curve point on Baby Jubjub for the peer],
  [$PubBjj("KES")$], [Public], [The public key/curve point on Baby Jubjub for the KES],
  [$nu_"peer"$], [Public], [Random 251 bit value, provided by the peer (`nonce_peer`)],
)

The peers will also agree on a third party agent to host the Key Escrow Service (KES). When the peers agree on the
particular KES, the publicly known public key to this service is shared as $PubBjj("KES")$.

Each participant will create a new one-time key pair to use for communication with the KES in the case of a dispute. The peers share the public keys with each other, referring to the other's as $PubBjj("peer")$.

During the interactive setup, the peers send each other a nonce, $nu_"peer"$, that guarantees that critically important data must be new and unique for this channel. This prevents the reuse of old data held by the peers.

The ZKP protocols prove that the real private keys are used correctly and that if a dispute is necessary, it will succeed.

==== Initialization protocol

The Grease protocol requires the generation and sharing of the ZKPs. The public data and the small proofs are shared
between peers, then are validated as a means to ensure protocol conformity before *MoNet* protocol stage 3 begins.

Each peer generates a set of secret random values to ensure security of communications, listed in @tbl-init-input. These not shared with the peer.

#figure(
    caption: "Inputs to ZKPs for the Grease Initialization Protocol",
    table(
      columns: 3,
      table.header([*Input*], [*Visibility*], []),
      [$nu_omega_0$], [Private], [Random 251 bit value (`blinding`)],
      [$a_1$], [Private], [Random 251 bit value],
      [$nu_1$], [Private], [Random 251 bit value (`r_1`)],
      [$nu_2$], [Private], [Random 251 bit value (`r_2`)],
      [$nu_"DLEQ"$], [Private], [Random 251 bit value (`blinding_DLEQ`)],
    )
) <tbl-init-input>

The ZKP operations produce the set of output values listed in @tbl-init-output. The publicly visible values must be
shared with the peer in addition to the generated proofs while the privately visible values must be stored for later
use.

#figure(
    caption: "Outputs of ZKPs for the Grease Initialization Protocol",
    table(
      columns: 3,
      table.header([*Output*], [*Visibility*], []),
      [$T_0$], [Public], [The public key/curve point on Baby Jubjub for $witness_0$],
      [$witness_0$], [Private], [The root private key protecting access to the user's locked value (`witness_0`)],
      [$c_1$], [Public], [`Feldman commitment 1` (used in tandem with `Feldman commitment 0` $=T_0$), which is a public key/curve point on Baby Jubjub],
      [$sigma_1$], [Private], [The split of $witness_0$ shared with the peer (`share_1`)],
      [$Phi_1$], [Public], [The ephemeral public key/curve point on Baby Jubjub for message transportation to the peer (`fi_1`)],
      [$chi_1$], [Public], [The encrypted value of $sigma_1$ (`enc_1`)],
      [$sigma_2$], [Private], [The split of $witness_0$ shared with the KES (`share_2`)],
      [$Phi_2$], [Public], [The ephemeral public key/curve point on Baby Jubjub for message transportation to the KES (`fi_2`)],
      [$chi_2$], [Public], [The encrypted value of $sigma_2$ (`enc_2`)],
      [$S_0$], [Public], [The public key/curve point on Ed25519 for $witness_0$],
      [C], [Public], [The Fiat–Shamir heuristic challenge (`challenge_bytes`)],
      [$Delta_bjj$], [Private], [Optimization parameter (`response_div_BabyJubjub`)],
      [$rho_bjj$], [Public], [The Fiat–Shamir heuristic challenge response on the Baby Jubjub curve (`response_BabyJubJub`)],
      [$Delta_ed$], [Private], [Optimization parameter (`response_div_BabyJubJub`)],
      [$rho_ed$], [Public], [The Fiat–Shamir heuristic challenge response on the Ed25519 curve (`response_div_ed25519`)],
    )
) <tbl-init-output>

During the initialization stage, the following operations are performed:

- #link(label("verify-witness0"), [*VerifyWitness0*])
- #link(label("verify-witness-sharing"), [*VerifyWitnessSharing*])
- #link(label("verify-equivalent-modulo"), [*VerifyEquivalentModulo*])
- #link(label("verify-dleq"), [*VerifyDLEQ*])

Particular details about these operations can be found in #ref(<zkp-operations>).

==== Post-initialization

After receiving the publicly visible values and ZK proofs from the peer, the Grease protocol requires the ZKP verification operations to ensure protocol conformity.

Once verified, the variables listed in @tbl-init-after must be stored. With these outputs the the initialization stage is complete and the channel is open. The peers can now transact and update the channel state or close the channel and receive the locked XMR value in the *Monero Refund Wallet*.


#figure(
    caption: "Resources and Information after Grease Initialization",
    table(
      columns: 2,
      table.header([*Resource*], []),
      [$Phi_1$], [The ephemeral public key/curve point on Baby Jubjub for message transportation from the peer (`fi_1`)],
      [$chi_1$], [The encrypted value of $sigma_1$ (`enc_1`) for the peer's $witness_0$],
      [$witness_0$], [The root private key protecting access to the user's locked value (`witness_0`)],
      [$S_0$], [The public key/curve point on Ed25519 for the peer's $witness_0$],
    )
) <tbl-init-after>

=== Channel Update

==== Motivation

Once a channel is open the peers may decide to transact and update the XMR balance between the peers. The only requirement is that the peers agree on the change in ownership of the *Locked Amount*.

Note that with an open channel there is no internal reason to perform an update outside of a peer-initiated change. However, the current Monero protocol requires that a newly broadcast transaction be created within a reasonable timeframe. As such, existing open channel should create a "zero delta" update at reasonable timeframes to ensure the channel may be closed arbitrarily. The specifics on this are outside of current scope.

Note that post-FCMP++, the signing mechanism for Monero transactions will be such that decoy selection can be deferred
until channel closing@jeffro25. This will simplify channel updates in two important ways:
- Updates will not need to query the Monero blockchain to select decoys at update time, which present a significant performance improvement.
- Channels can stay open indefinitely, without risk of the closing transaction becoming stale.

==== Preliminary

For the update stage to begin, the peers must agree upon a small amount of information:

#table(
  columns: 2,
  [*Resource*], [],
  [$Delta$], [The change in the two values in XMR (positive or negative) from the previous stage. This is a single
  number since the *Locked Amount* must stay the same.],
)

==== Update protocol

Grease replaces the MoNet update protocol completely with the generation and sharing of update ZKPs. The public data
and the small proofs are shared between peers, then are validated as a means to ensure protocol conformity.

The ZKP operations require the previous $witness_i$ (now $witness_(i-1)$) and a random value to ensure security of
communications, as described in @tbl-update-input. These are not shared with the peer.

#figure(
  caption: "Inputs to ZKPs for the Grease Update Protocol",
    table(
      columns: 3,
      table.header([*Input*], [*Visibility*], []),
      [$witness_(i-1)$], [Private], [The current private key protecting access to close the payment channel (`witness_im1`)],
      [$nu_"DLEQ"$], [Private], [Random 251 bit value (`blinding_DLEQ`)],
    )
) <tbl-update-input>

The ZKP operations produce the set of output values listed in @tbl-update-output. The public values must be shared with
the peer in addition to the generated proofs while the private values are stored for later use.

#figure(
    caption: "Outputs of ZKPs for the Grease Update Protocol",
    table(columns: 3,
      table.header([*Output*], [*Visibility*], []),
      [$T_(i-1)$], [Public], [The public key/curve point on Baby Jubjub for $witness_(i-1)$],
      [$T_i$], [Public], [The public key/curve point on Baby Jubjub for $witness_i$],
      [$witness_i$], [Private], [The next private private key protecting access to close the payment channel (`witness_i`)],
      [$S_i$], [Public], [The public key/curve point on Ed25519 for $witness_i$],
      [C], [Public], [The Fiat–Shamir heuristic challenge (`challenge_bytes`)],
      [$Delta_bjj$], [Private], [Optimization parameter (`response_div_BabyJubjub`)],
      [$rho_bjj$], [Public], [The Fiat–Shamir heuristic challenge response on the Baby Jubjub curve (`response_BabyJubJub`)],
      [$Delta_ed$], [Private], [Optimization parameter (`response_div_BabyJubJub`)],
      [$rho_ed$], [Public], [The Fiat–Shamir heuristic challenge response on the Ed25519 curve (`response_div_ed25519`)],
      [$C$], [Public], [The Fiat–Shamir heuristic challenge (`challenge_bytes`)],
      [$R_bjj$], [Public], [DLEQ commitment 1, which is a public key/curve point on Baby Jubjub (`R_1`)],
      [$R_ed$], [Public], [DLEQ commitment 2, which is a public key/curve point on Ed25519 (`R_2`)],
    )
) <tbl-update-output>

During the update stage, the following operations are performed:

- #link(<verify-cof>, [*VerifyCOF*])
- #link(<verify-equivalent-modulo>, [*VerifyEquivalentModulo*])
- #link(<verify-dleq>, [*VerifyDLEQ*])

Particular details about these operations can be found in #ref(<zkp-operations>).

==== Post-update

After receiving the publicly visible values and ZK proofs from the peer, the Grease protocol requires the ZKP verification operations to ensure protocol conformity.

Once verified, the variables listed in @tbl-update-post must be stored:

#figure(
    caption: "Variables to be stored after every channel update",
    table(
      columns: 2,
      table.header([*Resource*], []),
      [$witness_i$], [The current private key protecting access to close the payment channel (`witness_i`)],
      [$S_i$], [The public key/curve point on Ed25519 for the peer's $witness_i$],
    )
) <tbl-update-post>

With these outputs the the update stage is complete and the channel remains open. The peers can now transact further updates or close the channel and receive the locked XMR value *Channel Balance* in the *Monero Refund Wallet*.

= Grease ZKP Operations <zkp-operations>

The Grease protocol requires the creation and sharing of a series of Zero Knowledge proofs (ZKPs) as part of the lifetime of a payment channel. Most are Non-Interactive Zero Knowledge (NIZK) proofs in the form of Turing-complete circuits created using newly-established Plonky-based proving protocols. The others are classical interactive protocols with verification.

== VerifyWitness0 <verify-witness0>

=== Inputs
#table( columns: 3,
  [*Input*], [*Visibility*], [],
  [$nu_"peer"$], [Public], [Random 251 bit value, provided by the peer (`nonce_peer`)],
  [$nu_omega_0$], [Private], [Random 251 bit value (`blinding`)],
)

=== Outputs
#table( columns: 3,
  [*Output*], [*Visibility*], [],
  [$T_0$], [Public], [The public key/curve point on Baby Jubjub for $witness_0$],
  [$witness_0$], [Private], [The root private key protecting access to the user's locked value (`witness_0`)],
)

=== Summary

The *VerifyWitness0* operation is a Noir ZK circuit using the UltraHonk prover/verifier. It receives the provided random entropy inputs and produces the deterministic outputs. The circuit is ZK across the inputs, so no information is gained about the private inputs even with knowledge of the private output. The $T_0$ output is used for the further *VerifyEquivalentModulo* and *VerifyDLEQ* operations.

The operation uses the *blake2s* hashing function for its one-way random oracle simulation.

The scalar order of the Baby Jubjub curve is represented here by $L_bjj$.

=== Methods

$
  C = hashOf("blake2s", "HEADER" || nu_"peer" || nu_omega_0) \
  omega_0 = C mod L_bjj \
  T_0 = omega_0 dot.c G_bjj
$

== FeldmanSecretShare_2_of_2

=== Inputs
#table( columns: 3,
  [*Input*], [*Visibility*], [],
  [$witness_0$], [Private], [The root private key protecting access to the user's locked value (`secret`)],
  [$a_1$], [Private], [Random 251 bit value],
)

=== Outputs
#table( columns: 3,
  [*Output*], [*Visibility*], [],
  [$T_0$], [Public], [Feldman commitment 0, which is the public key/curve point on Baby Jubjub for $witness_0$],
  [$c_1$], [Public], [Feldman commitment 1, which is a public key/curve point on Baby Jubjub],
  [$sigma_1$], [Private], [The split of $witness_0$ shared with the peer (`share_1`)],
  [$sigma_2$], [Private], [The split of $witness_0$ shared with the KES (`share_2`)],
)

=== Summary

The *FeldmanSecretShare_2_of_2* operation is a Noir ZK circuit using the UltraHonk prover/verifier. It receives the provided secret data and random entropy inputs. The output are the two perfectly binding Feldman commitments and the two encoded split shares to send to the destinations. The circuit is not ZK across the inputs so that full knowledge of the private outputs can reconstruct the private inputs.

The outputs are used for the further *VerifyEncryptMessage*, *VerifyFeldmanSecretShare_peer*, *VerifyFeldmanSecretShare_KES*, and *ReconstructFeldmanSecretShare_2_of_2* operations.

The scalar order of the Baby Jubjub curve is represented here by $L_bjj$.

Note that for the peer to verify the validity of the secret sharing protocol, the calculation is:
$
  "VerifyFeldmanSecretShare_peer"(T_0, c_1, sigma_1)
$

Note that for the KES to verify the validity of the secret sharing protocol, the calculation is:
$
  "VerifyFeldmanSecretShare_KES"(T_0, c_1, sigma_2)
$

Note that for reconstructing the secret input $witness_0$, the calculation is:
$
  omega_0 = "ReconstructFeldmanSecretShare_2_of_2"(sigma_1, sigma_2)
$

=== Methods

$
  c_1 = a_1 dot.c G_bjj \
  sigma_1 = -(omega_0 + a_1) mod L_bjj \
  sigma_2 = 2*omega_0 + a_1 mod L_bjj
$

== ReconstructFeldmanSecretShare_2_of_2

=== Inputs
#table( columns: 3,
  [*Input*], [*Visibility*], [],
  [$sigma_1$], [Private], [The split of $witness_0$ shared with the peer (`share_1`)],
  [$sigma_2$], [Private], [The split of $witness_0$ shared with the KES (`share_2`)],
)

=== Outputs
#table( columns: 3,
  [*Output*], [*Visibility*], [],
  [$witness_0$], [Private], [The root private key protecting access to the user's locked value (`secret`)],
)

=== Summary

The *ReconstructFeldmanSecretShare_2_of_2* operation is a reconstruction protocol and is language independent. It receives the two split shares as inputs and outputs the original $witness_0$ secret.

The scalar order of the Baby Jubjub curve is represented here by $L_bjj$.

=== Methods

$
  omega_0 = sigma_1 + sigma_2 mod L_bjj
$

== VerifyFeldmanSecretShare_peer

=== Inputs
#table( columns: 3,
  [*Input*], [*Visibility*], [],
  [$T_0$], [Public], [Feldman commitment 0, which is the public key/curve point on Baby Jubjub for $witness_0$],
  [$c_1$], [Public], [Feldman commitment 1, which is a public key/curve point on Baby Jubjub],
  [$sigma_1$], [Private], [The split of $witness_0$ shared with the peer (`share_1`)],
)

=== Outputs

There are no outputs.

=== Summary

The *VerifyFeldmanSecretShare_peer* operation is a verification protocol and is language independent. This operation is redundant, in that the successful verification of the previous *FeldmanSecretShare_2_of_2* operation with the same publicly visible parameters implies that this operation will succeed.

=== Methods

$
  "assert"(sigma_1 dot.c G_bjj == -(T_0 + c_1))
$

== VerifyFeldmanSecretShare_KES

=== Inputs
#table( columns: 3,
  [*Input*], [*Visibility*], [],
  [$T_0$], [Public], [Feldman commitment 0, which is the public key/curve point on Baby Jubjub for $witness_0$],
  [$c_1$], [Public], [Feldman commitment 1, which is a public key/curve point on Baby Jubjub],
  [$sigma_2$], [Private], [The split of $witness_0$ shared with the KES (`share_2`)],
)

=== Outputs

There are no outputs.

=== Summary

The *VerifyFeldmanSecretShare_peer* operation is a verification protocol and is language independent. This operation is not redundant, in that the successful verification of the previous *FeldmanSecretShare_2_of_2* operation with the same publicly visible parameters implies that this operation will succeed, but the conditions are different.

This operation will be implemented by the KES in its own native implementation language where the successful verification of the previous *FeldmanSecretShare_2_of_2* operation cannot be assumed. As such, this operation will exist and can called independently of any other operations.

=== Methods

$
  "assert"(sigma_2 dot.c G_bjj == 2 dot.c T_0 + c_1)
$

== VerifyEncryptMessage

=== Inputs
#table( columns: 3,
  [*Input*], [*Visibility*], [],
  [$sigma$], [Private], [The secret 251 bit message (`message`)],
  [$nu$], [Private], [Random 251 bit value (`r`)],
  [$Pi$], [Public], [The public key/curve point on Baby Jubjub for the destination],
)

=== Outputs
#table( columns: 3,
  [*Output*], [*Visibility*], [],
  [$Phi$], [Public], [The ephemeral public key/curve point on Baby Jubjub for message transportation (`fi`)],
  [$chi$], [Public], [The encrypted value of $sigma$ (`enc`)],
)

=== Summary

The *VerifyEncryptMessage* operation is a Noir ZK circuit using the UltraHonk prover/verifier. It receives the provided secret data and random entropy inputs. The output are the perfectly binding public key commitment and the perfectly hiding encrypted scaler value to send to the destinations. The circuit is ZK across the inputs since the outputs are publicly visible.

The method of encryption is the ECDH (Elliptic-curve Diffie–Hellman) key agreement protocol. The operation uses the *blake2s* hashing function for its shared secret commitment simulation. Note that the unpacked form of the ephemeral key is used for hashing, instead of the standard $"PACKED"()$ function.

Note that for reconstructing the secret input $sigma$ given the private key $kappa$ where $Pi = kappa dot.c G_bjj$, the calculation is:

$
  (Pi, sigma) = "DecryptMessage"(kappa, Phi, chi) \
$

Note that this operation does not call for the use of HMAC or other message verification protocol due to the simplicity of the interactive steps and their resistance to message tampering. A more complicated or distributed protocol would requires this attack prevention.

The scalar order of the Baby Jubjub curve is represented here by $L_bjj$.

=== Methods

$
  Phi = nu dot.c G_bjj \
  nu_Pi = nu dot.c Pi \
  C = hashOf("blake2s", nu_Pi."x" || nu_Pi."y") \
  s = C mod L_bjj \
  chi = sigma + s mod L_bjj \
$

== DecryptMessage

=== Inputs
#table( columns: 3,
  [*Input*], [*Visibility*], [],
  [$kappa$], [Private], [The private key for the public key $Pi$],
  [$Phi$], [Public], [The ephemeral public key/curve point on Baby Jubjub for message transportation (`fi`)],
  [$chi$], [Public], [The encrypted value of $sigma$ (`enc`)],
)

=== Outputs
#table( columns: 3,
  [*Output*], [*Visibility*], [],
  [$Pi$], [Public], [The public key/curve point on Baby Jubjub for the destination],
  [$sigma$], [Private], [The secret 251 bit message (`message`)],
)

=== Summary

The *DecryptMessage* operation is a verification protocol and is language independent.

The method of decryption is the ECDH (Elliptic-curve Diffie–Hellman) key agreement protocol. The operation uses the *blake2s* hashing function for its shared secret commitment simulation. Note that the unpacked form of the ephemeral key is used for hashing, instead of the standard $"PACKED"()$ function.

The scalar order of the Baby Jubjub curve is represented here by $L_bjj$.

=== Methods

$
  Pi = kappa dot.c G_bjj \
  kappa_Phi = kappa dot.c Phi \
  C = H_"blake2s" (kappa_Phi."x" || kappa_Phi."y") \
  s = C mod L_bjj \
  sigma = chi - s mod L_bjj \
$

== VerifyWitnessSharing <verify-witness-sharing>

=== Inputs
#table( columns: 3,
  [*Input*], [*Visibility*], [],
  [$witness_0$], [Private], [The root private key protecting access to the user's locked value (`witness_0`)],
  [$a_1$], [Private], [Random 251 bit value],
  [$nu_1$], [Private], [Random 251 bit value (`r_1`)],
  [$PubBjj("peer")$], [Public], [The public key/curve point on Baby Jubjub for the peer],
  [$nu_2$], [Private], [Random 251 bit value (`r_2`)],
  [$PubBjj("KES")$], [Public], [The public key/curve point on Baby Jubjub for the KES],
)

=== Outputs
#table( columns: 3,
  [*Output*], [*Visibility*], [],
  [$c_1$], [Public], [`Feldman commitment 1` (used in tandem with `Feldman commitment 0` $=T_0$), which is a public key/curve point on Baby Jubjub],
  [$sigma_1$], [Private], [The split of $witness_0$ shared with the peer (`share_1`)],
  [$Phi_1$], [Public], [The ephemeral public key/curve point on Baby Jubjub for message transportation to the peer (`fi_1`)],
  [$chi_1$], [Public], [The encrypted value of $sigma_1$ (`enc_1`)],
  [$sigma_2$], [Private], [The split of $witness_0$ shared with the KES (`share_2`)],
  [$Phi_2$], [Public], [The ephemeral public key/curve point on Baby Jubjub for message transportation to the KES (`fi_2`)],
  [$chi_2$], [Public], [The encrypted value of $sigma_2$ (`enc_2`)],
)

=== Summary

The *VerifyWitnessSharing* operation is a Noir ZK circuit using the UltraHonk prover/verifier. It passes through the the provided inputs and calls the *FeldmanSecretShare_2_of_2* and *VerifyEncryptMessage* operations.

=== Methods

$
  (c_1,sigma_1,sigma_2) = "FeldmanSecretShare_2_of_2"(omega_0,a_1) \
  (Phi_1,chi_1) = "VerifyEncryptMessage"(sigma_1,nu_1,Pi_"peer") \
  (Phi_2,chi_2) = "VerifyEncryptMessage"(sigma_2,nu_2,Pi_"KES") \
$

== VerifyCOF <verify-cof>

=== Inputs
#table( columns: 3,
  [*Input*], [*Visibility*], [],
  [$witness_(i-1)$], [Private], [The current private key protecting access to close the payment channel (`witness_im1`)],
)

=== Outputs
#table( columns: 3,
  [*Output*], [*Visibility*], [],
  [$T_(i-1)$], [Public], [The public key/curve point on Baby Jubjub for $witness_(i-1)$],
  [$T_i$], [Public], [The public key/curve point on Baby Jubjub for $witness_i$],
  [$witness_i$], [Private], [The next private private key protecting access to close the payment channel (`witness_i`)],
)

=== Summary

The *VerifyCOF* operation is a Noir ZK circuit using the UltraHonk prover/verifier. It receives the provided deterministic input and produces the deterministic outputs. The circuit is ZK across the inputs, so no information is gained about the private input even with knowledge of the private output. The $T_i$ output is used for the further *VerifyEquivalentModulo* and *VerifyDLEQ* operations.

The operation uses the *blake2s* hashing function for its one-way random oracle simulation.

The scalar order of the Baby Jubjub curve is represented here by $L_bjj$.

=== Methods

$
  T_(i-1) = omega_(i-1) dot.c G_bjj \
  C = hashOf("blake2s", "HEADER" || omega_(i-1)) \
  omega_i = C mod L_bjj \
  T_i = omega_i dot.c G_bjj \
$

== VerifyEquivalentModulo <verify-equivalent-modulo>

=== Inputs
#table( columns: 3,
  [*Input*], [*Visibility*], [],
  [$witness_i$], [Private], [The current private key protecting access to close the payment channel (`witness_i`)],
  [$nu_"DLEQ"$], [Private], [Random 251 bit value (`blinding_DLEQ`)],
)

=== Outputs
#table( columns: 3,
  [*Output*], [*Visibility*], [],
  [$T_i$], [Public], [The public key/curve point on Baby Jubjub for $witness_i$],
  [$S_i$], [Public], [The public key/curve point on Ed25519 for $witness_i$],
  [C], [Public], [The Fiat–Shamir heuristic challenge (`challenge_bytes`)],
  [$Delta_bjj$], [Private], [Optimization parameter (`response_div_BabyJubjub`)],
  [$rho_bjj$], [Public], [The Fiat–Shamir heuristic challenge response on the Baby Jubjub curve (`response_BabyJubJub`)],
  [$Delta_ed$], [Private], [Optimization parameter (`response_div_BabyJubJub`)],
  [$rho_ed$], [Public], [The Fiat–Shamir heuristic challenge response on the Ed25519 curve (`response_div_ed25519`)],
)

=== Summary

The *VerifyEquivalentModulo* operation is a Noir ZK circuit using the UltraHonk prover/verifier. It receives the provided deterministic and random entropy inputs and produces the random outputs. The circuit is not ZK across the inputs since part of the private outputs can be used to reveal information about the private input. The $T_i$, $S_i$, $rho_bjj$, and $rho_ed$ outputs are used for the further *VerifyDLEQ* operation.

This operation proves that the two separate ephemeral $rho$ outputs are both modulo equivalent values determined from the same root value. This ensures that there is no need to compress the embedded size of secret data values transported across the different group orders of the Baby Jubjub and Ed25519 curves, and also avoids the need for the random abort process as specified here: https://eprint.iacr.org/2022/1593.pdf

Note that the $Delta_bjj$ and $Delta_ed$ outputs are used only for optimization of the Noir ZK circuit and may be removed as part of information leakage prevention.

The operation uses the *blake2s* hashing function for its Fiat–Shamir heuristic random oracle model simulation.

The scalar order of the Baby Jubjub curve is represented here by $L_bjj$. The scalar order of the Ed25519 curve is represented here by $L_ed$.

=== Methods

$
  T_i = omega_i dot.c G_bjj \
  S_i = omega_i dot.c G_ed \
  C = hashOf("blake2s", "HEADER" || "PACKED"(T_i) || "PACKED"(S_i)) \
  rho = omega_i * C - nu_"DLEQ" \
  rho_bjj = rho mod L_bjj \
  Delta_bjj = (rho - rho_bjj) / L_bjj \
  rho_ed = rho mod L_ed \
  Delta_ed = (rho - rho_ed) / L_ed \
$

== VerifyDLEQ <verify-dleq>

=== Inputs
#table( columns: 3,
  [*Input*], [*Visibility*], [],
  [$T_i$], [Public], [The public key/curve point on Baby Jubjub for $witness_i$],
  [$rho_bjj$], [Public], [The Fiat–Shamir heuristic challenge response on the Baby Jubjub curve (`response_BabyJubJub`)],
  [$S_i$], [Public], [The public key/curve point on Ed25519 for $witness_i$],
  [$rho_ed$], [Public], [The Fiat–Shamir heuristic challenge response on the Ed25519 curve (`response_div_ed25519`)],
)

=== Outputs
#table( columns: 3,
  [*Output*], [*Visibility*], [],
  [$C$], [Public], [The Fiat–Shamir heuristic challenge (`challenge_bytes`)],
  [$R_bjj$], [Public], [DLEQ commitment 1, which is a public key/curve point on Baby Jubjub (`R_1`)],
  [$R_ed$], [Public], [DLEQ commitment 2, which is a public key/curve point on Ed25519 (`R_2`)],
)

=== Summary

The *VerifyDLEQ* operation is a verification protocol and is language independent. This operation is not redundant, in that the successful verification of the previous *VerifyEquivalentModulo* operation with the same publicly visible parameters implies that this operation will succeed, but the conditions are different.

This operation will be implemented by the peers outside of a ZK circuit in its own native implementation language where the successful verification of the previous *VerifyEquivalentModulo* operation cannot be assumed complete. As such, this operation will exist and can called independently of any other operations.

This operation proves that the $T_i$ and $S_i$ public key/curve points were generated by the same secret key $witness_i$
. Given that the two separate ephemeral $rho$ output values are both modulo equivalent values determined from the same root value, the reconstruction of the two separate $R$ commitments proves this statement. The use of two separate ephemeral $rho$ output values ensures that there is no need to compress the embedded size of the secret data $witness_i$ transported across the different group orders of the Baby Jubjub and Ed25519 curves, and also avoids the need for the random abort process as specified here: https://eprint.iacr.org/2022/1593.pdf

The operation uses the *blake2s* hashing function for its Fiat–Shamir heuristic random oracle model simulation.

=== Methods

$
  C = hashOf("blake2s", "HEADER" || "PACKED"(T_i) || "PACKED"(S_i)) \
  Rho_bjj = rho_bjj dot.c G_bjj \
  C_T_i = C dot.c G_bjj \
  R_bjj = C_T_i - Rho_bjj \
  Rho_ed = rho_ed dot.c G_ed \
  C_S_i = C dot.c G_ed \
  R_ed = C_S_i - Rho_ed \
$
