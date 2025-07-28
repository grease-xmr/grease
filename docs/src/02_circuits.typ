#import "metadata/front-matter.typ":SMc

= Grease

The Grease protocol is a new bi-directional payment channel design with unlimited lifetime for Monero. It is fully compatible with the current Monero implementation and is also fully compatible with the upcoming $"FCMP++"$ update.

Using the Grease protocol, two peers may trustlessly cooperate to share, divide and reclaim a common locked amount of Monero XMR while minimizing the online transaction costs and with minimal use of outside trusted third parties.

The Grease protocol satisfices the security trilemma (Security, Decentralization, Scalability) by maintaining complete security and improving scalability at a minimal cost of network centralization. Since no identifiable information about the peers' privately owned Monero wallets are shared between the peers there is no means by which privacy can be compromised. And since only the one initialization transaction and one closure transaction impact the Monero blockchain, scalability is improved by the unlimited number of updates to the channel in between these two transactions.

Software implementations of the Grease protocol could create new markets opportunities for interactions that require a proof of potential payment or known and locked value for an arbitrary amount of time. Simple examples are down payments, subscriptions, creating a tab at a restaurant or reserving access to a future event.

With the upcoming $"FCMP++"$ update Monero will lose the ability to provably lock a known amount of XMR for a fixed length of time. This was used to create a simple proof of known and locked value outside of trusted third parties. The Grease protocol automatically includes this proof of known and locked value since the channel balance is exactly this proof, with the benefit that the value can be locked for any length of time and any value is easily transferable or refundable.

The Grease protocol is based on the original #link("https://eprint.iacr.org/2022/117")[AuxChannel] paper and #link("https://eprint.iacr.org/2022/744.pdf")[MoNet] protocol. These papers introduced new cryptography primitives that are useful for trustlessly proving conformity by untrusted peers. These primitives are useful abstractly, but the means of implementation were based on innovative and non-standard cryptographic methods that have not gained the general acceptance of the cryptographic community. This may change in time, while the Grease protocol bypasses this limitation by the use of generally accepted methods for the primitives' implementation.

Every update and the final closure of the channel require an online interaction over the Grease network. In order to prevent the accidental or intentional violation of the protocol by a peer not interacting and thus jamming the channel closure, Grease protocol requires the use of an external Key Escrow Service (KES). While a software service and not tied to any particular technology, we can still consider the KES to be an L2 since it will likely run on a ZKP-compatible smart contract blockchain. The example implementation uses the Aztec blockchain and its support of the Barretenberg Plonky proving system, but there are many other blockchains and proving systems that are fully compatible. Most blockchains have limitations on security due to their design, and if the funding for the KES requires publicly viewable transactions then the peer that funds the KES may confront security loss while the other peer does not and can be completely anonymous.

The KES will act as third-party judge of disputes. At initialization, each peer provably encrypts a 2-of-2 secret shared to both the other peer and to the KES. Any one share does not have enough information to interfere with the channel's operations or violate security. In the case of a dispute the KES will decide which peer is in violation and then release its share of the violating peer's secret to the wronged peer. The wronged peer can then reconstruct the original secret. This secret will allow the wronged peer to simulate the missing online interaction of the violating peer, allowing the channel to close with the existing balance. Only willfully valid channel balances can be closed as there is no way to simulate false updates.

= Grease payment channel lifetime

A quick walk-through of a Grease channel lifetime:

At *initialization*, two peers will:
+ communicate out-of-band, share connection information and agree to a fixed balance amount in XMR,
+ connect over a dedicated private communication channel,
+ create a new temporary Monero 2-of-2 multisignature wallet where each peer has full view access and 1-of-2 spend access,
+ create a KES subscription,
+ create proofs of randomizing a new root secret,
+ create proofs of using that root secret for an adaptor signature,
+ create proofs of sharing that root secret with the KES,
+ verify those proofs from the peer,
+ create a shared closing transaction where both peers receive a *vout* output to their private Monero wallet with the exact amount of their starting balance using the adaptor signature, so that each peer has 3-of-4 pieces of information needed to broadcast the transaction,
+ verify the correctness of the closing transaction using the shared view key, the unadapted signatures and the adaptor statements,
+ create a shared funding transaction where both peers provide a *vin* input from their private Monero wallet with the exact amount of their balance,
+ verify the correctness of the funding transaction using the shared view key,
+ activate the KES with the root secret shares,
+ and finally broadcast the funding transaction to Monero.

At *update*, the two peers will:
+ update the balance out-of-band,
+ create proofs of deterministically updating the previous secret,
+ create proofs of using the updated secret for a new adaptor signature,
+ verify those proofs from the peer,
+ update the shared closing transaction where both peers receive an updated *vout* output to their private Monero wallet with the new amount of their balance using the new adaptor signature, so that each peer has the new 3-of-4 pieces of information needed to broadcast the transaction,
+ and finally verify the correctness of the updated closing transaction using the shared view key, the new unadapted signatures and the new adaptor statements.
+ Repeat as often as desired.


At *closure*, the two peers will:
+ share their most recent secret,
+ adapt the unadapted signature of the closing transaction to gain the 4-of-4 pieces of information needed to broadcast the transaction,
+ and finally broadcast the closing transaction to Monero.

In case of a *dispute* a plaintiff will:
+ provide the unadapted signatures of the closing transaction to the KES.

If a dispute is detected the other peer will:
+ respond with the adapted signature of the closing transaction to the KES,
+ or simply broadcast the closing transaction to Monero.

If a dispute is lodged and the other peer does not respond:
+ the KES will provide the saved root secret share of the violating peer to the wronged peer,
+ the wronged peer will reconstruct the violating peer's root secret,
+ the wronged peer will deterministically update the the secret until finding the most recent secret,
+ the wronged peer will adapt the unadapted signature of the closing transaction using the most recent secret to gain the 4-of-4 pieces of information needed to broadcast the transaction,
+ and finally the wronged will broadcast the closing transaction to Monero.

The Grease protocol represents the first attempt to extend the high-security features of Monero while also using the problem-solving flexibility of the latest Turing-complete ZKP tools. Given the rate at which the ZKP technology is advancing there may be many more opportunities to extend Monero's security to new features and markets, connecting the future of Monero with the larger blockchain community and bringing greater attention and interest to the security that Monero has consistently proven.

= Future extensions

There are a number of possible extensions that Grease can support but are not implemented in this example implementation.

- The MoNet protocol allows for multi-hop payment for multiplying the scalability of the the Monero L1. We do not implement this but the MoNet design can be leveraged quickly and easily.
- The KES is assumed to be a single web service with one public key and is susceptible to Sybil attacks. We can add security with the use of TEEs, multiple servers using MPCs (such as co-SNARKs), or creating a more complex shared secret splitting mechanism among a larger number of KES nodes.
- KES funding specifics are not assumed. If the KES runs on a ZKP-compatible smart contract blockchain then both peers will require a funded temporary key pair for the blockchain. With account abstraction this would be trivial. Without account abstraction this can be implemented by the peer that funds the KES to transfer gas to the anonymous peer to accommodate a possible dispute, with the anonymous peer refunding the gas after channel closure (or simply revealing the temporary private key).

...
#SMc[TODO]

= Grease Protocol

The Grease protocol operates in four stages: initialization, update, closure and dispute. The ZKPs are used only in the initialization and update stage, as the closure and dispute do not need further verification to complete.

== Part 1: Protocol Stages

=== Initialization

==== Motivation

The two peers will decide to lock their declared XMR value and create a Grease payment channel so that they can begin transacting in the channel and not on the Monero network.

==== Preliminary

For the initialization stage to begin, the peers must agree upon a small amount of information:

#table(
  columns: 2,
  table.cell(colspan: 2, [*Before Initialization*]),
  [*Resource*], [],
  [Channel ID], [The identifier of the private communications channel. This will include the public key identifier of the peers and information about the means of communications between them.],
  [Locked Amount], [The two values in XMR (with either but not both allowed as zero) that the peers will lock into the channel during its lifetime.],
)

==== MoNet: Before Initialization

The *MoNet* protocol specifies that the peers must agree upon the following using the defined classical interactive protocols with verification:

#table(
  columns: 2,
  table.cell(colspan: 2, [*Before Initialization*]),
  [*Resource*], [],
  [Monero Funding Wallet], [Each peer must have a source wallet with its private spend key. This wallet will need to have at least the *Locked Amount* available.],
  [Monero Refund Wallet], [Each peer must have a destination wallet],
)

==== Grease: Before Initialization

At the start of the initialization stage the peers provide each other with the following resources and information:

#table(
  columns: 3,
  table.cell(colspan: 3, [*Before Initialization*]),
  [*Resource*], [*Visibility*], [],
  [$Pi_"peer"$], [Public], [The public key/curve point on Baby Jubjub for the peer],
  [$Pi_"KES"$], [Public], [The public key/curve point on Baby Jubjub for the KES],
  [$nu_"peer"$], [Public], [Random 251 bit value, provided by the peer (`nonce_peer`)],
)

The peers will also agree on a third party agent on the L2, knows as the Key Escrow Service (KES). When the peers agree on the particular KES, the publicly known public key to this service is shared as $Pi_"KES"$.

Each participant will create a new one-time key pair to use for communication with the KES in the case of a dispute. The peers share the public keys with each other, referring to the other's as $Pi_"peer"$.

During the interactive setup, the peers send each other a nonce, $nu_"peer"$, that guarantees that critically important data must be new and unique for this channel. This prevents the reuse of old data held by the peers.

The ZKP protocols prove that the real private keys are used correctly and that if a dispute is necessary, it will succeed.

===== MoNet: During Initialization

The *MoNet* protocol is very specific on its stages and operations. The Grease protocol maintains the main stages of the MoNet protocol in general but replaces the _2P-CLRAS.JGen()_, _2P-CLRAS.SWGen()_, _2P-CLRAS.NewSW()_, _2P-CLRAS.CVrfy()_ and _2P-CLRAS.PSign()_ functions. These functions were base on innovative and non-standard cryptographic methods that have not gained the general acceptance of the cryptographic community. This may change in time, while the MoNet protocol bypasses this by the use of generally accepted methods.

Note that the original MoNet protocol was not completely compatible with the existing Monero protocol due to the lack of Transaction Chains features. Note that this compatibility flaw will change with the $"FCMP++"$ update.

The 10 stages of the MoNet protocol for initialization are:

#table(
  columns: 3,
  table.cell(colspan: 3, [*MoNet*]),
  [*Stage*], [*Name*], [],
  [1], [_Call 2P-CLRAS.JGen_

  _and Obtain_ $("vk"_"AB",tilde("sk")_X)$], [This shared DKG temporary Monero wallet function is replaced entirely during MoNet.

  ...
  #SMc[TODO]

  The peers will use the well-established Monero wallet implementation of the DKG MPC to generate a 2-of-2 Monero wallet. Once complete, both peers will have the wallet view key $"vk"_"AB"$ and each peer will have 1 of the 2 private spend keys $tilde(k_i)$ / $tilde("sk")_X$. This wallet will require both $sigma_"vk"_A$ and $sigma_"vk"_B$ signatures to complete any transaction.

  Since the only outgoing transaction on this wallet is the $T_x_c$ commitment transaction, there will only be the 2 signatures, but these signatures will change during every channel update.],
  [2], [_Call 2P-CLRAS.SWGen()_

  _Obtain_ $(S^0, (S^0_X, omega^0_X),P^0_X)$], [This statement/witness generation function is replaced entirely by the Grease operations during initialization.

  Note that this is the stage at which all of the Grease operations for proving and verification will occur.],
  [3.0], [_Generate $T_x_f$_], [The peers will collaborate to create the funding transaction $T_x_f$ that will require each peer to each create 1 or 2 *vin* inputs and 1 or 2 *vout* outputs, so $T_x_f$ will have 2 to 4 *vin* inputs and 2 to 4 *vout* outputs. The *vout* data will include their Pedersen commitments (_out_pk_).

  Since the peers will share the new wallet's view key $"vk"_"AB"$ the peers can verify that 2 of the *vout* outputs will target the encrypted _one-time address_ of the temporary Monero wallet.],
  [3.5], [_Generate $T_x_c^0$_], [The peers will also collaborate to create the commitment transaction $T_x_c^0$ so that the 2 *vin* inputs for $T_x_c^0$ will include the $T_x_f$ transacstion's 2 *vout* outputs, and the 2 *vout* outputs for $T_x_c^0$ will each target the encrypted _one-time address_ of each peer's *Monero Refund Wallet* destination.

  Note that before the $"FCMP++"$ update there are no transaction chains features available, and the translation of the 2 *vout* outputs in $T_x_f$ to the 2 *vin* inputs in $T_x_c^0$ requires that the funding transaction $T_x_f$ is mined on the Monero blockchain so that the *vout index numbers* will exist. This is possible only at step 10. This limitation can be bypassed by creating an unusable $T_x_c^0$ with invalid *vout index numbers* that may be verified by the peers but cannot be broadcast to the Monero network.],
  [4], [_Call 2P-CLRAS.PSign()_

  _and Obtain $hat(sigma)^0_(tilde("sk")_A,tilde("sk")_B)$_ ], [The peers collaborate to create the unadapted signature $hat(sigma)^0_(tilde("sk")_A,tilde("sk")_B)$ for $T_x_c^0$ by using $tilde("sk")_X$ and verifying with $S^0_X$.],
  [5, 6, 7, 8], [_Call $"LRS.Sign"_"sk"_X (T_x_f)$_

  _and Obtain $sigma_"vk"_X$_], [The peers will collaborate atomically to complete the signature of $T_x_f$ one step at a time. First the peers will calculate the amount commitments (_ecdh_info_) and Bulletproofs. Then they will use their *Monero Funding Wallet* private spend keys to create the funding signatures $sigma_"vk"_X$.],
  [9], [_Broadcast signed $T_x_f$ to Monero_], [With the preliminaries complete, one of the peers broadcasts the complete $T_x_f$ to the Monero network. Both peers verify that $T_x_f$ is pending mining.],
  [10], [_Channel Established_], [Once $T_x_f$ is mined on the Monero blockchain, the channel is established.

  Note that before the $"FCMP++"$ update the peers can decide on whether to recompute step 3.5 to ensure that $T_x_c^0$ is usable.],
)

==== Grease: During Initialization

As a substitute for *MoNet* protocol stage 2, the Grease protocol requires the generation and sharing of the ZKPs. The public data and the small proofs are shared between peers, then are validated as a means to ensure protocol conformity before *MoNet* protocol stage 3 begins.

The ZKP operations require random values to ensure security of communications. These are not shared with the peer:

===== Inputs:
#table(
  columns: 3,
  table.cell(colspan: 3, [*During Initialization*]),
  [*Input*], [*Visibility*], [],
  [$nu_omega_0$], [Private], [Random 251 bit value (`blinding`)],
  [$a_1$], [Private], [Random 251 bit value],
  [$nu_1$], [Private], [Random 251 bit value (`r_1`)],
  [$nu_2$], [Private], [Random 251 bit value (`r_2`)],
  [$nu_"DLEQ"$], [Private], [Random 251 bit value (`blinding_DLEQ`)],
)

The ZKP operations produce output values, the publicly visible values must be shared with the peer in addition to the generated proofs while the privately visible values must be stored for later usage:

===== Outputs:
#table(
  columns: 3,
  table.cell(colspan: 3, [*During Initialization*]),
  [*Output*], [*Visibility*], [],
  [$T_0$], [Public], [The public key/curve point on Baby Jubjub for $omega_0$],
  [$omega_0$], [Private], [The root private key protecting access to the user's locked value (`witness_0`)],
  [$c_1$], [Public], [`Feldman commitment 1` (used in tandem with `Feldman commitment 0` $=T_0$), which is a public key/curve point on Baby Jubjub],
  [$sigma_1$], [Private], [The split of $omega_0$ shared with the peer (`share_1`)],
  [$Phi_1$], [Public], [The ephemeral public key/curve point on Baby Jubjub for message transportation to the peer (`fi_1`)],
  [$chi_1$], [Public], [The encrypted value of $sigma_1$ (`enc_1`)],
  [$sigma_2$], [Private], [The split of $omega_0$ shared with the KES (`share_2`)],
  [$Phi_2$], [Public], [The ephemeral public key/curve point on Baby Jubjub for message transportation to the KES (`fi_2`)],
  [$chi_2$], [Public], [The encrypted value of $sigma_2$ (`enc_2`)],
  [$S_0$], [Public], [The public key/curve point on Ed25519 for $omega_0$],
  [C], [Public], [The Fiat–Shamir heuristic challenge (`challenge_bytes`)],
  [$Delta_"BabyJubjub"$], [Private], [Optimization parameter (`response_div_BabyJubjub`)],
  [$rho_"BabyJubjub"$], [Public], [The Fiat–Shamir heuristic challenge response on the Baby Jubjub curve (`response_BabyJubJub`)],
  [$Delta_"Ed25519"$], [Private], [Optimization parameter (`response_div_BabyJubJub`)],
  [$rho_"Ed25519"$], [Public], [The Fiat–Shamir heuristic challenge response on the Ed25519 curve (`response_div_ed25519`)],
)

During the initialization stage, the following operations are performed:

- *VerifyWitness0*
- *VerifyWitnessSharing*
- *VerifyEquivalentModulo*
- *VerifyDLEQ*

Particular details about these operations can be found in *Part 2: Grease ZKP Operations*.

==== Grease: After Initialization

After receiving the publicly visible values and ZK proofs from the peer, the Grease protocol requires the ZKP verification operations to ensure protocol conformity.

Once verified, the following resources and information are available and must be stored:

#table(
  columns: 2,
  table.cell(colspan: 2, [*After Initialization*]),
  [*Resource*], [],
  [$Phi_1$], [The ephemeral public key/curve point on Baby Jubjub for message transportation from the peer (`fi_1`)],
  [$chi_1$], [The encrypted value of $sigma_1$ (`enc_1`) for the peer's $omega_0$],
  [$omega_0$], [The root private key protecting access to the user's locked value (`witness_0`)],
  [$S_0$], [The public key/curve point on Ed25519 for the peer's $omega_0$],
)

==== MoNet: After Initialization

When complete the following resources and information are available and must be stored:

#table(
  columns: 2,
  table.cell(colspan: 2, [*After Initialization*]),
  [*Resource*], [],
  [Monero Temporary Wallet], [The temporary 2-of-2 multisignature Monero wallet with the locked XMR value of the channel],
  [$"vk"_"AB"$], [The shared *Monero Temporary Wallet* view key],
  [$tilde("sk")_X$], [The *Monero Temporary Wallet* spend key],
  [Channel Balance], [The two values in XMR (with either but not both allowed as zero) for the peers, equal to *Locked Amount*],
  [$T_x_c^0$], [The commitment transaction that closes the channel, with the *vout* XMR values equal to *Channel Balance*],
)

With these outputs the the initialization stage is complete and the channel is open. The peers can now transact and update the channel state or close the channel and receive the locked XMR value in the *Monero Refund Wallet*.

=== Update

==== Motivation

Once a channel is open the peers may decide to transact and update the XMR balance between the peers. The only requirement is that the peers agree on the change in ownership of the *Locked Amount*.

Note that with an open channel there is no internal reason to perform an update outside of a peer-initiated change. However, the current Monero protocol requires that a newly broadcast transaction be created within a reasonable timeframe. The $"FCMP++"$ update does not change the need for this, but does alter the timeframe. As such, existing open channel should create a "zero delta" update at reasonable timeframes to ensure the channel may be closed arbitrarily. The specifics on this are outside of current scope.

==== Preliminary

For the update stage to begin, the peers must agree upon a small amount of information:

#table(
  columns: 2,
  table.cell(colspan: 2, [*Before Update*]),
  [*Resource*], [],
  [Delta], [The change in the two values in XMR (positive or negative) from the previous stage. This is a single number since the *Locked Amount* must stay the same.],
)

===== MoNet: During Update

The *MoNet* protocol is very specific on its stages and operations. The Grease protocol maintains the stages of the MoNet protocol in general but replaces all of the _2P-CLRAS.NewSW()_, _2P-CLRAS.CVrfy()_ and _2P-CLRAS.PSign()_ functions. These functions were base on innovative and non-standard cryptographic methods that have not gained the general acceptance of the cryptographic community. This may change in time, while the MoNet protocol bypasses this by the use of generally accepted methods.

The 3 stages of the MoNet protocol for update are:

#table(
  columns: 3,
  table.cell(colspan: 3, [*MoNet*]),
  [*Stage*], [*Name*], [],
  [11], [_Call 2P-CLRAS.NewSW()_

  _Obtain_ $(S^i, (S^i_X, omega^i_X),P^i_X)$], table.cell(rowspan: 2, [This statement/witness generation function is replaced entirely by the Grease *VerifyCOF* operation, and the verification function is replaced entirely by the Grease *VerifyDLEQ* operation.

  Note that this is the stage at which all of the Grease operations for proving and verification will occur.]),
  [12], [_If 2P-CLRAS.CVrfy_ $((S^(i-1)_X,S^i_X),P^i_X)) = 0 : ⊥$],
  [13], [_Elif Call 2P-CLRAS.PSign()_

  _and Obtain $hat(sigma)^i_(tilde("sk")_A,tilde("sk")_B)$_ ], [In MoNet, the peers collaborate to create the unadapted signature $hat(sigma)^i_(tilde("sk")_A,tilde("sk")_B)$ for new $T_x_c^i$ by using $tilde("sk")_X$ and verifying with $S^i_X$.

  This shared DKG Monero wallet function is replaced entirely during MoNet.

  ... #SMc[TODO] ],
)

==== Grease: During Update

As a substitute for *MoNet* protocol stages 11 and 12, the Grease protocol requires the generation and sharing of the ZKPs. The public data and the small proofs are shared between peers, then are validated as a means to ensure protocol conformity before *MoNet* protocol stage 13 begins.

The ZKP operations require the previous $omega_i$ (now $omega_(i-1)$) and a random value to ensure security of communications. These are not shared with the peer:

===== Inputs:
#table(
  columns: 3,
  table.cell(colspan: 3, [*During Update*]),
  [*Input*], [*Visibility*], [],
  [$omega_(i-1)$], [Private], [The current private key protecting access to close the payment channel (`witness_im1`)],
  [$nu_"DLEQ"$], [Private], [Random 251 bit value (`blinding_DLEQ`)],
)

The ZKP operations produce output values, the publicly visible values must be shared with the peer in addition to the generated proofs while the privately visible values must be stored for later usage:

===== Outputs:
#table(
  columns: 3,
  table.cell(colspan: 3, [*During Update*]),
  [*Output*], [*Visibility*], [],
  [$T_(i-1)$], [Public], [The public key/curve point on Baby Jubjub for $omega_(i-1)$],
  [$T_i$], [Public], [The public key/curve point on Baby Jubjub for $omega_i$],
  [$omega_i$], [Private], [The next private private key protecting access to close the payment channel (`witness_i`)],
  [$S_i$], [Public], [The public key/curve point on Ed25519 for $omega_i$],
  [C], [Public], [The Fiat–Shamir heuristic challenge (`challenge_bytes`)],
  [$Delta_"BabyJubjub"$], [Private], [Optimization parameter (`response_div_BabyJubjub`)],
  [$rho_"BabyJubjub"$], [Public], [The Fiat–Shamir heuristic challenge response on the Baby Jubjub curve (`response_BabyJubJub`)],
  [$Delta_"Ed25519"$], [Private], [Optimization parameter (`response_div_BabyJubJub`)],
  [$rho_"Ed25519"$], [Public], [The Fiat–Shamir heuristic challenge response on the Ed25519 curve (`response_div_ed25519`)],
  [$C$], [Public], [The Fiat–Shamir heuristic challenge (`challenge_bytes`)],
  [$R_"BabyJubjub"$], [Public], [DLEQ commitment 1, which is a public key/curve point on Baby Jubjub (`R_1`)],
  [$R_"Ed25519"$], [Public], [DLEQ commitment 2, which is a public key/curve point on Ed25519 (`R_2`)],
)

During the update stage, the following operations are performed:

- *VerifyCOF*
- *VerifyEquivalentModulo*
- *VerifyDLEQ*

Particular details about these operations can be found in *Part 2: Grease ZKP Operations*.

==== Grease: After Update

After receiving the publicly visible values and ZK proofs from the peer, the Grease protocol requires the ZKP verification operations to ensure protocol conformity.

Once verified, the following resources and information are available and must be stored:

#table(
  columns: 2,
  table.cell(colspan: 2, [*After Update*]),
  [*Resource*], [],
  [$omega_i$], [The current private key protecting access to close the payment channel (`witness_i`)],
  [$S_i$], [The public key/curve point on Ed25519 for the peer's $omega_i$],
)

==== MoNet: After Update

When complete the following resources and information are available and must be stored:

#table(
  columns: 2,
  table.cell(colspan: 2, [*After Initialization*]),
  [*Resource*], [],
  [Channel Balance], [The two values in XMR (with either but not both allowed as zero) for the peers],
  [$T_x_c^i$], [The commitment transaction that closes the channel, with the *vout* XMR values equal to *Channel Balance*],
)

With these outputs the the update stage is complete and the channel remains open. The peers can now transact further updates or close the channel and receive the locked XMR value *Channel Balance* in the *Monero Refund Wallet*.

== Part 2: Grease ZKP Operations

The Grease protocol requires the creation and sharing of a series of Zero Knowledge proofs (ZKPs) as part of the lifetime of a payment channel. Most are Non-Interactive Zero Knowledge (NIZK) proofs in the form of Turing-complete circuits created using newly-established Plonky-based proving protocols. The others are classical interactive protocols with verification.

=== VerifyWitness0

==== Inputs:
#table(
  columns: 3,
  [*Input*], [*Visibility*], [],
  [$nu_"peer"$], [Public], [Random 251 bit value, provided by the peer (`nonce_peer`)],
  [$nu_omega_0$], [Private], [Random 251 bit value (`blinding`)],
)

==== Outputs:
#table(
  columns: 3,
  [*Output*], [*Visibility*], [],
  [$T_0$], [Public], [The public key/curve point on Baby Jubjub for $omega_0$],
  [$omega_0$], [Private], [The root private key protecting access to the user's locked value (`witness_0`)],
)

==== Summary

The *VerifyWitness0* operation is a Noir ZK circuit using the UltraHonk prover/verifier. It receives the provided random entropy inputs and produces the deterministic outputs. The circuit is ZK across the inputs, so no information is gained about the private inputs even with knowledge of the private output. The $T_0$ output is used for the further *VerifyEquivalentModulo* and *VerifyDLEQ* operations.

The operation uses the *blake2s* hashing function for its one-way random oracle simulation.

The scalar order of the Baby Jubjub curve is represented here by $L_"BabyJubjub"$.

==== Methods

$
  C = H_"blake2s" ("HEADER" || nu_"peer" || nu_omega_0) \
  omega_0 = C mod L_"BabyJubjub" \
  T_0 = omega_0 dot.c G_"BabyJubjub"
$

=== FeldmanSecretShare_2_of_2

==== Inputs:
#table(
  columns: 3,
  [*Input*], [*Visibility*], [],
  [$omega_0$], [Private], [The root private key protecting access to the user's locked value (`secret`)],
  [$a_1$], [Private], [Random 251 bit value],
)

==== Outputs:
#table(
  columns: 3,
  [*Output*], [*Visibility*], [],
  [$T_0$], [Public], [Feldman commitment 0, which is the public key/curve point on Baby Jubjub for $omega_0$],
  [$c_1$], [Public], [Feldman commitment 1, which is a public key/curve point on Baby Jubjub],
  [$sigma_1$], [Private], [The split of $omega_0$ shared with the peer (`share_1`)],
  [$sigma_2$], [Private], [The split of $omega_0$ shared with the KES (`share_2`)],
)

==== Summary

The *FeldmanSecretShare_2_of_2* operation is a Noir ZK circuit using the UltraHonk prover/verifier. It receives the provided secret data and random entropy inputs. The output are the two perfectly binding Feldman commitments and the two encoded split shares to send to the destinations. The circuit is not ZK across the inputs so so that full knowledge of the private outputs can reconstruct the private inputs.

The outputs are used for the further *VerifyEncryptMessage*, *VerifyFeldmanSecretShare_peer*, *VerifyFeldmanSecretShare_KES*, and *ReconstructFeldmanSecretShare_2_of_2* operations.

The scalar order of the Baby Jubjub curve is represented here by $L_"BabyJubjub"$.

Note that for the peer to verify the validity of the secret sharing protocol, the calculation is:
$
  "VerifyFeldmanSecretShare_peer"(T_0, c_1, sigma_1)
$


Note that for the KES to verify the validity of the secret sharing protocol, the calculation is:
$
  "VerifyFeldmanSecretShare_KES"(T_0, c_1, sigma_2)
$

Note that for reconstructing the secret input $omega_0$, the calculation is:
$
  omega_0 = "ReconstructFeldmanSecretShare_2_of_2"(sigma_1, sigma_2)
$

==== Methods

$
  c_1 = a_1 dot.c G_"BabyJubjub" \
  sigma_1 = -(omega_0 + a_1) mod L_"BabyJubjub" \
  sigma_2 = 2*omega_0 + a_1 mod L_"BabyJubjub"
$


=== ReconstructFeldmanSecretShare_2_of_2

==== Inputs:
#table(
  columns: 3,
  [*Input*], [*Visibility*], [],
  [$sigma_1$], [Private], [The split of $omega_0$ shared with the peer (`share_1`)],
  [$sigma_2$], [Private], [The split of $omega_0$ shared with the KES (`share_2`)],
)

==== Outputs:
#table(
  columns: 3,
  [*Output*], [*Visibility*], [],
  [$omega_0$], [Private], [The root private key protecting access to the user's locked value (`secret`)],
)

==== Summary

The *ReconstructFeldmanSecretShare_2_of_2* operation is a reconstruction protocol and is language independent. It receives the two split shares as inputs and outputs the original $omega_0$ secret.

The scalar order of the Baby Jubjub curve is represented here by $L_"BabyJubjub"$.

==== Methods

$
  omega_0 = sigma_1 + sigma_2 mod L_"BabyJubjub"
$

=== VerifyFeldmanSecretShare_peer

==== Inputs:
#table(
  columns: 3,
  [*Input*], [*Visibility*], [],
  [$T_0$], [Public], [Feldman commitment 0, which is the public key/curve point on Baby Jubjub for $omega_0$],
  [$c_1$], [Public], [Feldman commitment 1, which is a public key/curve point on Baby Jubjub],
  [$sigma_1$], [Private], [The split of $omega_0$ shared with the peer (`share_1`)],
)

==== Outputs:

There are no outputs.

==== Summary

The *VerifyFeldmanSecretShare_peer* operation is a verification protocol and is language independent. This operation is redundant, in that the successful verification of the previous *FeldmanSecretShare_2_of_2* operation with the same publicly visible parameters implies that this operation will succeed.

==== Methods

$
  "assert"(sigma_1 dot.c G_"BabyJubjub" == -(T_0 + c_1))
$

=== VerifyFeldmanSecretShare_KES

==== Inputs:
#table(
  columns: 3,
  [*Input*], [*Visibility*], [],
  [$T_0$], [Public], [Feldman commitment 0, which is the public key/curve point on Baby Jubjub for $omega_0$],
  [$c_1$], [Public], [Feldman commitment 1, which is a public key/curve point on Baby Jubjub],
  [$sigma_2$], [Private], [The split of $omega_0$ shared with the KES (`share_2`)],
)

==== Outputs:

There are no outputs.

==== Summary

The *VerifyFeldmanSecretShare_peer* operation is a verification protocol and is language independent. This operation is not redundant, in that the successful verification of the previous *FeldmanSecretShare_2_of_2* operation with the same publicly visible parameters implies that this operation will succeed, but the conditions are different.

This operation will be implemented by the KES in its own native implementation language where the successful verification of the previous *FeldmanSecretShare_2_of_2* operation cannot be assumed. As such, this operation will exist and can called independently of any other operations.

==== Methods

$
  "assert"(sigma_2 dot.c G_"BabyJubjub" == 2 dot.c T_0 + c_1)
$

=== VerifyEncryptMessage

==== Inputs:
#table(
  columns: 3,
  [*Input*], [*Visibility*], [],
  [$sigma$], [Private], [The secret 251 bit message (`message`)],
  [$nu$], [Private], [Random 251 bit value (`r`)],
  [$Pi$], [Public], [The public key/curve point on Baby Jubjub for the destination],
)

==== Outputs:
#table(
  columns: 3,
  [*Output*], [*Visibility*], [],
  [$Phi$], [Public], [The ephemeral public key/curve point on Baby Jubjub for message transportation (`fi`)],
  [$chi$], [Public], [The encrypted value of $sigma$ (`enc`)],
)

==== Summary

The *VerifyEncryptMessage* operation is a Noir ZK circuit using the UltraHonk prover/verifier. It receives the provided secret data and random entropy inputs. The output are the perfectly binding public key commitment and the perfectly hiding encrypted scaler value to send to the destinations. The circuit is ZK across the inputs since the outputs are publicly visible.

The method of encryption is the ECDH (Elliptic-curve Diffie–Hellman) key agreement protocol. The operation uses the *blake2s* hashing function for its shared secret commitment simulation. Note that the unpacked form of the ephemeral key is used for hashing, instead of the standard $"PACKED"()$ function.

Note that for reconstructing the secret input $sigma$ given the private key $kappa$ where $Pi = kappa dot.c G_"BabyJubjub"$, the calculation is:

$
  (Pi, sigma) = "DecryptMessage"(kappa, Phi, chi) \
$

Note that this operation does not call for the use of HMAC or other message verification protocol due to the simplicity of the interactive steps and their resistance to message tampering. A more complicated or distributed protocol would requires this attack prevention.

The scalar order of the Baby Jubjub curve is represented here by $L_"BabyJubjub"$.

==== Methods

$
  Phi = nu dot.c G_"BabyJubjub" \
  nu_Pi = nu dot.c Pi \
  C = H_"blake2s" (nu_Pi."x" || nu_Pi."y") \
  s = C mod L_"BabyJubjub" \
  chi = sigma + s mod L_"BabyJubjub" \
$

=== DecryptMessage

==== Inputs:
#table(
  columns: 3,
  [*Input*], [*Visibility*], [],
  [$kappa$], [Private], [The private key for the public key $Pi$],
  [$Phi$], [Public], [The ephemeral public key/curve point on Baby Jubjub for message transportation (`fi`)],
  [$chi$], [Public], [The encrypted value of $sigma$ (`enc`)],
)

==== Outputs:
#table(
  columns: 3,
  [*Output*], [*Visibility*], [],
  [$Pi$], [Public], [The public key/curve point on Baby Jubjub for the destination],
  [$sigma$], [Private], [The secret 251 bit message (`message`)],
)

==== Summary

The *DecryptMessage* operation is a verification protocol and is language independent.

The method of decryption is the ECDH (Elliptic-curve Diffie–Hellman) key agreement protocol. The operation uses the *blake2s* hashing function for its shared secret commitment simulation. Note that the unpacked form of the ephemeral key is used for hashing, instead of the standard $"PACKED"()$ function.

The scalar order of the Baby Jubjub curve is represented here by $L_"BabyJubjub"$.

==== Methods

$
  Pi = kappa dot.c G_"BabyJubjub" \
  kappa_Phi = kappa dot.c Phi \
  C = H_"blake2s" (kappa_Phi."x" || kappa_Phi."y") \
  s = C mod L_"BabyJubjub" \
  sigma = chi - s mod L_"BabyJubjub" \
$

=== VerifyWitnessSharing

==== Inputs:
#table(
  columns: 3,
  [*Input*], [*Visibility*], [],
  [$omega_0$], [Private], [The root private key protecting access to the user's locked value (`witness_0`)],
  [$a_1$], [Private], [Random 251 bit value],
  [$nu_1$], [Private], [Random 251 bit value (`r_1`)],
  [$Pi_"peer"$], [Public], [The public key/curve point on Baby Jubjub for the peer],
  [$nu_2$], [Private], [Random 251 bit value (`r_2`)],
  [$Pi_"KES"$], [Public], [The public key/curve point on Baby Jubjub for the KES],
)

==== Outputs:
#table(
  columns: 3,
  [*Output*], [*Visibility*], [],
  [$c_1$], [Public], [`Feldman commitment 1` (used in tandem with `Feldman commitment 0` $=T_0$), which is a public key/curve point on Baby Jubjub],
  [$sigma_1$], [Private], [The split of $omega_0$ shared with the peer (`share_1`)],
  [$Phi_1$], [Public], [The ephemeral public key/curve point on Baby Jubjub for message transportation to the peer (`fi_1`)],
  [$chi_1$], [Public], [The encrypted value of $sigma_1$ (`enc_1`)],
  [$sigma_2$], [Private], [The split of $omega_0$ shared with the KES (`share_2`)],
  [$Phi_2$], [Public], [The ephemeral public key/curve point on Baby Jubjub for message transportation to the KES (`fi_2`)],
  [$chi_2$], [Public], [The encrypted value of $sigma_2$ (`enc_2`)],
)

==== Summary

The *VerifyWitnessSharing* operation is a Noir ZK circuit using the UltraHonk prover/verifier. It passes through the the provided inputs and calls the *FeldmanSecretShare_2_of_2* and *VerifyEncryptMessage* operations.

==== Methods

$
  (c_1,sigma_1,sigma_2) = "FeldmanSecretShare_2_of_2"(omega_0,a_1) \
  (Phi_1,chi_1) = "VerifyEncryptMessage"(sigma_1,nu_1,Pi_"peer") \
  (Phi_2,chi_2) = "VerifyEncryptMessage"(sigma_2,nu_2,Pi_"KES") \
$

=== VerifyCOF


==== Inputs:
#table(
  columns: 3,
  [*Input*], [*Visibility*], [],
  [$omega_(i-1)$], [Private], [The current private key protecting access to close the payment channel (`witness_im1`)],
)

==== Outputs:
#table(
  columns: 3,
  [*Output*], [*Visibility*], [],
  [$T_(i-1)$], [Public], [The public key/curve point on Baby Jubjub for $omega_(i-1)$],
  [$T_i$], [Public], [The public key/curve point on Baby Jubjub for $omega_i$],
  [$omega_i$], [Private], [The next private private key protecting access to close the payment channel (`witness_i`)],
)

==== Summary

The *VerifyCOF* operation is a Noir ZK circuit using the UltraHonk prover/verifier. It receives the provided deterministic input and produces the deterministic outputs. The circuit is ZK across the inputs, so no information is gained about the private input even with knowledge of the private output. The $T_i$ output is used for the further *VerifyEquivalentModulo* and *VerifyDLEQ* operations.

The operation uses the *blake2s* hashing function for its one-way random oracle simulation.

The scalar order of the Baby Jubjub curve is represented here by $L_"BabyJubjub"$.

==== Methods

$
  T_(i-1) = omega_(i-1) dot.c G_"BabyJubjub" \
  C = H_"blake2s" ("HEADER" || omega_(i-1)) \
  omega_i = C mod L_"BabyJubjub" \
  T_i = omega_i dot.c G_"BabyJubjub" \
$

=== VerifyEquivalentModulo

==== Inputs:
#table(
  columns: 3,
  [*Input*], [*Visibility*], [],
  [$omega_i$], [Private], [The current private key protecting access to close the payment channel (`witness_i`)],
  [$nu_"DLEQ"$], [Private], [Random 251 bit value (`blinding_DLEQ`)],
)

==== Outputs:
#table(
  columns: 3,
  [*Output*], [*Visibility*], [],
  [$T_i$], [Public], [The public key/curve point on Baby Jubjub for $omega_i$],
  [$S_i$], [Public], [The public key/curve point on Ed25519 for $omega_i$],
  [C], [Public], [The Fiat–Shamir heuristic challenge (`challenge_bytes`)],
  [$Delta_"BabyJubjub"$], [Private], [Optimization parameter (`response_div_BabyJubjub`)],
  [$rho_"BabyJubjub"$], [Public], [The Fiat–Shamir heuristic challenge response on the Baby Jubjub curve (`response_BabyJubJub`)],
  [$Delta_"Ed25519"$], [Private], [Optimization parameter (`response_div_BabyJubJub`)],
  [$rho_"Ed25519"$], [Public], [The Fiat–Shamir heuristic challenge response on the Ed25519 curve (`response_div_ed25519`)],
)

==== Summary

The *VerifyEquivalentModulo* operation is a Noir ZK circuit using the UltraHonk prover/verifier. It receives the provided deterministic and random entropy inputs and produces the random outputs. The circuit is not ZK across the inputs since part of the private outputs can be used to reveal information about the private input. The $T_i$, $S_i$, $rho_"BabyJubjub"$, and $rho_"Ed25519"$ outputs are used for the further *VerifyDLEQ* operation.


This operation proves that the two separate ephemeral $rho$ outputs are both modulo equivalent values determined from the same root value. This ensures that there is no need to compress the embedded size of secret data values transported across the different group orders of the Baby Jubjub and Ed25519 curves, and also avoids the need for the random abort process as specified here: https://eprint.iacr.org/2022/1593.pdf

Note that the $Delta_"BabyJubjub"$ and $Delta_"Ed25519"$ outputs are used only for optimization of the Noir ZK circuit and may be removed as part of information leakage prevention.

The operation uses the *blake2s* hashing function for its Fiat–Shamir heuristic random oracle model simulation.

The scalar order of the Baby Jubjub curve is represented here by $L_"BabyJubjub"$. The scalar order of the Ed25519 curve is represented here by $L_"Ed25519"$.

==== Methods

$
  T_i = omega_i dot.c G_"BabyJubjub" \
  S_i = omega_i dot.c G_"Ed25519" \
  C = H_"blake2s" ("HEADER" || "PACKED"(T_i) || "PACKED"(S_i)) \
  rho = omega_i * C - nu_"DLEQ" \
  rho_"BabyJubjub" = rho mod L_"BabyJubjub" \
  Delta_"BabyJubjub" = (rho - rho_"BabyJubjub") / L_"BabyJubjub" \
  rho_"Ed25519" = rho mod L_"Ed25519" \
  Delta_"Ed25519" = (rho - rho_"Ed25519") / L_"Ed25519" \
$

=== VerifyDLEQ

==== Inputs:
#table(
  columns: 3,
  [*Input*], [*Visibility*], [],
  [$T_i$], [Public], [The public key/curve point on Baby Jubjub for $omega_i$],
  [$rho_"BabyJubjub"$], [Public], [The Fiat–Shamir heuristic challenge response on the Baby Jubjub curve (`response_BabyJubJub`)],
  [$S_i$], [Public], [The public key/curve point on Ed25519 for $omega_i$],
  [$rho_"Ed25519"$], [Public], [The Fiat–Shamir heuristic challenge response on the Ed25519 curve (`response_div_ed25519`)],
)

==== Outputs:
#table(
  columns: 3,
  [*Output*], [*Visibility*], [],
  [$C$], [Public], [The Fiat–Shamir heuristic challenge (`challenge_bytes`)],
  [$R_"BabyJubjub"$], [Public], [DLEQ commitment 1, which is a public key/curve point on Baby Jubjub (`R_1`)],
  [$R_"Ed25519"$], [Public], [DLEQ commitment 2, which is a public key/curve point on Ed25519 (`R_2`)],
)

==== Summary

The *VerifyDLEQ* operation is a verification protocol and is language independent. This operation is not redundant, in that the successful verification of the previous *VerifyEquivalentModulo* operation with the same publicly visible parameters implies that this operation will succeed, but the conditions are different.

This operation will be implemented by the peers outside of a ZK circuit in its own native implementation language where the successful verification of the previous *VerifyEquivalentModulo* operation cannot be assumed complete. As such, this operation will exist and can called independently of any other operations.

This operation proves that the $T_i$ and $S_i$ public key/curve points were generated by the same secret key $omega_i$. Given that the two separate ephemeral $rho$ output values are both modulo equivalent values determined from the same root value, the reconstruction of the two separate $R$ commitments proves this statement. The use of two separate ephemeral $rho$ output values ensures that there is no need to compress the embedded size of the secret data $omega_i$ transported across the different group orders of the Baby Jubjub and Ed25519 curves, and also avoids the need for the random abort process as specified here: https://eprint.iacr.org/2022/1593.pdf

The operation uses the *blake2s* hashing function for its Fiat–Shamir heuristic random oracle model simulation.

==== Methods

$
  C = H_"blake2s" ("HEADER" || "PACKED"(T_i) || "PACKED"(S_i)) \
  Rho_"BabyJubjub" = rho_"BabyJubjub" dot.c G_"BabyJubjub" \
  C_T_i = C dot.c G_"BabyJubjub" \
  R_"BabyJubjub" = C_T_i - Rho_"BabyJubjub" \
  Rho_"Ed25519" = rho_"Ed25519" dot.c G_"Ed25519" \
  C_S_i = C dot.c G_"Ed25519" \
  R_"Ed25519" = C_S_i - Rho_"Ed25519" \
$
