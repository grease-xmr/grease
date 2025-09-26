= Introduction

Monero is, alongside cash, the world's most private @what-is-monero @all-about-monero @culafi24, and, arguably the
best currency in circulation, but the user _experience_ remains less than ideal.
This comment is not necessarily aimed at user _interfaces_ -- for example, there are Monero wallets that are very attractive
and easy to use -- but the fundamental design of Monero means that:

- many, especially new, users find they can make only one payment roughly every ~20 minutes when their wallet holds a single spendable output (the change from the first payment typically requires about 10 confirmations before it can be spent again),
- due to the lack of scripting capabilities, use-cases that capture the public imagination, like DeFi, are not possible in vanilla Monero.

Therefore, the _experience_ of using Monero tends to be one of waiting, and limited functionality.

For Monero to achieve mass adoption, it will need to find ways to:

- provide an order of magnitude _better UX_ (again, not necessarily UI). Locking UTXOs after spending and block
confirmation times add significant friction to Monero and is a turn-off for new users who are already unsure about how cryptocurrency works.
- provide _instant confirmations_ when purchasing with Monero.
- enable _seamless point-of-sale transactions_ so that using Monero for purchases feels no different to using a credit card or Venmo.
- enable DeFi for Monero. DeFi is the future of finance. The lack of permissionless access to bank-like services (loans,
 insurance, and investments) is a key barrier to truly democratic money.
- provide for Monero-backed and/or privacy-maximizing stable coins.

A payment-channel solution for Monero is one of the foundational requirements for achieving these goals in Monero.
The other is smart contracting functionality, but that is out of scope for this project.

== Payment channels in Monero

Monero's primary function is private, fungible money.
This goal very likely excludes any kind of meaningful on-chain state management for Monero, since state implies heterogeneity.
And heterogeneity immediately breaks fungibility.
That's not to say that some hitherto undiscovered insight won't allow this in future, but for the short and medium-term at least, any kind
of state management for Monero transactions or UTXOs would have to be stored off-chain.

It makes the most sense to store this off-chain state on another decentralized, private protocol.
Zero-knowledge Rollup blockchains (ZKR) fit the bill nicely.

It's the goal of this project to marry Monero (for private money) with a ZK-rollup chain (for private state management) to create a
proof-of-concept Monero payment channel for Monero.

=== Enter Grease

The Grease protocol is a new bi-directional payment channel design with unlimited lifetime for Monero. It is fully compatible with the current Monero implementation and is also fully compatible with the upcoming FCMP++ update.

Using the Grease protocol, two peers may trustlessly cooperate to share, divide and reclaim a common locked amount of Monero XMR while minimizing the online transaction costs and with minimal use of outside trusted third parties.

The Grease protocol maintains all of Monero's security.
No identifiable information about the peers' privately owned Monero wallets are shared between the peers. This means
that there is no way that privacy can be compromised. Each channel lifecycle requires two Monero transactions, with
effectively unlimited near-instant updates to the channel balance in between these two transactions. This dramatically
improves the scalability of Monero.

The Grease protocol is based on the original AuxChannel@aux-channel paper and Monet@monet protocol. These papers
introduced new cryptographic primitives that are useful for trustlessly proving conformity by untrusted peers. These primitives are useful abstractly, but the means of implementation were based on innovative and non-standard cryptographic methods that have not gained the general acceptance of the cryptographic community. This may change in time, while the Grease protocol bypasses this limitation by the use of generally accepted methods for the primitives' implementation.

Every update and the final closure of the channel require an online interaction over the Grease network. In order to
prevent the accidental or intentional violation of the protocol by a peer not interacting and thus jamming the channel
closure, Grease introduces an external Key Escrow Service (KES). The KES needs to run on a stateful, logic- and
time-aware platform. A decentralized zero-knowledge smart contract platform satisfies this requirement while also
providing the privacy-focused ethos familiar to the Monero community.

=== Why does another chain have to be involved?

Offline payment channels necessarily _require_ a trustless state management mechanism. Typically, the scripting features for
a given blockchain allow for this state to be managed directly. However, Monero's primary design goals are privacy and fungibility.
Attaching state to UTXOs would create a heterogeneity that threatens these goals. (Fungibility is more important than specialty
for maintaining privacy.)

The state does not have to be managed on the same chain though. Any place where the state is:

- available,
- reliable and verifiable,
- trustless,

will suffice.

The initial implementation uses the any Noir-compatible execution environment that supports the Barretenberg Plonky
proving system, the Aztec blockchain being one candidate.

The KES acts as a third‑party judge in disputes. At initialization, each peer splits a secret using a 2‑of‑2 scheme and encrypts one share for the counterparty and one for the KES. Any single share is useless on its own. If a dispute arises, the KES identifies the violating peer and releases its share of that peer’s secret to the wronged peer. Combined with the counterparty‑held share already in their possession, the wronged peer can reconstruct the secret and simulate the missing online interaction to close the channel with the latest agreed balance. Only valid channel states can be unilaterally closed; fabricated updates cannot be simulated.

= Design principles

Grease is a bidirectional two-party payment channel. This means that funds can flow in both directions, but in the vast
majority of cases, funds will flow from one party (the client, or private peer) to the other (the merchant, or public peer).

Grease embraces this use case and optimizes the design and UX based on the following assumptions:

- The public peer is responsible for recording the channel state on the ZK chain.
- The public peer pays for gas fees on the ZK chain and will need to have some amount of ZK chain tokens to pay for these fees.
- The public peer will be able to recover gas fees from the client peer.
- The client peer does not _have_ to have any ZK chain tokens, but will need to hold Monero to open the channel.
- The client peer will need ZK chain tokens if they want to dispute a channel closure. In the vast majority of cases, this
  won't be necessary, since funds almost always flow in one direction from the client to the merchant. However, in
  instances where this is not the case, the client is able to dispute the channel closure by watching the ZK chain and
  proving that the channel was closed with outdated state.
- In the vast majority of cases, the client opens a channel with _m_ XMR and the public peer starts with a zero XMR balance
  (since the public peer is providing assets or services and not monetary value).
- Usually, both parties mutually close the channel. Either party _may_ force close the channel, and are able to claim their
  funds after a predetermined time-out. In this case, the forcing party is usually the merchant since they have the
  greater incentive to do so in the case where a channel has been abandoned by the client.

== Anti-principles

The following design goals are explicitly _excluded_ from the Grease design:

- Multi-hop channels. Multi-hop channels are probably _possible_ in Grease, but they are not a design goal.
Taking the Lightning Network as the case study, CJ  argues@monerokon-grease that the vast
majority of the utility of lightning is captured by bilateral channels, with a tiny fraction of the complexity.
