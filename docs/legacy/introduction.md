# Introduction

_Note: This markdown version is retained for convenience, but may not be maintained in the future. The typst version
(docs/introduction.typ) is the canonical version._

Monero is, alongside cash, the world's most private [[1],[2],[3]] and, arguably the best currency in circulation, but
the user _experience_ remains less than ideal.
This comment is not necessarily aimed at user _interfaces_ -- for example, there are Monero wallets that are
very attractive and easy to use -- but the fundamental design of Monero means that:

- many, especially new, users find that they can only process a single send every ~20 minutes (since their wallets
  contain a single UTXO),
- due to the lack of scripting capabilities, use-cases that capture the public imagination, like DeFi, are not
  possible in vanilla Monero.

Therefore, the _experience_ of using Monero tends to be one of waiting, and limited functionality.

[1]: https://www.getmonero.org/get-started/what-is-monero/ "Monero: What is Monero?"
[2]: https://www.chainalysis.com/blog/all-about-monero/ "Monero: All About the Top Privacy Coin"
[3]: https://www.techtarget.com/searchsecurity/news/252512394/Monero-and-the-complicated-world-of-privacy-coins "Monero and the complicated world of privacy coins"

For Monero to achieve mass adoption, it will need to find ways to

1. provide an order of magnitude _better UX_ (again, not necessarily UI). Locking UTXOs after spending and block
   confirmation times add significant friction to Monero and is a turn-off for new users who are already unsure
   about how cryptocurrency works.
2. provide _Instant confirmations_ when purchasing with Monero.
3. enable _seamless point-of-sale transactions_ so that using Monero for purchases feels no different to using a
   credit card or Venmo.
4. enable DeFi for Monero. DeFi is  the future of finance. The lack of permissionless access to bank-like services
   (loans, insurance, and investments) is a key barrier to truly democratic money.
5. provide for Monero-backed and/or privacy-maximizing stable coins.

A payment-channel solution for Monero is one of the foundational requirements for achieving these goals in Monero.
The other is smart contracting functionality, but that is out of scope for this project.

## Payment channels in Monero

Monero's primary function is private, fungible money.
This goal very likely excludes any kind of meaningful on-chain state management for Monero, since state implies
heterogeneity.
And heterogeneity immediately breaks fungibility.
That's not to say that some hitherto undiscovered insight won't allow this in future, but for the short and
medium-term at least, any kind of state management for Monero transactions or UTXOs would have to be stored off-chain.

It makes the most sense to store this off-chain state on another decentralized, private protocol.
Zero-knowledge Rollup blockchains (ZKR) fit the bill nicely.

It's the goal of this project to marry Monero (for private money) with a ZK-rollup chain (for private state
management) to create a proof-of-concept Monero payment channel for Monero.

### Enter Grease

Grease is a proof-of-concept Monero payment channel that uses a ZK-rollup chain for off-chain state management.

It aims to tackle the use cases that are exemplified by the following scenarios:

#### Rapid point-of-sale

Alice is a customer of Bob's bar. Alice will be making multiple purchases throughout an evening. She opens a channel at
the beginning of the evening with a certain amount of Monero, and can make instant purchases against it until she and
Bob mutually close the channel at the end of the evening and the final settlement is recorded on the Monero chain.

#### Micro-transactions

Bob owns a Monero-enabled arcade. Dave can open a channel and play dozens, or hundreds of games until his balance runs
out. Each payment is instant and secure, does not bloat the Monero blockchain, and is completely private. Some games
might offer rebate prizes which can be pushed straight back into the channel.

#### Private and anonymous content consumption

Erica's online newspaper utilizes a pay-per-view model. Instead of a monthly subscription fee, users open a channel
with their maximum "reading budget" and instantly and seamlessly pay for each article they read. No accounts, no KYC
and no email addresses are required. At the end of the month, users can close the channel to settle their bills, or
default opt to continue their balance to the next month without closing the channel (and hence performing an onchain
swap with the associated XMR fees). That is to say that if Fred has read 100 articles at 0.0005 XMR each, and has sent
0.05 XMR down the channel, he can pay 0.05 XMR on-chain, and Erica pushes that amount back up the channel, effectively
resetting the state for the new month. This provides the ability to have a combination of the use-or-lose minimum fee
plus À la carte options which is standard in legacy subscription models.

### Why does another chain have to be involved?

Offline payment channels necessarily require a trustless state management mechanism. Typically, the scripting features
for a given blockchain allow for this state to be managed directly. However, Monero's primary design goals are privacy
and fungibility. Attaching state to UTXOs would create a heterogeneity that threatens these goals. (Fungibility is more
important than specialty for maintaining privacy.)

The state does not have to be managed on the same chain though. Any place where the state is

- available,
- reliable and verifiable,
- trustless,

will suffice.

The [AuxChannel] and [MoNet] papers (summarized in [Payment Channel Network for Scriptless Blockchains]) provide a
workable demonstration of this, using Ethereum as the state management chain. However, by using Ethereum, the channel
metadata, including the peer's public keys and the channel state (open, disputed) is scrutable by the public.

Grease aims to improve on this by making the payment channel metadata private as well. Zero knowledge proofs provide a
way to do this.

[AuxChannel]: https://eprint.iacr.org/2022/117.pdf
[MoNet]: https://eprint.iacr.org/2022/744.pdf
[Payment Channel Network for Scriptless Blockchains]: https://bridges.monash.edu/articles/thesis/Payment_Channel_Network_for_Scriptless_Blockchains/23909907

## Design principles

Grease is a bidirectional two-party payment channel. This means that funds can flow in both directions, but in the
vast majority of cases, funds will flow from one party (the client, or private peer) to the other (the merchant, or
public peer).

Grease embraces this use case and optimizes the design and UX based on the following assumptions:

- The public peer is responsible for recording the channel state on the ZK chain.
- The public peer pays for gas fees on the ZK chain and will need to have some amount of ZK chain tokens to pay for
  these fees.
- The public peer will be able to recover gas fees from the client peer.
- The client peer does not **have** to have any ZK chain tokens, but will need to hold Monero to open the channel.
- The client peer will need ZK chain tokens if they want to dispute a channel closure. In the vast majority of cases,
  this won't be necessary, since funds almost always flow in one direction from the client to the merchant. However,
  in instances where this is not the case, the client is able to dispute the channel closure by watching the ZK
  chain and proving that the channel was closed with outdated state.
- In the vast majority of cases, the client opens a channel with _m_ XMR and the public peer starts with a zero XMR
  balance (since the public peer is providing assets or services and not monetary value).
- Usually, both parties mutually close the channel. Either party **may** force close the channel, and are able to
  claim their funds after a predetermined time-out. In this case, the
  forcing party is usually the merchant since they have the greater incentive to do so in the case where a channel
  has been abandoned by the client.

### Anti-principles

The following design goals are explicitly _excluded_ from the Grease design:

* Multi-hop channels. Multi-hop channels are probably _possible_ in Grease, but they are not a design goal. 
  Taking the Lightning Network as the case study, [CJ argues](monerokon5) that the vast majority of the utility of 
  lightning is captured by bilateral channels, with a tiny fraction of the complexity.

[monerokon5]: https://cfp.twed.org/mk5/talk/QYDGPM/ "Grease: A Minimalistic Payment Channel Implementation for Monero"