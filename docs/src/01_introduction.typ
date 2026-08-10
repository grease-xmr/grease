= Introduction

Monero is, alongside cash, the world's most private @what-is-monero @all-about-monero @culafi24, and, arguably the best currency in
circulation, but the user _experience_ remains less than ideal. This comment is not necessarily aimed at user _interfaces_ -- for example,
there are Monero wallets that are very attractive and easy to use -- but the fundamental design of Monero means that:

- many, especially new, users find they can make only one payment roughly every ~20 minutes when their wallet holds a single spendable
  output (the change from the first payment typically requires about 10 confirmations before it can be spent again),
- due to the absence of scripting capabilities, use-cases that capture the public imagination, like DeFi, are not possible in vanilla
  Monero.

Therefore, the _experience_ of using Monero tends to be one of waiting, and limited functionality.

For Monero to achieve mass adoption, it will need to find ways to:

- provide an order of magnitude _better UX_ (again, not necessarily UI). Locking UTXOs after spending and block confirmation times add
  significant friction to Monero and is a turn-off for new users who are already unsure about how cryptocurrency works.
- provide _instant confirmations_ when purchasing with Monero.
- enable _seamless point-of-sale transactions_ so that using Monero for purchases feels no different to using a credit card or Venmo.
- enable DeFi for Monero. DeFi is the future of finance. The lack of permissionless access to bank-like services (loans, insurance, and
  investments) is a key barrier to truly democratic money.
- provide for Monero-backed and/or privacy-maximizing stable coins.

A payment-channel solution for Monero is one of the foundational requirements for achieving these goals in Monero. The other is smart
contracting functionality, but that is out of scope for this project.

== Payment channels in Monero

Monero's primary function is private, fungible money. This goal very likely excludes any kind of meaningful on-chain state management for
Monero, since state implies heterogeneity. And heterogeneity immediately breaks fungibility. That's not to say that some hitherto
undiscovered insight won't allow this in future, but for the short and medium-term at least, any kind of state management for Monero
transactions or UTXOs would have to be stored off-chain.

The small amount of state a channel needs in order to resolve a dispute — which of two signed records is the more recent — is not private;
it is a public fact that both parties already share. What it needs is a platform that will evaluate that fact deterministically and act on
it in a way no single operator can subvert. A public consensus platform provides exactly this.

It's the goal of this project to pair Monero (for private money) with such a platform (for trustless dispute resolution) to create a
proof-of-concept payment channel for Monero.

=== Enter Grease

The Grease protocol is a new bi-directional payment channel design with unlimited lifetime for Monero. It is built on FCMP++ (Full-Chain
Membership Proofs++), which replaces Monero's fixed-size ring signatures with a succinct proof that a spent output belongs to the whole set of
outputs on the chain. Because that membership proof is assembled when a transaction is finally broadcast rather than when it is signed, two
properties follow that shape the entire design:

- A channel's pre-signed closing transaction never becomes stale, which is what gives a Grease channel its unlimited lifetime.
- A transaction can be signed against a funding output that has been _determined_ but not yet mined, so a channel's initial state is fully
  signed before any money moves. Either party may fund the channel, or both may, with nobody having to deposit first and trust the other to
  reciprocate.

Using the Grease protocol, two peers may trustlessly #footnote[No trust is needed between the channel parties. Dispute resolution relies on
  an arbiter, whose trust assumptions reduce to those of its consensus platform; the arbiter holds no funds and no
  secret whose leak could cost a channel anything.] cooperate to share, divide and reclaim a common locked amount of Monero XMR while
minimizing the online transaction costs and with minimal use of outside trusted third parties.

The Grease protocol maintains all of Monero's security. No identifiable information about the peers' privately owned Monero wallets is
shared between the peers. This means that there is no way that privacy can be compromised. Each channel lifecycle requires two Monero
transactions, with effectively unlimited near-instant updates to the channel balance in between these two transactions. This dramatically
improves the scalability of Monero.

The Grease protocol is based on the original AuxChannel@aux-channel paper and Monet@monet protocol. Monet provides a sketch of a payment
channel design but many details were omitted or elided. Grease is a full-fledged implementation with full consideration given to state
management, multiple concurrent channels, peer-to-peer communication and encryption and practical performance.

Every update and the final closure of the channel require an online interaction between channel parties. In order to prevent the accidental
or intentional violation of the protocol by a peer not interacting and thus jamming the channel closure, Grease introduces an external
_arbiter_. The arbiter needs to run on a stateful, logic- and time-aware platform whose behavior is determined by consensus rather than by
any single operator. A decentralized smart-contract platform satisfies this requirement.

=== Why does another platform have to be involved?

Offline payment channels necessarily _require_ a state management mechanism. Typically, the scripting features for a given blockchain allow
for this state to be managed directly. However, Monero's primary design goals are privacy and fungibility. Attaching state to UTXOs would
create a heterogeneity that threatens these goals. Fungibility is more important than features when it comes to privacy.

The dispute state does not have to be managed on the same chain though. Any place where it is:

- available,
- reliable,
- has trust assumptions appropriate for the value involved,

will suffice. Note that this state is not secret — it is a public record of which channel update is the most recent — so the platform is
never asked to keep a secret, only to run its published logic honestly.

The initial implementation targets the Internet Computer, whose canisters can hold a stable threshold key on behalf of the whole validator
set and release an attestation on demand under the control of on-chain logic.

The arbiter acts as a third-party judge in disputes, but holds nothing that could be stolen. At every update, each peer encrypts a fresh
secret offset so that it can only be recovered once the arbiter attests that this state is the channel's latest. This uses _identity-based
encryption_: a value can be sealed to a short "identity" — here the statement "this is the channel's latest state" — using only a public key,
and it becomes decryptable only when the arbiter issues the single attestation that matches that identity. The offset is sealed long before
any dispute; if one arises, the arbiter attests the most recent state either party can prove, and that attestation is exactly the key that
unseals the offset closing at it. A stale or fabricated state is never attested and can never be closed. @arbiterDesign has full details on
the arbiter's design and implementation.

= Design principles

Grease is a bidirectional two-party payment channel. This means that funds can flow in both directions, but in the vast majority of cases,
funds will flow from one party (the "customer") to the other (the "merchant"). This designation is somewhat arbitrary, either party in a
channel may assume either role. Most channels will have participants that are easily identifiable in either the customer or merchant role
and we use that terminology throughout this document.

Grease embraces this use case and optimizes the design and UX based on the following assumptions:

- The merchant is, by convention, the party that interacts with the arbiter — lodging any optional setup deposit and covering its fees.
- The merchant therefore needs to hold a small amount of the arbiter chain's native token to pay those fees.
- The customer needs a small quantity of the arbiter chain's token to dispute a closure. In the vast majority of cases this
  won't be necessary, since funds almost always flow in one direction from the customer to the merchant. In practice, the merchant can
  supply this if the customer has none. The customer must watch the arbiter and present a more recent cross-signed record than the one
  the merchant tried to close on in the case of a dispute.
- In the vast majority of cases, the customer opens a channel with _m_ XMR and the merchant starts with a zero XMR balance (since the
  merchant is providing assets or services in exchange for Monero). The design does not require this: either party may fund, and a merchant
  that wants a balance to refund or spend from contributes a funding output of its own alongside the customer's (@fundingDeclaration).
- Usually, both parties mutually close the channel. Either party _may_ close the channel unilaterally through the arbiter, and are able to
  claim their funds once the adjudication window has elapsed. In this case, the party doing so is usually the merchant since they have the
  greater incentive to do so in the case of an abandoned channel.

== Anti-principles

The following design goals are explicitly _excluded_ from the Grease design:

- Multi-hop channels. Multi-hop channels are probably _possible_ in Grease, but they are not a design goal.
Taking the Lightning Network as the case study, CJ argues@monerokon-grease that the vast majority of the utility of lightning is captured by
bilateral channels, with a tiny fraction of the complexity.
