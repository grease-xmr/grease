#import "@preview/note-me:0.5.0": *

= The Grease Channel Lifecycle

== Overall design description

Grease builds on the Monet@monet design, a payment channel protocol that introduced the use of a third-party arbiter to resolve channel
disputes.

A Grease payment channel is a 2-party bidirectional channel. The most common use case is in a multi-payment arrangement between a customer
and a merchant, and so we will label the parties as such.

To set up a new channel, the customer and merchant agree on the funds to be locked in the channel. They're usually all provided by the
customer, but it doesn't need to be. These funds are sent to a new 2-of-2 multisig wallet, which is created on the Monero blockchain for the
sole purpose of serving the channel.

The idea is that a _commitment transaction_, so-called for reasons that will be made clear later, spends the funds out of the multisig
wallet back to the customer and merchant can be trustlessly, securely and rapidly updated many thousands of times by the customer and
merchant without having to go on-chain.

Every time the channel is updated, the customer and merchant provide signatures that _can't be used to spend the funds_ out of the multisig
wallet, but _prove_ that they will be able to spend the funds if a small piece of missing data is provided #footnote([These signatures are
  called adapter signatures.]). When the channel is closed, the customer gives the merchant that little piece of data and the funds are
spent out of the multisig wallet to the customer and merchant, closing the channel.

If the merchant cheats and tries to close the channel with an outdated state, or decides not to broadcast the commitment transaction, the
customer can resolve the closure through an _arbiter_.

The arbiter resolves disputes. It is a deterministic state machine deployed on a public consensus platform, and it holds no share of the
channel's funds and no secret whose leak could cost a channel anything. It won't be called upon for the vast majority of channel instances,
but its presence is what makes cheating pointless.

#note[
  In fact, you could run Grease without an arbiter, if there is a high-trust relationship between the customer and merchant.
]

At every channel update, each party generates a fresh secret offset that completes the counterparty's half of that state's closing
signature, and hands the counterparty a _verifiably encrypted offset_: the offset, encrypted so that it can only be recovered once the arbiter attests that this
state is the channel's latest. No secret is ever handed to the arbiter, and the arbiter never sees a ciphertext.

If the merchant tries to close using an outdated state, or refuses to publish anything at all, the customer presents its latest cross-signed
record to the arbiter. The arbiter opens a window, during which either party may present a newer record, and then attests the highest update
count it has seen.

That attestation releases the offset for the _true latest_ state, and only that state. The customer completes and broadcasts the latest
closing transaction, recovering its correct balance; the merchant's stale close is never attested and so can never be completed. Cheating is
not punished — it is simply frozen — which is exactly what motivates parties to behave honestly.

#warning[
  Once a channel is closed, neither party should use the 2-of-2 multisig wallet again, since there exists another party that can immediately
  spend out of that wallet.
]

== High-level state machine

On a high level, the payment channel lifecycle goes through 6 phases:

- `New` - The channel has just been created and is entering the establishment negotiation phase. Basic information is swapped in this phase,
  including the public keys of the peers, the nominated arbiter, and the initial balance. The channel parameters agreed here — initial
  balances, public keys and closing addresses — feed the channel id, which is finalized once the funding output exists and commits to it (See
  @channelId). If both parties are satisfied with the proposed channel parameters, the channel moves to the `Establishing` state.
- `Establishing` - The channel is being established. This phase creates and funds the multisig wallet. Once both parties have verified the
  funding transaction, the parties will share an `AckChannelEstablished` message. Once acknowledged, an `OnChannelEstablished` event is
  emitted, and the channel will move to the `Open` state.
- `Open` - The channel is open and ready for use. Any number of channel update events can occur in this phase and the channel can remain in
  this state indefinitely. The channel remains in this state until the channel is closed via the amicable `Closing` state or the `Disputing`
  state. At each update, both parties cryptographically _commit_ to the new state of the channel and collaborate to produce a new,
  partially-signed commitment transaction.
- `Closing` - The channel is being closed. This phase includes sharing of adapter secrets and signing of the final commitment transaction.
  Once both parties have signed the final commitment transaction, any party will be able to broadcast it, but by convention it will be the
  merchant that does so.
- `Closed` - The channel is closed. A channel can reach the `Closed` state after a co-operative close, following a resolved dispute, or
  after several error conditions arising during the `New` and `Establishing` phases. The arbiter keeps no per-channel state outside an open
  dispute, so there is nothing to clean up.
- `Disputing` - The channel is being disputed because someone initiated a unilateral close. If the local party initiated it, this phase
  includes presenting its latest cross-signed record to the arbiter and waiting for the adjudication window to expire so that the
  counterparty's offset can be recovered in order to synthesize the closing transaction. If the other party initiated the dispute, we can
  present a newer record to the arbiter, or do nothing if we hold no newer state. The final state transition is always to the `Closed`
  state, only the reason can vary. See @arbiterDesign for details.
