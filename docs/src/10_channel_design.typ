#import "@preview/note-me:0.5.0": *

= The Grease Channel Lifecycle

== Overall design description

Grease largely follows the Monet@monet design, which is a payment channel protocol that uses a key escrow service (KES) to manage the funds
in the channel.

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
customer can dispute the closure of the channel with the key escrow service (KES).

The KES is responsible for arbitrating disputes. It is ideally a permissionless, decentralized private smart contract, but it can be a
centralized 3rd-party service as well. It won't be called upon for the vast majority of channel instances, but its presence it mandatory to
disincentivize cheating.

#note[
  In fact, you could run Grease without a KES, if there is a high-trust relationship between the customer and merchant.
]

When the 2-of-2 multisig wallet is created, both the customer and merchant encrypt their adapter signature offset to the KES.

If, say, the merchant tries to force-close a channel using an outdated state (which is itself enacting the dispute process), or refuses to
publish anything at all (in which case the customer will enact the force-close process), the customer has a certain window in which it can
prove to the KES that it has a valid, more recent channel state signature.

In a successful dispute, either by waiting for the challenge period to end, or the KES accepts the challenge, the KES will hand over the
merchant's first adapter offset. The customer will then be able to sign any transaction in the history of the channel by reconstructing the
appropriate adapter signature offset, including any states that favour the customer. This is a form of punishment that should motivate
parties to behave honestly.

#warning[
  One a channel is closed, neither party should use the 2-of-2 multisig wallet again, since there exists another party that can immediately
  spend out of that wallet.
]

== High-level state machine

On a high level, the payment channel lifecycle goes through 6 phases:

- `New` - The channel has just been created and is entering the establishment negotiation phase. Basic information is swapped in this phase,
  including the public keys of the peers, the nominated KES, and the initial balance. The channel id is derived data describing the channel,
  including, the initial balance, public keys and closing addresses (See @channelId). If both parties are satisfied with the proposed
  channel parameters, the channel moves to the `Establishing` state.
- `Establishing` - The channel is being established. This phase includes the KES establishment and funding transaction. Once the KES is
  established and both parties have verified the funding transaction, the parties will share an `AckChannelEstablished` message. Once
  acknowledged, an `OnChannelEstablished` event is emitted, and the channel will move to the `Open` state.
- `Open` - The channel is open and ready for use. Any number of channel update events can occur in this phase and the channel can remain in
  this state indefinitely. The channel remains in this state until the channel is closed via the amicable `Closing` state or the `Disputing`
  state. The peers share an `AckWantToClose` message to signal a desire to close the channel. This triggers an `OnStartClose` event, and the
  channel will move to the `Closing` state. If the counterparty party initiates a force-close on the channel via the KES, an `onForceClose`
  event is emitted, and the channel moves to the `Disputing` state. If the counterparty stops responding to updates or for whatever other
  reason, you can trigger a force close (an `onTriggerForceClose` event), and the channel will move to the `Disputing` state.
- `Closing` - The channel is being closed. This phase includes sharing of adapter secrets and signing of the final commitment transaction.
  Once both parties have signed the final commitment transaction, any party will be able to broadcast it, but by convention it will be the
  merchant that does so.
- `Closed` - The channel is closed. The merchant *should* inform the KES of the closure so that it can clean up any state associated with
  the channel. A channel can reach the `Closed` state after a co-operative close, following a resolved dispute, or after several error
  conditions arising during the `New` and `Establishing` phases.
- `Disputing` - The channel is being disputed because someone initiated a force-close. If the local party initiated the force close, this
  phase includes invoking the force-close on the KES, and waiting for the dispute window to expire so that the counterparty's secret can be
  recovered in order to synthesize the closing transaction. If the other party initiated the force-close, we can invoke the KES to challenge
  the closing state, submit the correct signature offset, $omega_n$, or do nothing and allow the counterparty to use your $omega_0$ to
  recover any previous channel state. The final state transition is always to the `Closed` state, only the reason can vary. See @kesDesign
  for details.
