= Future extensions and known limitations

Grease assumes that Monero will never implement state management features such as timelocks and scripting capabilities — the very features
that would let a channel enforce its own dispute resolution on the base layer. Lacking them, Grease delegates that role to an external
arbiter, and its principal limitations follow from that separation.

== Bilateral channels only

Grease is a two-party channel and does not attempt multi-hop routing — an explicit anti-principle of the design. Taking the Lightning Network
as a case study, we hold that the bulk of a payment channel's utility is captured by bilateral channels at a small fraction of the
complexity. Networks built by composing Grease channels are possible, but are not a goal of this work.

== Trust in the arbiter

Grease strips custody from its dispute resolver but not authority: the arbiter's guarantees rest on the honesty of its consensus platform.
The worst-case failure is a bounded rollback to a past state _both parties actually signed_, and only when the committee is compromised *and*
a channel party colludes; the funding key is never at risk and balances can never be fabricated. The full trust analysis is set out in
@arbiterDesign.

== Liveness depends on cooperation or an extension

If the arbiter halts, an honest party can still close, but only with its counterparty's cooperation; funds are never at risk, but a
unilateral close must wait. A channel that must survive an arbiter halt _without_ cooperation can adopt the time-beacon backstop of
@extensions, at the price of capacity-sized collateral and a bounded lifetime — which is why it is off by default.

== Watching duty

Because a dispute is resolved off-chain, each party must watch the arbiter's log for disputes on its channels, just as it watches the Monero
chain for a close. Both duties are delegable to a watchtower -- with the associated privacy risks -- which can recognize and answer a
dispute but can never redirect funds, since a close always pays the parties' own addresses (@arbiterPrivacy).

