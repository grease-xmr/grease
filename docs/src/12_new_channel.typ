#import "metadata/nomenclature.typ": *

== New Channel

A new channel is established when a Merchant shares some initialization data with a Customer out-of-band.

The customer takes this data, combines it with their own information, and sends a channel proposal to the Merchant.

There are *three* half-rounds of communication in this phase#footnote([See `server.rs:customer_establish_new_channel`]):

1. Out-of-band channel initialization data (CID) sharing from Merchant to Customer:
  - Contact information for the merchant
  - Channel seed metadata. This includes metadata so that both merchant and customer can uniquely identify the channel throughout the
    channel's lifetime. This includes:
    - a random nonce id,
    - the merchant's closing address,
    - the requested initial balances,
    - the merchant's public key,
    - the dispute window duration
  - Protocol-specific initialization data. This might include commitments for parameters that will be shared later, the arbiters that can be
    accepted, etc.
2. New channel proposal from Customer to Merchant
3. Accepting the proposal from Merchant to Customer

#figure(include "../diagrams/new_channel_sequence.md", caption: [The New Channel proposal sequence]) <new_channel_sequence>

=== Channel Id <channelId>

The channel id uniquely identifies the channel and, once final, _commits to its funding outputs_, so that every record and every dispute is
bound to one specific 2-of-2 wallet. It is a 65-character string: a three-character prefix followed by the first 31 bytes of the
*Blake2b-512* hash of the transcript below, rendered in hexadecimal (62 characters). The prefix is `XGC` for a final id and `XGT` for a
_provisional_ one — a channel still under negotiation, whose funding outputs have not been declared yet.

The transcript combines the negotiated channel metadata with the _linking tags_ $L_F$ of the channel's funding outputs — the key images that
their spend will publish, one per funding party, which the two parties derive jointly from the shared wallet with each proving its
contribution correct (@linkingTagExchange):

- The merchant public key, #Pm, 32 bytes in little-endian byte order,
- The customer public key, #Pc, 32 bytes in little-endian byte order,
- The merchant initial balance in piconero, as a 64-bit unsigned integer in little-endian byte order,
- The customer initial balance in piconero, as a 64-bit unsigned integer in little-endian byte order,
- The nominated closing address of the merchant, as a Base58 string,
- The nominated closing address of the customer, as a Base58 string,
- The funding linking tags $L_F$: each tag 32 bytes in little-endian byte order, ordered ascending by that encoding and concatenated — an
  empty message while the id is provisional,
- A merchant nonce, a 64-bit little-endian unsigned integer, randomly chosen by the merchant, and
- A customer nonce, a 64-bit little-endian unsigned integer, randomly chosen by the customer.

"Randomly chosen" is a strict requirement, not advice: each party *must* draw its nonce uniformly at random. The nonces are what makes id uniqueness
unconditional rather than a byproduct of key hygiene — the contribution proof (@linkingTagExchange) guarantees that $L_F$ is honestly
derived from the two partial spend keys, but an honestly derived tag still repeats if a spend key does, and every other transcript field
may legitimately repeat. A fresh nonce is each party's _unilateral_ guarantee that no two of its channels share an id, whatever the
counterparty does. The merchant's nonce travels with the out-of-band seed, which may be reused across proposals; within one seed it is
therefore the customer's nonce that separates channel ids. A party that reuses its own nonce bears the resulting collision risk itself:
two ids can only collide if _both_ parties repeat their nonces along with every other field of the transcript.

Because $L_F$ is only fixed once the funding outputs are declared, the id is derived in two stages. The parties settle the metadata in the
`New` phase and hash the transcript with an empty `funding_linking_tags` message, giving the provisional `XGT` id, which identifies the
negotiated parameters but commits to no funding output. The id is _finalized during establishment_ (@initProtocol), as soon as each party has
declared the output it will contribute and the parties have jointly derived the tag for each: the same transcript is hashed with the tags in
place, giving the final `XGC` id.

The prefix is a *display-layer tag and is not absorbed into the transcript*. It does not need to be, because the two hashes already differ:
`funding_linking_tags` is absorbed as an empty message in the provisional case and as the concatenated tags in the final one, and every
transcript message is length-prefixed, so an absent tag can never collide with a present one — nor can a singly-funded channel's one tag
collide with a dual-funded channel's two. What the prefix adds is legibility — a party holding nothing but the id string can tell which kind
of id it has, without holding the metadata behind it.

That statement is about the id transcript alone, and it has a load-bearing complement one layer down. Every transcript that turns a channel
id into signed or sealed bytes — the dispute statement $m = (#raw("id"), i)$ that the arbiter attests and offsets are encrypted to
(@arbiterDesign), the adapter-signature message, the update record, and the establishment payloads — absorbs the id as its full 65-character
prefixed string. At that layer the prefix _is_ full domain separation between a provisional and a final channel: the two statements differ
in the first three bytes of the message by construction, whatever their hex halves do. An implementation must therefore absorb the id string
whole; "normalising" an id to its hex half or its raw hash bytes before signing or sealing would silently delete that separation.

A channel id is bound to its funding outputs exactly once: finalizing an id that is already final is refused, because it would silently
rename a channel that the counterparty, the stored records and any watchtower already refer to by its current id. Nor may a provisional id
carry cryptographic weight. No adapter signature, verifiably encrypted offset, binding proof or update record may be produced against one, for
two reasons: such material commits to an id that finalization is about to supersede, so it would not verify against the channel's real id; and
a provisional id commits to no funding output, so material sealed to it is not bound to one specific wallet. Establishment enforces this — the
initial-state package can neither be generated nor accepted before the id is final.

Two properties follow from the final id, both relied on by the arbiter (@arbiterDesign). First, the id _commits to_ $L_F$, so a record or
attestation carrying it is bound to these funding outputs and cannot be replayed against another channel. Second, the id _hides_ $L_F$: the
two random nonces blind the hash, so publishing the id reveals neither the funding outputs nor any way to locate their eventual spend on the
Monero chain — only a holder of the transcript (the counterparties, and any watchtower they appoint) can open the commitment. The arbiter
uses the id only as an opaque, unique label, so this binding costs it no knowledge of the channel's funds.

