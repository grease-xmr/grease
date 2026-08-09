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

The channel id uniquely identifies the channel and, once final, _commits to its funding output_, so that every record and every dispute is
bound to one specific 2-of-2 wallet. It is a 65-character string: a three-character prefix followed by the first 31 bytes of the
*Blake2b-512* hash of the transcript below, rendered in hexadecimal (62 characters). The prefix is `XGC` for a final id and `XGT` for a
_provisional_ one — a channel still under negotiation, whose funding output does not exist yet.

The transcript combines the negotiated channel metadata with the funding output's _linking tag_ $L_F$ — the key image that any spend of the
funding output publishes, which the two parties compute jointly from the shared wallet:

- The merchant public key, #Pm, 32 bytes in little-endian byte order,
- The customer public key, #Pc, 32 bytes in little-endian byte order,
- The merchant initial balance in piconero, as a 64-bit unsigned integer in little-endian byte order,
- The customer initial balance in piconero, as a 64-bit unsigned integer in little-endian byte order,
- The nominated closing address of the merchant, as a Base58 string,
- The nominated closing address of the customer, as a Base58 string,
- The funding output linking tag, $L_F$, 32 bytes in little-endian byte order — an empty message while the id is provisional,
- A merchant nonce, a 64-bit little-endian unsigned integer, randomly chosen by the merchant, and
- A customer nonce, a 64-bit little-endian unsigned integer, randomly chosen by the customer.

Because $L_F$ is only fixed once the shared funding wallet exists, the id is derived in two stages. The parties settle the metadata in the
`New` phase and hash the transcript with an empty `funding_linking_tag` message, giving the provisional `XGT` id, which identifies the
negotiated parameters but commits to no funding output. The id is _finalized during establishment_ (@initProtocol), as soon as the parties
have jointly derived $L_F$: the same transcript is hashed with the 32-byte tag in place, giving the final `XGC` id.

The prefix is a *display-layer tag and is not absorbed into the transcript*. It does not need to be, because the two hashes already differ:
`funding_linking_tag` is absorbed as an empty message in the provisional case and as a 32-byte value in the final one, and every transcript
message is length-prefixed, so an absent tag can never collide with a present one. What the prefix adds is legibility — a party holding
nothing but the id string can tell which kind of id it has, without holding the metadata behind it.

A channel id is bound to a funding output exactly once: finalizing an id that is already final is refused, because it would silently rename
a channel that the counterparty, the stored records and any watchtower already refer to by its current id. Nor may a provisional id carry
cryptographic weight. No adapter signature, verifiably encrypted offset, binding proof or update record may be produced against one, for two
reasons: such material commits to an id that finalization is about to supersede, so it would not verify against the channel's real id; and a
provisional id commits to no funding output, so material sealed to it is not bound to one specific wallet. Establishment enforces this — the
initial-state package can neither be generated nor accepted before the id is final.

Two properties follow from the final id, both relied on by the arbiter (@arbiterDesign). First, the id _commits to_ $L_F$, so a record or
attestation carrying it is bound to this funding output and cannot be replayed against another channel. Second, the id _hides_ $L_F$: the
two random nonces blind the hash, so publishing the id reveals neither the funding output nor any way to locate its eventual close on the
Monero chain — only a holder of the transcript (the counterparties, and any watchtower they appoint) can open the commitment. The arbiter
uses the id only as an opaque, unique label, so this binding costs it no knowledge of the channel's funds.

