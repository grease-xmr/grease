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

The channel id uniquely identifies the channel and _commits to its funding output_, so that every record and every dispute is bound to one
specific 2-of-2 wallet. It is the prefix "XGC" followed by the first 31 bytes of the *Blake2b-512* hash of the transcript below, rendered in
hexadecimal (a 65-character string).

The transcript combines the negotiated channel metadata with the funding output's _linking tag_ $L_F$ — the key image that any spend of the
funding output publishes, which the two parties compute jointly from the shared wallet:

- The merchant public key, #Pm, 32 bytes in little-endian byte order,
- The customer public key, #Pc, 32 bytes in little-endian byte order,
- The merchant initial balance in piconero, as a 64-bit unsigned integer in little-endian byte order,
- The customer initial balance in piconero, as a 64-bit unsigned integer in little-endian byte order,
- The nominated closing address of the merchant, as a Base58 string,
- The nominated closing address of the customer, as a Base58 string,
- The funding output linking tag, $L_F$, 32 bytes in little-endian byte order,
- A merchant nonce, a 64-bit little-endian unsigned integer, randomly chosen by the merchant, and
- A customer nonce, a 64-bit little-endian unsigned integer, randomly chosen by the customer.

Because $L_F$ is only fixed once the shared funding wallet exists, the id is _finalized during establishment_ (@initProtocol), not during the
initial negotiation: the parties settle the metadata in the `New` phase and compute the id as soon as they have jointly derived $L_F$.

Two properties follow, both relied on by the arbiter (@arbiterDesign). First, the id _commits to_ $L_F$, so a record or attestation carrying
it is bound to this funding output and cannot be replayed against another channel. Second, the id _hides_ $L_F$: the two random nonces blind
the hash, so publishing the id reveals neither the funding output nor any way to locate its eventual close on the Monero chain — only a holder
of the transcript (the counterparties, and any watchtower they appoint) can open the commitment. The arbiter uses the id only as an opaque,
unique label, so this binding costs it no knowledge of the channel's funds.

