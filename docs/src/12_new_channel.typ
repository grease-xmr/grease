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
  - Protocol-specific initialization data. This might include commitments for parameters that will be shared later, the KES public keys that
    can be accepted, etc.
2. New channel proposal from Customer to Merchant
3. Accepting the proposal from Merchant to Customer

#include "../diagrams/new_channel_sequence.md"

=== Channel Id <channelId>

The channel id is a 65 character hexadecimal string that uniquely identifies the channel. It is defined as the prefix "XGC", followed by the
first 31 bytes of the *Blake2b-512* hash of the channel metadata in hexadecimal format.

The hash is calculated from the following transcript:

- The merchant public key, #Pm, 32 bytes in little-endian byte order,
- The customer public key, #Pc, 32 bytes in little-endian byte order,
- The merchant initial balance in piconero, as a 64-bit unsigned integer in little-endian byte order,
- The customer initial balance in piconero, as a 64-bit unsigned integer in little-endian byte order,
- The nominated closing address of the merchant, as a Base58 string,
- The nominated closing address of the customer, as a Base58 string,
- A merchant nonce, a 64-bit little-endian unsigned integer, randomly chosen by the merchant, and
- A customer nonce, a 64-bit little-endian unsigned integer, randomly chosen by the customer

