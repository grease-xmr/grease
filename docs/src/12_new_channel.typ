== New Channel

A new channel is established when a Merchant shares some initialization data with a Customer
out-of-band.

The customer takes this data, combines it with their own information, and sends a channel proposal to the Merchant.

There are *three* half-rounds of communication in this phase#footnote([See `server.rs:customer_establish_new_channel`]):

1. Out-of-band channel initialization data (CID) sharing from Merchant to Customer:
    - Contact information for the merchant
    - Channel seed metadata. This includes metadata so that both merchant and customer can uniquely identify the
      channel throughout the channel's lifetime. This includes:
        - an id for the channel
        - The merchant's closing address
        - The requested initial balances
        - The merchant's id
    - Protocol-specific initialization data. This might include commitments for parameters that will be shared later,
      the KES public keys that can be accepted, etc.
2. New channel proposal from Customer to Merchant
3. Accepting the proposal from Merchant to Customer

#include "../diagrams/new_channel_sequence.md"
