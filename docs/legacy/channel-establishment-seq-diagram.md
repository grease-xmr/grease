# Channel Establishment

The usual flow is as follows:

The merchant shares some information with the Customer out-of-band. This could be via a QR code, or a link. This 
information will include the channel ID, the merchant's public key, and the (suggested) amount of Monero to be 
locked in the channel.

Assuming the client is happy with the terms, they will initiate a channel establishment request 
(`InitiateNewChannelRequest`) with the merchant.

Channel establishment involves:
* Setting up a new 2-of-2 multisig Monero wallet, into which the funding transaction funds will be sent.
* Splitting the spending key of the multisig wallet into two secret shares, one for the other party to hold and one 
  that is stored by the key escrow service.
* Creating the key escrow service (KES) on the ZK chain, which will be used to store the one of the secret shares of 
  the 
  multisig wallet. The KES is created by the merchant, and the customer can verify it.
* 
* the channel ID, 
* the amount of Monero to be locked in the channel (definitive), 
* the customer's pseudonymous public key (which the customer can rotate as desired),
* the encryption one-time public key for the key escrow service (KES).
* The split secret for spending the comm


{!include "diagrams/establish_channel.md"}
