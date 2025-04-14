# Channel Establishment

The usual flow is isa follows:

The merchant shares some information with the Customer out-of-band. This could be via a QR code, or a link. This 
information will include the channel ID, the merchant's public key, and the (suggested) amount of Monero to be 
locked in the channel.

Assuming the client is happy with the terms, they will initiate a channel establishment request 
(`InitiateNewChannelRequest`) with the merchant. This request includes 
* the channel ID, 
* the amount of Monero to be locked in the channel (definitive), 
* the customer's public key.
* the encryption key for the key escrow service (KES)

```mermaid
sequenceDiagram
    participant C as Customer
    participant M as Merchant
    participant L1 as Monero blockchain
    participant L2 as ZK chain

    M ->> C: Initiate New Channel Request<br/>{amt_p, pubkey_M, channel_id_M}
    C ->> M: Accept Channel Request<br/>{pubkey_C, channel_id, tf_c, tc_c0, dk_0}
    par KES creation
        M ->> C: KES Public Info<br/>{channel_id, P_kes}
        C -->>+ L2: Watch for KES creation (optional)
        M ->> L2: Establish KES<br/>{amt, pubkey, channel_id}
        L2 ->> M: KES Created<br/>{??}
        L2 -->>- C: KES Created<br/>{??}
        C ->> C: Verify KES
        M ->> M: Verify KES
    and Open channel
        M ->> C: Send Secret Share (M)<br/>{???}
        C ->> M: Send Secret Share (C)<br/>{???}
        C ->> M: Partially Signed Funding Transaction (C)<br/>{???}
        M ->> C: Partially Signed Funding Transaction (M)<br/>{???}
        C ->> M: Create Funding Transaction (C)<br/>{???}
        M ->> M: Create Funding Transaction (M)<br/>{???}
        M ->>+ L1: Fund Channel<br/>{amt, pubkey, channel_id}
        L1 ->>- L1: Tx confirmed<br/>{??}
        M -->> C: Channel Opened<br/>{Y0, channel_id}
    end
    
    

```