# Grease Payment Channel FSM

This document describes the complete Finite State Machine (FSM) for Grease payment channels, showing all states, transitions, and the protocol traits implemented by each state.

## State Machine Diagram

```mermaid
stateDiagram-v2
    [*] --> Proposing: Create channel

    state Proposing {
        note right of Proposing
            <b>Protocol Traits:</b>
            - ProposeProtocolCommon
            - ProposeProtocolProposer (Merchant)
            - ProposeProtocolProposee (Customer)
        end note
    }

    Proposing --> Establishing: ProposalAccepted / MerchantAcceptedProposal
    Proposing --> Closed: RejectProposal / Timeout

    state Establishing {
        note right of Establishing
            <b>Protocol Traits:</b>
            - EstablishProtocolCommon&lt;C, D&gt;
            - EstablishProtocolMerchant&lt;C, D&gt;
            - EstablishProtocolCustomer&lt;C, D&gt;
            - PeerInfo&lt;C&gt;
            - HasRole, HasPublicKey, HasSecretKey
        end note
    }

    Establishing --> Open: requirements_met() = true
    Establishing --> Closed: timeout

    state Open {
        note right of Open
            <b>Protocol Traits:</b>
            - UpdateProtocolCommon&lt;C&gt;
            - UpdateProtocolProposer&lt;C&gt;
            - UpdateProtocolProposee&lt;C&gt;
            - HasRole
        end note
    }

    Open --> Closing: cooperative_close()
    Open --> Disputing: force_close()

    state Closing {
        note right of Closing
            <b>Protocol Traits:</b>
            - CloseProtocolCommon
            - CloseProtocolInitiator
            - CloseProtocolResponder
            - HasRole
        end note
    }

    Closing --> Closed: final_tx_confirmed()

    state Disputing {
        note right of Disputing
            <b>Protocol Traits:</b>
            - ForceCloseProtocolCommon
            - ForceCloseProtocolClaimant
            - ForceCloseProtocolDefendant
            - HasRole
        end note
    }

    Disputing --> Closed: dispute_resolved()

    state Closed {
        note right of Closed
            <b>Reasons:</b>
            - Normal (cooperative close)
            - Timeout (channel expired)
            - ForceClosed
            - Disputed
            - Rejected (proposal rejected)
        end note
    }

    Closed --> [*]
```

## State Descriptions

### Proposing (ProposingState)

The initial state when a channel is being proposed. The customer scans a merchant's QR code and initiates channel creation.

**Events:**
- `ProposalAcceptedByMerchant` - Customer receives acceptance from merchant, transitions to Establishing
- `MerchantAcceptedProposal` - Merchant accepts customer's proposal, transitions to Establishing
- `RejectProposal` - Proposal rejected, transition to Closed
- `Timeout` - Negotiation timeout, transition to Closed

**Protocol Traits:**
- `ProposeProtocolCommon` - Common proposal operations
- `ProposeProtocolProposer` - Merchant-side operations
- `ProposeProtocolProposee` - Customer-side operations

### Establishing (EstablishingState&lt;C&gt;)

The state where both parties set up the 2-of-2 multisig wallet, exchange keys, generate ZK proofs, and establish the KES (Key Encryption Server).

**Requirements for transition to Open:**
1. Multisig wallet created
2. KES client initialized
3. KES proof received
4. Funding transaction confirmed

**Events:**
- `MultiSigWalletCreated` - Wallet keys exchanged
- `KesClientInitialized` - KES client set up
- `KesShards` - Secret shards exchanged
- `KesCreated` - KES proof received
- `FundingTxConfirmed` - Funding transaction on-chain
- `MyProof0Generated` / `PeerProof0Received` - Initial ZK proofs

**Protocol Traits:**
- `EstablishProtocolCommon<C, D>` - Common establishment operations
- `EstablishProtocolMerchant<C, D>` - Merchant-specific operations
- `EstablishProtocolCustomer<C, D>` - Customer-specific operations (reads wallet commitment)
- `PeerInfo<C>` - Access to peer's DLEQ proof and adapted signature

### Open (EstablishedChannelState)

The active channel state where payments can be made. Each payment updates the channel state with new balances and exchanged ZK proofs.

**Events:**
- `ChannelUpdate` - Process a payment update
- `CloseChannel` - Initiate cooperative close
- `OnForceClose` - Initiate dispute (unilateral close)

**Protocol Traits:**
- `UpdateProtocolCommon<C>` - VCOF-based witness derivation
- `UpdateProtocolProposer<C>` - Proposer-side update operations
- `UpdateProtocolProposee<C>` - Proposee-side update verification

### Closing (ClosingChannelState)

The cooperative close state where both parties agree to close the channel and exchange witnesses to create the final transaction.

**Events:**
- `FinalTxConfirmed` - Final transaction confirmed on-chain

**Protocol Traits:**
- `CloseProtocolCommon` - Common close operations
- `CloseProtocolInitiator` - Party that initiated the close
- `CloseProtocolResponder` - Party that responds to close request

### Disputing (DisputingChannelState)

The dispute state when one party forces a close without cooperation. A dispute window allows the other party to submit a more recent state.

**Dispute Reasons:**
- `UnresponsivePeer` - Peer stopped responding
- `InvalidUpdate` - Peer submitted invalid update
- `FraudAttempt` - Peer attempted to cheat
- `Timeout` - Protocol timeout

**Events:**
- `OnDisputeResolved` - Dispute resolved (by KES or timeout)

**Protocol Traits:**
- `ForceCloseProtocolCommon` - Common dispute operations
- `ForceCloseProtocolClaimant` - Party claiming funds
- `ForceCloseProtocolDefendant` - Party defending against claim

### Closed (ClosedChannelState)

The terminal state. The channel is complete and can no longer be used.

**Close Reasons:**
- `Normal` - Cooperative close completed
- `Timeout` - Channel expired
- `ForceClosed` - Unilateral close completed
- `Disputed` - Dispute resolved
- `Rejected` - Proposal was rejected

## Role-Specific Behavior

Each state has role-specific protocol trait implementations:

| State | Merchant Role | Customer Role |
|-------|--------------|---------------|
| Proposing | `ProposeProtocolProposer` | `ProposeProtocolProposee` |
| Establishing | `EstablishProtocolMerchant` | `EstablishProtocolCustomer` |
| Open | `UpdateProtocolProposer` (proposer) | `UpdateProtocolProposee` (proposee) |
| Closing | Initiator or Responder (depends on who closes) | Initiator or Responder |
| Disputing | Claimant or Defendant (depends on dispute) | Claimant or Defendant |

## Generic Type Parameters

- `C: FrostCurve` - The FROST-compatible elliptic curve (default: BabyJubJub)
- `D: SecureDigest` - The cryptographic digest (default: Blake2b512)
