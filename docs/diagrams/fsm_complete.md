# Grease Payment Channel FSM

This document describes the finite state machine (FSM) for a Grease payment channel: its states, the transitions between them, and each
party's responsibilities in every state. It complements the lifecycle overview in `10_channel_design` and the arbiter design in `40_arbiter`.

## State Machine Diagram

```mermaid
stateDiagram-v2
    [*] --> Proposing: Create channel

    state Proposing {
        note right of Proposing
            <b>Responsibilities:</b>
            - Exchange seed, proposal, confirmation
            - Agree channel parameters and the arbiter
            - Derive the provisional channel id
        end note
    }

    Proposing --> Establishing: ProposalAccepted
    Proposing --> Closed: RejectProposal / Timeout

    state Establishing {
        note right of Establishing
            <b>Responsibilities:</b>
            - Create the 2-of-2 multisig wallet
            - Declare each party's funding output
            - Finalize the channel id (commits to L_F)
            - Pre-sign the state-0 exits and the initial
              state: adapter signature, verifiably
              encrypted offset and binding proof
            - Broadcast and confirm the funding outputs
        end note
    }

    Establishing --> Open: funding_confirmed()
    Establishing --> Closed: timeout / abort

    state Open {
        note right of Open
            <b>Responsibilities:</b>
            - Per update: fresh offset, adapter sign,
              verifiably encrypted offset, binding proof,
              cross-signed update record
            - Watch the arbiter log for disputes
        end note
    }

    Open --> Closing: cooperative_close()
    Open --> Disputing: unilateral_close()

    state Closing {
        note right of Closing
            <b>Responsibilities:</b>
            - Exchange the latest offsets
            - Complete and broadcast the closing tx
        end note
    }

    Closing --> Closed: final_tx_confirmed()

    state Disputing {
        note right of Disputing
            <b>Responsibilities:</b>
            - Present latest record to the arbiter
            - Answer a stale record with a newer one
            - On attestation, decrypt offset and close
        end note
    }

    Disputing --> Closed: dispute_resolved()

    state Closed {
        note right of Closed
            <b>Reasons:</b> Normal, Timeout,
            UnilateralClose, Disputed, Rejected
        end note
    }

    Closed --> [*]
```

## State descriptions

### Proposing

The initial state, entered when a customer takes a merchant's out-of-band seed and sends a channel proposal. The parties agree the channel
parameters — initial balances, public keys, closing addresses, dispute-window duration, and the arbiter to be used — and derive the
provisional channel id from that metadata.

**Events:** `ProposalAccepted`, `RejectProposal`, `Timeout`

### Establishing

The parties create the 2-of-2 multisig wallet, each funding party declares the output it will contribute, and the channel id is finalized
against those outputs (it commits to their linking tags `L_F`). Only then is the initial channel state exchanged, and it is built exactly
like a later update: each party adapter-signs the counterparty's closing transaction with a fresh secret offset and hands over a *verifiably
encrypted offset* together with a binding proof. No zero-knowledge circuit is involved, and the arbiter is not contacted — it holds no state
for the channel until a dispute is opened.

All of this happens *before* any funding transaction is broadcast. State 0 is one exit transaction per funding output, each returning that
output to the party that contributed it, so once the initial state is signed every funder holds a way out that does not depend on the
counterparty. The funding parties broadcast last.

**Requirements for transition to Open:**
1. Multisig wallet created
2. Every funding output declared and verified against the declaring party's committed balance
3. Channel id finalized (commits to `L_F`)
4. Initial verifiably encrypted offsets and binding proofs exchanged and verified
5. Every declared funding output confirmed on chain as declared

**Events:** `MultisigWalletCreated`, `FundingOutputsDeclared`, `ChannelIdFinalized`, `InitialStateExchanged`, `FundingTxConfirmed`

### Open

The active state. Any number of updates may occur, and the channel can remain here indefinitely. At each update, both parties agree a new
balance, jointly build a new partially-signed closing transaction, and each hands the other a fresh offset sealed as a verifiably encrypted
offset with a binding proof, then cross-sign an update record. While open, each party also watches the arbiter's log for any dispute opened
on the channel (a duty it may delegate to a watchtower).

**Events:** `ChannelUpdate`, `CooperativeClose`, `UnilateralClose`

### Closing

The cooperative-close state. Each party sends its latest offset to the other; either can then complete and broadcast the single closing
transaction, though by convention the merchant does so. The arbiter is not involved.

**Events:** `ChannelCloseSigned`, `FinalTxBroadcast`, `FinalTxConfirmed`

### Disputing

Entered when a party closes unilaterally, or a counterparty goes silent. The disputing party presents its latest cross-signed record to the
arbiter, which opens an adjudication window. Either party may answer a stale record with a newer one; the arbiter advances its high-water
mark and, at the window's close, attests the statement for the highest update count it saw. That attestation unseals exactly the offset that
closes at the true latest state. A stale record is never attested, so a stale close can never complete. The arbiter's own state machine is
described in `40_arbiter`.

**Events:** `RecordPresented`, `WindowElapsed`, `DisputeResolved`

### Closed

The terminal state, reached after a cooperative close, a resolved dispute, or an error/timeout during proposal or establishment. The arbiter
keeps no per-channel state outside an open dispute, so there is nothing to clean up.

**Close reasons:** `Normal`, `Timeout`, `UnilateralClose`, `Disputed`, `Rejected`

> Once a channel is closed, neither party should reuse the 2-of-2 multisig wallet: the counterparty holds everything needed to spend from it.

## Role-specific behavior

| State | Merchant | Customer |
|-------|----------|----------|
| Proposing | Proposer (shares seed, accepts) | Proposee (builds proposal) |
| Establishing | Multisig + initial-state exchange, funds the wallet if it takes a balance | Multisig + initial-state exchange, funds the wallet |
| Open | Update proposer (by convention) | Update proposee |
| Closing | Initiator or responder | Initiator or responder |
| Disputing | Claimant or defendant | Claimant or defendant |

## Cryptographic primitives

- **Funding wallet and closing signatures:** Monero (Ed25519), 2-of-2 FROST multisig, producing the FCMP++ spend-authorization-and-linkability
  (SAL) proof at close.
- **Adapter signatures and offsets:** Ed25519 scalars; the per-state offset `ω` is fresh and independent (offsets do not chain).
- **Verifiably encrypted offset:** identity-based encryption of `ω` against the arbiter's stable BLS12-381 threshold key, addressed to the
  statement "this is the channel's latest state", carried with a binding proof that ties it to the state's adapter point.

