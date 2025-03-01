# Grease Architecture

_This document is currently still in planning / conceptual phase and is subject to extreme revision._

## Systems

* [ ] Monero Blockchain
  * Intention to use existing monero RPC client interacting with `monerod`.
* [ ] Z-K Blockchain
  * Likely Aztec / Noir for PoC, but there can be support for multiple implementations.  
* [ ] Key Escrow Service (KES)
* [ ] Grease Client
  * Rust-based CLI application
* [ ] Grease Server
  * Rust-based CLI application
* [ ] Grease Middleware
  * [ ] Payment channel state machine
  * [ ] Z-K proofs. Noir?
* [ ] Grease P2P
  * Rust. Built on `libp2p` and `tokio`.

## Users

Public peer, sometimes referred to as the merchant.
Private peer, sometimes referred to as the client.

## Apriori Assets

### Public peer

* 0 XMR (None needed, so no running balance)
* ~X~ ZKL2 gas
* ~Y~ KES gas
* Grease Server

### Private peer

* 1 XMR
* Grease Client

## Synthetic Assets

### Public peer

`Tab` key

### Private peer

`Tab` key

## UX Steps

1. Negotiate
2. Purchase
3. Close
4. Dispute

Not covered:
5. Re-open/re-allocate amount

# Walkthrough

1. Negotiate
   1. Private walk's into Public's store and asks for service
   2. Public uses Grease Server and presses `New Customer Tab` button, with `Tab amount: 1 XMR` default
   3. Public asks Private to scan the QR code on Grease Server screen to establish a tab
   4. Private uses Grease Client to scan QR code, deciding on `Tab amount` and accepting
   5. Grease Client uses Grease Network to negotiate with Grease Server to establish tab
      1. Private uses:
            1 XMR in refundable lock (minus XMR fee)
      2. Public uses:
            ~X~ ZKL2 gas
   6. Grease Server use KES to start key escrow
      1. Public uses: ~X~ KES gas
   7. Grease Client and Grease Server use KES to store Private and Public `Tab` key, respectively
   8. Grease Client and Grease Server use KES to verify storage of other's `Tab` key
   9. Grease Client and Grease Server show success code to Private and Public, respectively
2. Purchase
   1. Private requests purchase for 0.5 XMR
   2. Public uses Grease Server and creates bill
   3. Grease Server uses Grease Network to negotiate with Grease Client to update tab
   4. Private uses Grease Client to approve update
   5. Grease Client uses Grease Network to negotiate with Grease Server to approve update tab
      1. `Tab amount` is 0.5 XMR to 0.5 XMR Private/Public
   6. Grease Server show success code to Public
   7. Public provides purchase (on trust)
3. Close
   1. Private uses Grease Client to close tab (perhaps at the request of Public)
   2. Grease Client uses Grease Network to negotiate with Grease Server to close tab
   3. Grease Server uses Grease Network to negotiate with Grease Client to close tab
   4. Grease Server notifies Public that tab is closed
   5. Grease Client unlocks 0.5 XMR to Private
   6. Grease Server unlocks 0.5 XMR to Public
   7. Grease Server use KES to end key escrow
      1. Public recovers:
            ~X~ KES gas
4. Dispute
   1. Public asks Private to close tab
   2. Private **DASHES FROM THE STORE!!!!**
   3. Grease Server uses Grease Network to dispute the non-closure
   4. Grease Network publishes dispute
      1. Public uses:
        ~X~ ZKL2 gas
   5. Grease Server notifies Public of status of dispute
   6. Grease Network concludes timer
   7. Grease Server uses KES to process dispute
      1. Public uses:
            ~X~ KES gas
   8. KES negotiates with Grease Server to release Private's `Tab` key
   9. Grease Server uses Private's `Tab` key to reconstruct the entire channel, resulting in ability to perform close
   10. Grease Server uses all information to close tab
   11. Grease Server notifies Public that tab is closed
   12. Grease Server unlocks 0.5 XMR to Public and 0.5 XMR to Private
   13. Eventually, Grease Client notifies Private that tab is closed
   14. Or, Private eventually realizes that 0.5 XMR are now available on Private's original Monero wallet
