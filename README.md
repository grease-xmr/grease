**A word of warning:**  
_This project is being developed in public. The documents, code, design specifications, ideas and discussions in
this repository are a reflection of this process and are all subject to change. The end-goal is to result in something
that can be implemented in production, but as of now, consider this a proof-of-concept only._

# Grease

> This car is automatic\
    It's systematic\
    It's hydromatic\
    Why, it's greased lightning!

-- Greased Lightning, _Grease_ (1978)

* For a brief motivation for Grease, read the [introduction](./docs/introduction.md).
* You can find a more detailed description of how Grease works in the [architecture document](./docs/architecture.md).

# Using the Grease CLI

## Installation

## Setting up as a Merchant

In "merchant mode", the grease p2p client runs as a server, listening for incoming connections from clients.

### Create an identity

```text
$ grease-cli id create Alice

Identity created: Alice:12D3KooWPCPfYeoV7zePmR6PNGNriVuScUKwhQTpqAig5itMF67Y
Saving identities to ~/.grease/config.yml
Bye :)
```

### Run the server

```text
$ export RUST_LOG=info # optional
$ grease-cli --id Alice serve -a /ip4/127.0.0.1/tcp/7440 
```

That's it!

## Setting up as a client
                                                                                                        
In "client mode", the grease-cli application connects to a server, executes the desired command and then disconnects.
In these examples, we specify the server's address and peer id. When grease is in production, the PoS device will 
generate a QR code with this information on it, which the client will scan and use to connect to the server without 
needing provide the address and peer id manually.

Make sure you have created an identity as described [above](#create-an-identity).

## Opening a channel
                                                         
To open a new channel, use the `channel open` command. 
The command requires the server's address and peer id, as well as the amount to be deposited in the channel.

```
$ grease-cli --id Bob channel -s /ip4/127.0.0.1/tcp/7440/p2p/12D3KooWRKF4eA6xyD8WbvZQKnQEqg9xTgsoQmSJfukLkMor6dK8 open 250

[2025-03-03T12:10:35Z INFO  grease_cli] Initiating channel command
[2025-03-03T12:10:35Z INFO  grease_cli] Loading identities from ~/.grease/config.yml
[2025-03-03T12:10:35Z INFO  grease_cli] Dialing remote server
[2025-03-03T12:10:35Z INFO  grease_cli] Remote server connected
Creating new channel with initial balance 250 : 0
[2025-03-03T12:10:35Z INFO  grease_p2p::event_loop] Open channel request sent to 12D3KooWRKF4eA6xyD8WbvZQKnQEqg9xTgsoQmSJfukLkMor6dK8
New channel open: 1. My balance: 250, Their balance: 0
[2025-03-03T12:10:35Z INFO  grease_cli] Command completed.
[2025-03-03T12:10:35Z INFO  grease_p2p::event_loop] Shutting down event loop.
[2025-03-03T12:10:35Z INFO  grease_p2p::event_loop] Connection to 12D3KooWRKF4eA6xyD8WbvZQKnQEqg9xTgsoQmSJfukLkMor6dK8/1 closed. We were dialer to /ip4/127.0.0.1/tcp/7440/p2p/12D3KooWRKF4eA6xyD8WbvZQKnQEqg9xTgsoQmSJfukLkMor6dK8/p2p/12D3KooWRKF4eA6xyD8WbvZQKnQEqg9xTgsoQmSJfukLkMor6dK8. Reason: Connection closed gracefully. 0 connections remain.
[2025-03-03T12:10:35Z INFO  grease_p2p::event_loop] Event loop has shutdown gracefully.
Bye :)
```

## Sending funds

## Closing a channel

### The standard path

### Force-closing a channel

### Disputing a channel closure
