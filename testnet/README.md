# How to run a local testnet

These instructions will help you set up a local Monero testnet environment using `monerod` and `monero-wallet-cli`.
It runs in "regtest" mode, which is a special mode for testing purposes, and which (somewhat confusingly) 
uses _`Mainnet`_ as the network type - and so all configuration files will need to point to mainnet.

The configuration is as follows:
1. A single Monero node running in regtest mode, which both wallets and grease servers will talk to.
2. Alice, who plays the role of Customer. 
3. Bob, who plays the role of Merchant.

The scripts will create a tmux session with one node, and a wallet each for Alice and Bob.

## Linux instructions

### Pre-requisites

You will the following installed:
* [tmux](https://github.com/tmux/tmux/wiki)
* monerod
* monero-wallet-cli
* grease-cli 

We'll assume that all the binaries are in your `PATH`. If not, you will have to tweak the scripts in this folder to 
point them to the correct locations.

### Create the wallets

Run `localnet.sh` to create the wallets for Alice and Bob. 

This will 
* Start a new tmux session called `LocalNet` and run `monerod` in it.
* use `grease-cli` to generate new spend keys for Alice and Bob. It will save these keys in `alice-spend-key.txt` 
and `bob-spend-key.txt`.
  DO NOT USE THESE KEYS FOR REAL MAINNET TRANSACTIONS!
* create a new wallet for Alice.
  * Paste the private key in at the command prompt when asked.
  * You can leave the wallet pasword empty.
  * Confirm the empty password.
  * Select 1 for English.
  * Say "N" when asked to background mine.
  * type `exit` to exist the wallet.
* Repeat the same steps for Bob's wallet.

If all goes well, you should have a tmux session called `LocalNet` running with `monerod` and two wallets created for Alice and Bob.

You can then run `grease-cli` in a separate terminal to create and play with payment channels.