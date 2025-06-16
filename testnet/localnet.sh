#!/bin/bash
# This creates a localnet (RegTest). It assumes your data and configuration files are in ~/testnet.
# Have a bug fix or improvements to this script? Submit a PR!

# tmux session name
SN=LocalNet
PWD=$(pwd)
tmux kill-session -t $SN

# nodes window

# start node_01 (initial session)
echo Starting Node
tmux new-session -d -s $SN -n nodes -- sh -ic "monerod --config-file $PWD/localnet.conf"
sleep 2

# Each session starts from scratch, so delete the old wallets and recreate them
rm alice-local.bin.*
rm bob-local.bin.*
echo "Creating wallets for Alice and Bob..."
./create-wallets.sh

echo "Wallets created successfully. Starting the tmux session for wallets..."
sleep 2


# start wallet_01 (first pane in new window)
tmux new-window -t $SN -n CustomerWallet -c $PWD -- sh -ic "monero-wallet-cli --config-file $PWD/alice-local.conf"
tmux new-window -t $SN -n MerchantWallet -c $PWD -- sh -ic "monero-wallet-cli --config-file $PWD/bob-local.conf"

# open tmux for this session
tmux a -t $SN
