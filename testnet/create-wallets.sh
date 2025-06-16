#!/bin/bash

# Create a new wallet for Alice and Bob.

GREASE=grease-cli
MONEROD=localhost:25070

create_wallet() {
    local name=$1
    local config_file="${name}-local.conf"
    local wallet_file="${name}-local.bin"

    # if the wallet file exists, quit
    if [ -f "$wallet_file" ]; then
        echo "Wallet file $wallet_file already exists. Exiting."
        exit 1
    fi
    echo "Creating wallet for $name..."
    grease-cli keypair > "$name-spend-key.txt"

    echo PASTE THE FOLLOWING SPEND KEY AT THE PROMPT WHEN ASKED
    cat "$name-spend-key.txt"

    monero-wallet-cli --generate-from-spend-key alice-local.bin --daemon-address=$MONEROD

    echo "Wallet for $name created successfully."
    echo ""
    echo ""
}

create_wallet alice
create_wallet bob