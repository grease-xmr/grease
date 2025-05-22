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

Both merchant and customer use the same command line interface (CLI) to interact with the Grease network.
First, you need to create an identity that identifies you on the P2P network. 

Then, you can run the CLI tool to interact with peers.

## Create an identity

```text
$ grease-cli id create Alice

Identity created: Alice:12D3KooWPCPfYeoV7zePmR6PNGNriVuScUKwhQTpqAig5itMF67Y
Saving identities to ~/.grease/config.yml
Bye :)
```

## Tweaking the config

The CLI saves the identity to `~/.grease/config.yml`. You can edit this file to change the default port and other settings.

```yml
# Location of identities file, if you want to maintain multiple identities
identities_file: /home/user/.grease/identities.yml
preferred_identity: Alice
# The URL that the grease server must listen on
server_address: /ip4/127.0.0.1/tcp/40012
# The public key of the KES that this identity wants to use
kes_public_key: 61772c23631fa02db2fbe47515dda43fc28a471ee47719930e388d2ba5275016
# An arbitrary label use to derive Channel IDs. Make this unique to yourself
user_label: test_customer
# You root secret key. Do not share this with anyone. This is used to derive the channel keys, and spend keys for 
  multisig wallets.
initial_secret: c4a........0c
# The path to the directory where the channel states are saved.
channel_storage_directory: customer_channels
```

### Run the server

The **grease-cli** application is used to run the server and interact with payment channels.

```text
Grease Monero Payment Channels.

Payment channel management and command-line client for grease.

Usage: grease-cli [OPTIONS] <COMMAND>

Commands:
  id       Add, list or delete local peer identities
  keypair  Print a random keypair and quit. The secret key can be used in the `initial_secret` field of the config file
  serve    Run the server
  help     Print this message or the help of the given subcommand(s)

Options:
  -c, --config-file <CONFIG_FILE>
          Path to the configuration file. The default is `$HOME/.grease/config.yml`

      --id <ID_NAME>
          P2P identity to use. If omitted, the first record in the identity database is used

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version
```

Generally, you can fire up grease CLI with the following command, which will present the interactive CLI menu.

```bash
$ export RUST_LOG=info # optional
$ grease-cli serve 
```

```console
$ ./target/debug/grease-cli serve
[2025-05-17T12:11:54Z INFO  grease_cli::launch_app] Starting interactive server
[2025-05-17T12:11:54Z INFO  grease_cli::id_management] Loading identities from /home/code/.grease/identities.yml
_____________/\\\_______/\\\__/\\\\____________/\\\\____/\\\\\\\\\___________________________________                 
_____________\///\\\___/\\\/__\/\\\\\\________/\\\\\\__/\\\///////\\\_________________________________                
________________\///\\\\\\/____\/\\\//\\\____/\\\//\\\_\/\\\_____\/\\\_________________________________              
___________________\//\\\\______\/\\\\///\\\/\\\/_\/\\\_\/\\\\\\\\\\\/__________________________________              
_____________________\/\\\\______\/\\\__\///\\\/___\/\\\_\/\\\//////\\\__________________________________             
______________________/\\\\\\_____\/\\\____\///_____\/\\\_\/\\\____\//\\\_________________________________            
_____________________/\\\////\\\___\/\\\_____________\/\\\_\/\\\_____\//\\\________________________________           
____________________/\\\/___\///\\\_\/\\\_____________\/\\\_\/\\\______\//\\\_______________________________          
_____/\\\\\\\\\\\\____/\\\\\\\\\______/\\\\\\\\\\\\\\\_____/\\\\\\\\\________/\\\\\\\\\\\____/\\\\\\\\\\\\\\\_        
 ___/\\\//////////___/\\\///////\\\___\/\\\///////////____/\\\\\\\\\\\\\____/\\\/////////\\\_\/\\\///////////__       
  __/\\\_____________\/\\\_____\/\\\___\/\\\______________/\\\/////////\\\__\//\\\______\///__\/\\\_____________      
   _\/\\\____/\\\\\\\_\/\\\\\\\\\\\/____\/\\\\\\\\\\\_____\/\\\_______\/\\\___\////\\\_________\/\\\\\\\\\\\_____     
    _\/\\\___\/////\\\_\/\\\//////\\\____\/\\\///////______\/\\\\\\\\\\\\\\\______\////\\\______\/\\\///////______    
     _\/\\\_______\/\\\_\/\\\____\//\\\___\/\\\_____________\/\\\/////////\\\_________\////\\\___\/\\\_____________   
       _\/\\\_______\/\\\_\/\\\_____\//\\\__\/\\\_____________\/\\\_______\/\\\__/\\\______\//\\\__\/\\\_____________  
        _\//\\\\\\\\\\\\/__\/\\\______\//\\\_\/\\\\\\\\\\\\\\\_\/\\\_______\/\\\_\///\\\\\\\\\\\/___\/\\\\\\\\\\\\\\\_
         __\////////////____\///________\///__\///////////////__\///________\///____\///////////_____\///////////////__


?
Main                          No active channel                                           Bob@12D3KooWLLFZAuusef2zws9er5e5cTziLd66EKKGiqTa6mZaJr2R    
[Ready] ›  
For Customers
For Merchants
Manage Identities
Exit
```

## Establishing a new channel

The typical flow is that a customer want to open a new channel with a merchant. The merchant then displays a QR code 
with the merchant connection info, including its public key, the initial balance.

* Select `For Merchants | Display new channel QR code` in the menu.
* Enter the initial balances.

```console
Enter customer initial balance: 2
Enter merchant initial balance: 0
Ok.
Channel info:
█▀▀▀▀▀█  █▀▄███ ▀█▀▄▄ ▄█▀▄▄▄ █ ▀█▄▀▄ ▀▄▀▄ ▀  ▄ █▄ ▄▀▀▀█▄▄▀▄ ▄█▀▄▄▄▀▀ ▀▀█▀█ ▄▄█▀█▀ █▀▀▀▀▀█
█ ███ █ █▄▀ ▀▄█ ▀ ▀▀▄▀██▄█ ▀█ █▄▀▄▀ ▄▀█▄▀▀▄▀█▀▄▄▄▀▀▄▀▀▀▄▄ ▄▀ ▄▀  ██▀█▀  █▄█▄█ ▄ ▄ █ ███ █
█ ▀▀▀ █ █ █ ▀▄▄▄▄ ▀█▄ ▀▄█ █ █▀▀▀███ █▀▀█▀▄ ▄▄█▄█  ▄█ ▄█▀▀▀█ ▀▀▄▄█ ▄ ▄▀▀ ▀▄ █ █ █  █ ▀▀▀ █
▀▀▀▀▀▀▀ █ █ █▄█▄▀ ▀▄▀▄█▄▀ ▀ █ ▀ █ ▀ █▄█▄█▄█▄▀▄█▄█▄▀▄█ █ ▀ █ ▀ ▀▄▀▄▀ ▀▄▀ ▀▄█▄▀ ▀▄█ ▀▀▀▀▀▀▀
▀ ████▀▄ ▀█ ▄▄█▀█▀█ ▄█▀ ▄▀█ ▀██▀▀ █ ▀▀ █▄▀█▄ ▄▄▄██ █▀▀██▀▀▀▄▀▀ ▀ ▀█ ▀▄  ▀█ █ ▀▀█▀ █▀███  
 ▀ █ ▄▀▀▀ ██▀▀▀▄▀▀  ▀██▀▀▄▄▄██▀▀ █▀ ▀  █ ██ █▀█ ▀██▄ ▀▄  ▀▀▄ ▄ █▀▄█▄▄▀█ ▄▀▄▀▄▀▄ █▀ ▀▀▄▄█ 
▄▀▀█ ▄▀█▀█▄█▄▀█▀ ▄▄▄▀▀▄▄▀ ▀▄█ ▄█▄█▄▀▀▀ ▄█ █▄█▄ ▀█▄█▀▀█▀█▀▄█▀▄▀▀█▀   ▀ ▀ ▄ ▀█   ▀▀▀ ▀▀▄ ▀█
▄   ▀ ▀ ▄▄▄▀█▀ ██ █   ▀▀▄██   ▀ ▀█▄█▄    ▄▀█  █▄ ▄  ▄ ██▀▄▀▄█ ▀ ▀█▀▄ ▀▀ ▄█▀▀█ ▀█▀▀ ▄▄▀▄██
▀  █  ▀▀▄█▄█▄ ▄▀▀▀▄█ █▀██▀█▀▄█▄█▀ ▀▄█▀ ▀▀██▄█▄ ███ ▀▀▀█ ▀█▀ ▀▀ ▄▀▄▀▄▀▄▄  ▄ ▀▀▄▀▀▀█▄▀█  ▀▄
▄▄█ █▀▀ ██▀▀▄  ▀▀█▄▀█▄  █▄▄█▄▀ ▄▀█ ▄█▀ ▄▀▄  ▀▄ █▀ ▀ ▄▀▀   ▄▄█▀▀▀▀▀▀▀▄▄ ▀▄█▀█▄▄█▀▄▀█▀█▀▀██
  ▄█▄ ▀██▀ █ █ ▀  █ █ ▀ ▄▄▀█▄▀▄▄█▄ ▀▀▀▀█▀▀█▀ ▀▄▀█▄ █▄ ▄█▀▀▄ █▀ ▀█ ▀  █▀██▄▄ ▄█▀ ▄█▄ █▄▀██
▄█▄ █▀▀██ ▄█   ▄ ▀▀█▀ ▀▀██ ▄  ▄██▄█▄▀▄█ ▄▀█▄▄▀ ▄▀ ▀▀▀  ▀▀▀▀ ▄▀▄▀▀▄█  ▄▀▄██  █▀▀▀ ▄▀▄▄▄ ▀▀
▄█ ▀ ▀▀ ▄▀█ ▀ ▄ ▄ ▀█ ▀█▀██▀▄▀ ██▀▄▄▄█ █▀ ▀█ ▄ █ ▀▀ ▀█ ▀▄▄▀  ▄ ▄▀ ██▀ ▄▄█▄▀▀▀  ▀█▄   ▄ ▀█ 
▀  ██ ▀ ▄▀█▀▀█  █▄▀▄ ▄▀ ▀ ▀█▀▀█▄  ▄▀ ▀ ▀▄▀▀  ▄  █▀▄▄▄▄▀ ▀█▄▄█▄▄█▄▀  ▄▄▄██▀▀▀▄█▀▄▀█▀ █   ▄
▄▀  █▀▀▀█▄  ▄▀█ ▄▄█▄▄█▄   ▄ █▀▀▀█▄ ██ ▀▀  ▄▀█▀▀█▄ ▄  ▀█▀▀▀███▀  ▄ ██▄▄▄▄▄ ██▀ ███▀▀▀█  ▀ 
█▀███ ▀ ██ ▀▄▀  ███ ▄ ▀█ █ ▀█ ▀ ██▀▄ ▀▄█▄ ▄▀█████▀ ▀▄ █ ▀ █ ▄▀    █▄▀▀▄▄▄▀██ █▀ █ ▀ █▄█▄▀
▀ ▄██▀▀████▀▄ ▀▄ ▄ █▀▄▀▄▄▀▀▄████▀▀ ▀█ ▀█▄ █  █ ▄▄ ▄█▄ ▀█▀██ █  █▄█▀█    ▄ ▄▀▀▀▄ ██▀▀█▄▀▄█
 ▀██  ▀ ▄ █ █ ▀▄█▄▀█▄███▀ ▄▀█▄ ▀██▀ █▄▀   ▀▀▄▄▀▄▄▀ ▄▄▄▀▀  ▀▀█▀▀ █▀▀█▀▄▄▄  ▄█ █▄▀▄▄▄ ▄▄ █ 
 ▄█▀▄█▀ ▀█  █▀▄▀█▀█▄█▀▀▄  ██▄█ ▄▀▀ █▄█▄ ▀▀ █▄ ▀▄█ █▄ ▄▀▀ ▀▄▄▄▄▄██▀██ █▄▄█ ▀▄▄▄ ▄▄ ▄ ████ 
▄▄ ▄▄█▀ ▄▀██▀▀  █▀▄▀  ▀█▄▀▀▄▄█▀▄███▀▄▄ ▀ ▀▀▀█▄▀ ▀▀█▀ ▄▀▄▀█ █▀█ █▀▀▄█▀  ▀▄▀ █▄▄▀▀▄▀  ▀ ▄██
█ ▄ ▄█▀▄▄▀▀ ▄ ▄▄▄ ▄▄▀ ▀█▀ ▄ ▀█▄▄ █▀ █▀██▄▀ █     ▄▄▀  ▀██▄█ ▄▄▄ ▀▀█▄ █  ▄ ▀  ▄▀█▄  ███ █ 
▄ ▀██ ▀  ▀ ▄▄█▀▄▄█ ▀▄▀▀▀▀   █▄▄▄▄█▀▄ ▄█▄   ▀▄▀███  █▄▄▄▀█▄▀▄▀▄▄▀▄█▄██▀▄▄ ▀▀█▀ ▀▀▀█  ▀  █ 
▀ ▀▄  ▀▀▀ ▀▀▄▄  ▀    █▀ ▀█▀▀███▄ ▀  █  █ ▀█▀▄▀█ ▀▄   ▄▀▀ █ ▄█▀▄█▄█▄ ▀█   ▄▄▀  ▀█▄█ ▄▄  ▀▄
▀ ▀███▀▀▀█▄ █▄▀ ▀   ▄ ▄█ ▄▀▀▄▄▄██▄██  █▀  ▄  █▄ ▀  ▄█▀█▀ ▀  ▄ ▄▄█▄▄ ▀█▀▄    ▀█▄█▀█   █   
██  ▀ ▀▄▀▄ ▀▄▄▀█▄▀     ▀███▀  █  █▄▄█ ▀▀ ▀█▀   ▄▀▄▀█ ▄  ▀█▄ ▄█  ▄  ▀▀▄▀  ▄▄ █  ▀▄█ ▄▄▀███
▄▀█▄▀ ▀▄▄ ▀ ▄▀ ▀█▄ █  ▀▀ ▄█▄▄▀█▀  ▄▄▀▀ ▀ █▀  ▀▀ ▄▄▀█▄  ▄▄█ ▄ ▀▄▄▀▀▄▄▄ ▀ █▄ ▀▀██   ▀▄▀▀▄▀▄
▀█▄ ▄█▀▄▄█▀▄▀█▀█ ▄▀ ▀▄▄▀██▀▀▄█▄▀██▀ ▄▀██ ██▀ ▀█ █ ▀▀▄▄ ▀ ▀ ▄█▄   ▀▀ ▄▄▄▀▄ ▄▄▄██  ██▀█▀▀▀▀
█▄▄▄█▀▀▀█▄▀ ███ ▄▀▄▀ ▀█▄ ▄▀▄█▀▀▀█ ▀ █ ▀▄▄▀█▄▀█▀▄█▀ ▀▄▀█▀▀▀█▄▀▄█▀▀█▄▄▄▄ ▀▀ ▄▄ ▀ ██▀▀▀█ █ ▀
██ ██ ▀ ██▄▄▀▀▀▄▀█▄ ▄██▄ ▄▄▄█ ▀ █▄██▀▀ █▄ ▀▄█▄█▀▀▄▀▀ ▄█ ▀ █ █   █▄▀▄▄▄  ██ ▄▀ ▄ █ ▀ █▀██▄
 ▄▀▀██▀█▀▄▄▀  ▄█▄▄█▀█▀  ▄▀▄█▀▀▀████▄ ▀ █▄ █▄█   █ ▀█▄▀█▀▀██▀█ ▀▀▀▀▀▀▄ ▄▀▀ ▄▀ ▀▄█▀████▀▄█ 
 █▄▄▀▄▀█▀▄▀▀▄██▀▄▀▄▀▄██▄▄ ▄█▄▄▀█ █▀██ ▄█▄ █▄ ▄▄▀ ▄▀█▀▄    ▄▀█▄ ▀▄ ██▄▄█▄▀▄ ▀▄▀▀▄▄▄▄▀ ▀ ▀ 
 █▀█▄▄▀ ▄▀█ ▄█  ▀▀ ▄█ █▄██▄███▄▀█ ▀ █▀  █ ██▄▄▀▀  ▀█▄  ▄▀▄▀▄▀▀ █▀▀▀█▄▄▀█▄▄▄▀▀▀▄▄█▀ ▀ ▄▀█▄
▄▄▀██▀▀▄█▀▄▄▄▄▀▀▄▄▄▄ ▄ ▀▀█▄ ▀▄▄▀▄▄ ▄▄▄    █▄██▄█▀▀ ▄▀▄   ▄█▄    █▄▄ ▄█▄▀▀  █▄▄ ▀▄▀ ▀█ █▀▄
 ▀▄▄██▀████ ▀▄█▄▀ ▄▄ ▄▀▄█ ▄█  ▄█▄█▀ ▄▀▀▄▄▄▄▀▄█▀▄▀█ ▀█▄▀▀▀██▄   ▄▀█████▄▀▄█▀▀▄▀█▄▄▀  ▄▀▄▀▀
█▄█▄█ ▀▄  █▄ ▄ ▀▄██▄█▄█▄█▄▄  ▀ ▀  ▀▀ █ ▀▀██▄▄▄ █▀█ ▀ ▄▀▀█▄█ ▀▀▄▀▀▀█▄ ▄  ▄▄ █▀ ▀ ▀▀█▀ ▀▀▀█
 ▄▄▀▀ ▀██▀▄▄▀▀▄▄▀  █▄█▄ ▀▀▄ █ ██▄▄ █▄██▀█▀▄▄▄ ▄ █▀▀█▄ ▀█▀█▄ ██▀ ▀█▀▀ ▄▀▄▄  █ █   ▀▀ ▄▀▀██
▀█  ▄█▀ ▄ ▄ ▄▀ █ ▀ ▄█▄▀▄█ ▀  ▄▀▄█▄█▀█▀ ██ ███▄▄▄█ ▀█▀██ ▀█▄ █▀ ██ █▀ ████▄▄▀ ▄▀▄▄▀▄ ▀ ▄█▀
▀▄ █▀▀▀ ▄ █▀▀▀  ▀ ▄ ▄▀ ▀▄▄ ▀▀▄ ▀███ ▄▄▀▀▄█▀ ▄█  ▀▀ ▀▀▄█▄ ▄  ▄█ ▀  █▀▀▄▀█ ▀▄  ▄▀▄█ ▀▀▀█ ▀█
█ █▀██▀███▀▀█  ▄█▄█  ▀▄ █ ▄      ▄█ █ ▀▀█▄   █ ▀█▀▀█ █ ▀█▄  ▄█▀████▀▀▀▄ ▄▀▄█▄ ▀█▀▀▄ █ ▀▀█
█▄ ▀▄▄▀▀  ▀█▄█ ▀█   ▄▀█▄ ▀▀█▄▄ █▄█  ▀▀▄▀▀ ██ ▀ ▀█ ▄▀▀▄ ▄▀█▄██ ▀█▀▀▀▀█▀ ██▀▀ ▄▀▀▄▀▀  █  █▀
▀  ▀  ▀▀▄▄▄▀▄▀▀▄  ██ ▄▀██▄▄▀█▀▀▀██▀▀▀ ▀▀  ▄▄ ▀▀▄█▀ ▀ ▄█▀▀▀█▄▄▀ █▀ █▀▄ ▄▄▄▀▄█▄▀▀██▀▀▀█  ▄▄
█▀▀▀▀▀█ ▄▄▄█▀▄▄▀ ▀▀▀ ▀  ▄▄▀▀█ ▀ █▄  █▀ ██▀█▄▄▀███ █▀███ ▀ █▀▄ ▀▀▄██ ▀█ ▄▄█▀▄▄▄▀██ ▀ ████ 
█ ███ █ █ ██▀█▄██ █▄█▄▄  ▀▀▄▀██▀▀█▀ █  █▄ █▀▄ ▄▄▄▀▀█▄▄▀██▀▀ █▀▄██▀█  ▀▄ ▄█▀▄▀▀▄▄▀█▀▀█ ██ 
█ ▀▀▀ █ ▀ ▄▄▀▄▀▄▀█▀▀ ▀▄▀█▄ ▄█ █▄▀█ ▄▀▄█  ▀▀▀█ ▀▄▄██ ▄ █▀▀█▀███▄▀▄█▄█▀▄ ▄▄ ▀▀▄▀▄▀▀▄  █▀▀█ 
▀▀▀▀▀▀▀ ▀  ▀ ▀       ▀   ▀▀▀▀ ▀▀▀  ▀▀▀ ▀ ▀▀▀ ▀          ▀ ▀▀   ▀▀  ▀▀▀  ▀▀  ▀  ▀▀▀▀▀▀ ▀  
{"contact":{
  "name":"Bob","peer_id":"0024080112209c3cd0da14edbce70c1d19c660b2835750a0931794a08676ddf03c7b655a886e",
  "address":"/ip4/127.0.0.1/tcp/23001/p2p/12D3KooWLLFZAuusef2zws9er5e5cTziLd66EKKGiqTa6mZaJr2R"},
  "seed":{"role":"Customer","pubkey":"79b7bd48d037eb90f45a9b005b15767cfbf9b2fd3b33872216201a29ad771b47",
  "key_id":11357053259213804631,"kes_public_key":"61772c23631fa02db2fbe47515dda43fc28a471ee47719930e388d2ba5275016",
  "initial_balances":{"merchant":0,"customer":2000000000000},"user_label":"test_merchant-11357053259213804631"}
}
```
## Client imports the Channel initialization info.

Mobile clients will typically scan the QR code. In Grease CLI, you copy the JSON object and paste it at the prompt 
after selecting `For Customers | Initiate new channel`

This will kick off the channel negotiation procedure. This includes:
* Creating an authenticated connection between the customer and merchant.
* The establishment of a new 2-of-2 multisig Monero wallet.
* The establishment as validation of a new Key Escrow service.
* The sharing of encrypted keys and channel state information.
* Watching for confirmation of the funding transaction on the Monero blockchain.

If you have set the `RUST_LOG` environment variable to `info`, you will see the channel negotiation process in the logs.

```console
[2025-05-17T12:28:56Z INFO  grease_p2p::event_loop] Connection to 12D3KooWLLFZAuusef2zws9er5e5cTziLd66EKKGiqTa6mZaJr2R established as dialer in 0.010s. Connection id: 1. 1 connections are active.
[2025-05-17T12:28:56Z INFO  grease_p2p::event_loop] New channel proposal sent to 12D3KooWLLFZAuusef2zws9er5e5cTziLd66EKKGiqTa6mZaJr2R
[2025-05-17T12:28:56Z INFO  grease_p2p::event_loop] Sent identify info to PeerId("12D3KooWLLFZAuusef2zws9er5e5cTziLd66EKKGiqTa6mZaJr2R")
[2025-05-17T12:28:56Z INFO  grease_p2p::event_loop] Received identify info from PeerId("12D3KooWLLFZAuusef2zws9er5e5cTziLd66EKKGiqTa6mZaJr2R"): Info { public_key: PublicKey { publickey: Ed25519(PublicKey(compressed): 9c3cd0da14edbce7c1d19c660b2835750a0931794a08676ddf03c7b655a886e) }, protocol_version: "/grease-channel/id/1", agent_version: "rust-libp2p/0.46.0", listen_addrs: [/ip4/127.0.0.1/tcp/23001], protocols: ["/grease-channel/comms/1", "/ipfs/id/1.0.0", "/ipfs/id/push/1.0.0"], observed_addr: /ip4/127.0.0.1/tcp/23002 }
[2025-05-17T12:28:56Z INFO  grease_p2p::server] 🥂 Channel proposal accepted.
[2025-05-17T12:28:56Z INFO  grease_cli::interactive] Channels saved.
Ok.
New channel created: XGC0299fa31831dcdeabbd3a55e0f67298c
```

## Sending funds

To do

## Closing a channel

To do

## Force-closing a channel

To do

## Disputing a channel closure
