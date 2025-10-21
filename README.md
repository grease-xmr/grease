**A word of warning:**  
_This project is being developed in public. The documents, code, design specifications, ideas and discussions in
this repository are a reflection of this process and are all subject to change. The end-goal is to result in something
that can be implemented in production, but as of now, consider this a proof-of-concept only._

![Grease Logo](assets/logo2.webp)

> This car is automatic\
> It's systematic\
> It's hydromatic\
> Why, it's greased lightning!

-- Greased Lightning, _Grease_ (1978)

* For a brief motivation for Grease, read the [introduction](docs/legacy/introduction.md).
* You can find a more detailed description of how Grease works in the [architecture document](docs/legacy/architecture.md).

# Using the Grease CLI

(You can run Grease in a local testnet. If you need help setting that up, 
follow the [testnet setup instructions](scripts/testnet/README.md).)

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

The CLI saves the identity to `~/.grease/config.yml`. You can edit this file to change the default port and other
settings.

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
          ++++++++++++                      *   .   *           .       *       .       *          .        *
      +++++++++++++++++++                                 .    *     .    *  *      .       *           *
    +++++++++++++++++++++++                   ;;;;;;;;                                              .
   ++++++++++++++++++++++++++              ;&&&&&&&&&&;  ;&&&&&;   ;&&&&&&&&; ;&&&&&&;    ;&&&&&; ;;;;;;;;;
  +++++++++++++++++++++++ ++++            ;&&&&&&&&&&&; ;&&&&&&&&; ;&&&&&&&+  ;&&&&&&;  ;&&&&&&&&;&&&&&&&&;
 +++++  +++++++++++++++   +++++          ;&&&&x;  ;&&&; ;&&&;;;&&&;;&&&;      ;&&&&&&&  ;&&&&;;;; &&&&;;;;;
++++++    ++++++++++++    +++++         ;&&&&&;    ;;;;  &&&; ;&&&;;&&&;;;;   ;&&; &&&; ;&&&&;    &&&&;
++++++      ++++++++      ++++++        ;&&&&;           &&&;;&&&&;;&&&&&&;   x&&; ;&&;  ;&&&&;   &&&&&&&;
++++++   #    ++++    #   ++++++        ;&&&&;  ;&&&&&&&;&&&&&&&;; ;&&&;;.   ;&&&&&&&&;   ;X&&&&; &&&&&&&;
++++++   ##    +    ###   +++++         ;&&&&;  ;&&&&&&&;&&&&&&&;  ;&&&;     ;&&&&&&&&;     ;&&&&;&&&&;     &
++++++   ####     #####   +++++         ;&&&&&: ;;;;&&&; +&&&;&&&; ;&&&&&&&&;&&&&  ;&&&.;&   ;&&&&;&&&;     .
         ###### #######                  ;&&&&;    &&&&; ;&&& ;&&&&;&&&&&&&&;&&&;  ;&&&;&&&+;&&&&&;&&&&&&&&;
         ##############                   ;&&&&&&&&&&&&; ;&&&; ;&&&&&;;     &&&&;  ;&&&;&&&&&&&&&;;&&&&&&&&
   ##########################              ;&&&&&&&&&&;  ;;;;;   ;&&&&&&&;         ;&&&&;;&&&&&&;        .
    #######################                  ;;&&&&;;              ;;X&;;        &  ;;;;;   ;     *   .
       ##################                 .               *     .    .   .      .     *      .  *      *
          ###########                         *  .   *       .    *        *  .         *          .      .

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

Right now, we only allow customers to fund the channel. This restriction will be lifted in the future.

```console
[Ready] · Display new channel QR code
Enter customer initial balance: 1
Ok.
Channel info:
█▀▀▀▀▀█   ▀▀ █▀█▄█▀▀▀▀▄▀▄██▄   ▄▀██▄█▄█▀ ▀▄█▄█  █▄█ ▀▄█▀ █▄ ▄  ▀ ▀▀█▀█▄ ▄█ ▄▀▄▀ █  █▄ █▀▀▀▀▀█
█ ███ █ █  ██▀██▀▄▄▄ ▀▄█   ▀█▄█▄ ▀▀█▄▄ █▄▀   ▄█▄█▄▀▄▄ █ █ ██▄▀▀▀█▄█▄▀ ▄██▀▀  ▄█▀█▀ ▄▀ █ ███ █
█ ▀▀▀ █ █▀ ▀▄ ▀▀▀▀▀█▀▄▄ ▄▄█▀█▀▀▀██▀▀█ █▄▄▀▄██▄ ▄▀ ▄▄▀▀▀██▀▀▀██ █▄▄█▄ ▀▄▄▄  ██▄▄▀ ▄▀█  █ ▀▀▀ █
▀▀▀▀▀▀▀ █ ▀▄▀ ▀ ▀▄█▄▀ █ ▀ █ █ ▀ █ ▀ ▀ █▄▀ █▄▀ ▀▄▀▄▀▄▀ █▄█ ▀ █ ▀ ▀ ▀▄█ ▀ ▀ ▀ █▄█ █▄▀ █ ▀▀▀▀▀▀▀
█▄▀██▀▀▄ ██ ██▄▄█  █ ▄█▀  ▀ ███▀▀▀▄▄ ▀▄▄█▀█▄ ██▄█▄  ▄▄█▀▀█▀▀▀▄▀█▄ ██▄▀ ▄  ██▀█▀█▄█▄▀▀▄▀█▀▀█▄▄
▄███  ▀▀█▀█ ▄  ▀ ▄▄ ▄   ▀ █ █ ▄▀▀███▄▀▀ ▀▀█▀▀▀▄██▄▄   ▄█▀ ▀▀██▄▀▄█▄▀▄▀  ▄▄▄█ ▀█▀▄▀▄▀▄ ▀█ ▀█ █
█ ▄▀  ▀██▄██▀█▀▄▀█▄▄ ▄█▄▄▄ ▄█▀█▄██ ▀▄▀ ▀  █ ▄▄   ▄ ▄▄▀▄ █▀▀▀█ ▀▀ ▄▀▄█▀▄▄█▀█▄▀▄▀▀▀▄▀▀▄▀▀█ █ ▄█
█▀ ▀█▄▀▄▄▀█▄▀ ▀█  ▄█ ▀ █▄▀▀▄ ▀  ▄█▄█ ▀ █▄ █  ▀█▀ ▄ █  █▄ ▄█▀█▀▄█▀██  █  ▄█▀▀▄██▀ ▄██▄▄█▀▀▀▀▄ 
▄█▄▄ ▀▀▀▄▀▄▄▀ █ █ ▄▀▄▄  ▀▀ ▄▀▀▄█▀▄█▀█ ███▀█▄▀█▄ ▀▀█▄█ ▄▀▀█▀▄▄▀▀█▀ ██▄█▄ ▄ ▀█▄▄▀ █▄▄██ ▄██ █▄█
▀▀██▀▄▀▀█▀█ ▀ ▀▀▀▀  █▄█▄▄▄ ▀███ ▀▀  ▄▀▀██ █▀▄█ ████ ▀▀█▄ █ █▄▀██▄ ▀▀ █▄ ▄▄▀▀█▀▀█▄▄▀█▄▄▀▀▀ █▄ 
█▀▄▄▀▄▀ ▄▀█▄█▀█  ▄▄▄▀ ▀▄▄ ▀▄▄ ▄█   █▄  ▀▀██ ▀▄ ▄ █▄▀  ▀▀███▀▄ ▀▄▀▄  ██▄▄▄▄▀▀  ▀▀▄▄▀▀█▀ █▀▄██▀
▄ █▄▀ ▀▄█ ▄▄▄▄▄▄ ▀▀  ▀ ██ █▄   ▀  ▄▄ ▄▄▄▀▀▄▄  ▄ ▄▄▀█   ▀ ▄ ▀▄▄▀ ▄▀█▀ ▄▀▀▄▄ ▄▀ ▀▀▄▄ ▄ ▄█▀▄▀▀▄▀
 ██ ▄ ▀▄ ▀ ▀ █▄ ▄█    ██▄▀ ▀█ ▀█▀▄█ █▀    ▀▄▀▀█▀█▀▄▄▀ ▄▀▀▀▄███▄████  ▄▄▄█ ▄█▀▀ ▄▄█▄▀█▀▄▀█ ▀ ▀
▄ █▀██▀▄▄▄█▄▀ ██  ▄  ▄██▀▀▀▀█▀▄▀█▀██  ▀█▀▀▄▄██  ▀ ████▄▀▀█▄███▀▄▄█▀▀  ▀▄▄█▀▀ █▀█  █▀▀▀▄▀█▀▄  
▄  ▀█▀▀▀██▄▄█ ███ ██ ▄ █ ▄  █▀▀▀██▀    █   ▄▀█▀ █ ▀▀  ▄▀█▀▀▀█ ▄█  ▄▀█▄▄▀▄▀ ▄▄▀▄▀▄  ▀█▀▀▀█ ▀▄ 
▀██▄█ ▀ ██▀▄▀▄▄██▀▀█▄█▀ ██ ▄█ ▀ █▄█▀█▄▄█ █▄ █▄▀██ █▄▀ █▄█ ▀ █▄ ▄  ▄▄▀▀▄█▀▄ ▄ █▄█▀▄▄██ ▀ ██▄ ▀
  ▀▀█▀▀▀▀█▀█▀█▀█▀▄▀▀ ▀██▀ ▀▄▀▀▀▀▀▀▀▀█ █ ▀ ▄▄ █ ▄█▄ ██ ▄ ▀▀█▀▀▀▀ ▄ █▀██▄▄██▀▀▄█▀ ▄█▄█▀████▄▀▀█
▀▄▀  ▄▀ ▀▀ ▄█ ▄██  ▄▄█▄ █▀█   █▀█▀ ██▄▄▄▀█▀█▀█▄ █▄█▄▀▄ ▄█▀ █▀  ▄ ▄▀▄ ▀▄▄▀▄▀▄ █▄ ▀▄ ▀█  ▄ ▄   
███ ▄▄▀ ▀█  ▄ ▄ ▀  ▄█ ▀ █▀  ▀ ▄▄██ ▄█▄▀█ ▄ ▄ ▄ ▀ ▄███   █▄▀███▀ ▄ ▄▀█▄▄▄▀▀▄▄▄█▀▀▄▀██▀▄▀ ▀▄█▄ 
▄  ▀▀▀▀▄█▀  ▄▀  ▀ ▄▄█▀▄▀▄▄█▀▄ ▀▀▄▀▀ █▄▀ ▄██▄   ▀▄  ▄▀▄ ▄▄▀▀▀▀█▀ ▄██ ▀▄ ▀▀▀   █▄█▀ ▄▀█▀▄▄█▄█▄ 
 ▀  █ ▀▀▀▀▄▄▀█  ▀█ ▀▄▄█▀▀███ ▄██▀▀ ▀ ▄█▀▀▄█ ▄█▀  ▀ ▀▄ █▀▄▀ ▀██▀▀ ▄▄  ▄▀█▀ ██▄▄▀█ █ ▀▀▄▄▄ █▄ ▄
▀▀▄▄█▄▀▄▄▀▀▄  ▄▀█   ███▀▄  ▄  ▄  ▄█▀ ▄█   ██ ▀▀▀▀█▄▄▀▄ ▄▀▀▀▄▀▄▀ ▄▀██ █▄▀▀▀▀▄▄▄▄█▀ ▀ ▀▀▄▄█ █ █
 ▄ █  ▀▄   ▄█▀▀██▄▄█▀▄ ▄▀ █▀▀▀ ▄▀▄▀▄▀▄██▄▀▀ ▄█▀▀ █▀█▀▄▄▀▄▄▀ ▀▀█▄▄ ▄▀▀█ ▄█▄▄▀█▄██ ▀█▀█ ▄▀█ █ █
▄█ ▀██▀▄▀ █▀▀▄ ▄█▄▀▄▀█▄▄▀▀██▄▄ ██▀ ▀▀  ▀▄ ▄  ▄▄█▄▄▀ █▄▀▄▄█ ▀█▀▀▀▀▄▄▄▀▀ ██▄▄▀▄▀▄██▀▀   █▄▀██ ▄
 ▀█▀█▀▀ ▄██▀ ▄▄▀ ▄  ▄▀██▄▀   ▀ ▀▄▄  ▀▀ ██▄▄▀██▀▀▀▄█▄▀▀▄ ▄█▀ █ ▄ █ ▀▄██▀▄▀▀ ██ ▀ ▀▄▀██▄▄▄  ▄▀▀
▄▀ ▄▀█▀█▀▀   █ ▀▀ ▄██▄▄▄▄▄█▄ ▄▄▀  ▄▀▀▀ █▀█▀█▀▀▄ ▀ ▀▀▀ ▄ ▄█▀ █▀▄ ▀▄▄▄  █▄█  █  ▀▀  ▀▄▄ █▄█▀▀▀ 
█ ▀ ▄ ▀▀▄▀▄▀ ▄ ▀ ▀█▀█▄▀▀ ▀▀▄█▀▀ █▀▄▀   ▀█▄▀▄ █▄ ▄▀▀▀  █▀ █▄ ▄▄▄▄▄▄  █▄▀▀▀▀▀█▀ ▄▀▀██▀▄ ▀ ▄▀ ▀ 
▄▀▀  █▀▀ ▄  █▀ ▀█▀ ▄█▀█▀▀██▀ ▄▄█ █▄▀▄ ▀▀█    ▀▀▀▄▄▀▀█▄▀▀█▀▄ ▄█▄▀▀▀▄ ▀█▀▀█▀▄▀▀▀█▄▄  ▄▄▀ ▀▄▀  ▀
 ▀  █▀▀▀█▀ ▀▀██▄▀▀█▀▄█▄▀▄ █▄█▀▀▀█▄  ██▀  ▀▀█  ▄ ▄▀█▀▀▄ ██▀▀▀█ ▄ █ ▀ ▀▄█▀ █  █ ▀  █▀██▀▀▀██▄ ▄
█▀▄▀█ ▀ █▀█▄▄ █▄ █  ▀ █ █ ▄██ ▀ █▄  ▀  ▀  ▄ ▀▀ ▀▄ █▄▄▄█ █ ▀ ██▄█▄▄▀▄▄▀▀██▀▄▀▀▀▀▄▄  ██ ▀ █▀   
▄ ███▀▀██▄██ ▀▄   ▀█▄▀▄█▀▀▄▀▀▀▀▀█▀█▄██ █▀▀█▀▄▀ ▀▄▀ ▀▄██▀▀██▀▀▀ ▄▀▀█ ▄▄▀▀ █ ██▀▀ ▀▄▀ ▀█▀█▀▀▄▀█
██ ▀  ▀▄▀▄▄▄█ ▀  ▀███▀ █ ▀█▀▄ ▄▀▄▄█▀ ▀▀▀ █▀▄█▀▄▀ ▀▄█  ▄▄▄▀ ▄█▀▄ ▄▀██  ▀█  ▀▄ ▀█ ▀  █▀▄▄▀▀▀█▀ 
█▀▄▀  ▀▀▄▄▄▄▀▄▄▄   ▀▀ █▄ █▀▄ ▄█▄▄▄▄▀█ █▀ ▄  ▄█████ █  ▄▄█▀▄ ▀▀ █▀▀▀▀▀▀█ █   ▀▀▀ ▀ ▀█▀▀▄▄▀█▄█▄
█▄  ▀█▀  ▄██▀▄▄█▀█▀▀▄▀ █ █▀▀ ▄▀▄▀▀▄█▀███ ▄▀ ▀▀▀█▀█▀▀▄▀▀ █▀  █▄▄█▄█▀▀▄ ▀█▄   ▀▄▀ ▄█▀ █▄▄▀▀ █  
 █ █▀▀▀██▀███▀ █ ▀ █▄▀▄█▀ █▄      ▀▄ ▀ ▄█▀██▄▀▀▄█▄▀  ▀▄███▀▄██▀▀ ▀▀ ▄▄▄   ▀▀▀▀█ ▄█▀▀▀▄▄▄▄▀ ▄█
▀▀ ██▀▀  ▀▄  █ █▄▄  ▀▄  ▀▀▄ ██▀██▄▄█▄▀█▄▀ █▀ █▄ ▀▄▄    ▄ ▀█▀▀  █▄▄█ ▄  ▀▄▄▀▀▀█▀▀ ▄▀▄██ ▄▄█ ▄ 
█ ▀██▀▀█  ▀▀ ▄▄ ▄▀█▀█  ▄ ▀█▀  ▄▀ ▀▄▄▄▀▄▀ ▄█▀ ▄▀▄  █▀ ▀▀▄▀▄ ▀█   ▄▄█ ▄ ▀ ▄▄▀█▀▀██▄█▀█▀▄  ▀ ▄▄▄
▄▀▄█▀▄▀ █ ▄▀▄▀ ▀█▀▀▀█▄█▀▄█▄ ▄▀█▄ ▀ █▄▄█▄█▀ ▀ ▀▄▄▄▄██ ▄▄ ▀▄ ▀ ▀█▄  ▀▄▄▀▀▀▄█ ▀▀█▀▀▄▄▄▀ ▄ ▄▄█ ▄ 
 █ █▄█▀  ▀▄  █  ▀▄▀▀ ▀█▄ ▄▄█  █ ▀█▀▄▀█▀█▄█▄ ▄▀█▄ ▀▄▄█▀█ ▄▀█▄█▀█ ▄█▀ ▄██▄█▀▀▀   ▀██ ▀▀█▄▄ ▄█ ▀
▄▄██▀ ▀ ▀██▀█  ███ █ █▀ ▄▄▄▄▄▀▀▄█▀  █▄█▀▀ ▀  █ ▄  ▀▄█▀ ▄▀  ▀█▄▀▀▄█▀▀▄▄▀▄▄ ▀█▄ ▀█ █  ▀ ▄▄ ▄█▄▀
█ █▀█▄▀▄██▀▄▄▀▀███▀▀▄  ▀▄  ▀▀█▄▀▀▀ ▀  █      ▄ █  ▀    ▄▄▄ ▀▀▄█▄▄▄▄█▀██ █▀▀ ▄ ▀▀▄▀▄ █▄█▄ ▄▀ ▀
▄▄ ▄█▄▀▀▀  ▄▄█ █▄█▄▄ ▄ █  █▄█▄█▄ ▄▀█▄  ▄█▀▄▄▄▄▄ ▀ ▄▄█▄▄▄ █  ▀▀ ▄ ▀█  ▄▄ ▄█▀  ▀▄█▄█ ▀ ▄ █ ▀▀  
 ▀▀   ▀ ▄▀▄█▀▀▄ ▄▀ █▀▄▄▄▀██ █▀▀▀█▄▀▄█  ▀▄  ▄ █▀██▄ █▄▄▄ █▀▀▀█▀▀ ▄ █  ▀▄▄▄ █ ▄ ▄ ▄  ██▀▀▀█▄ █ 
█▀▀▀▀▀█ ▄█▀█▀▀ █▄▄▄▀█  █▄▀▄ █ ▀ █ ▀ ▀  █▄▀▄ ▄█▀ ▄▄█▄  █▀█ ▀ █▄▀▀▄ ▀▄▀ ▄█▀▀▀▄ ▄▄█▀█▄▀█ ▀ █▀▄▀▀
█ ███ █ █▄ ▄▀██▄  ▀█▄ █  █ █▀▀███  ▀   ▀ ▀█▄▄█ ▀ █▄ ▀ █ █▀▀▀█▄ ▀▄▄█ ▀▀▄ ▀ ▄██▄  ▀▀▄▄▀▀▀██ █▀▀
█ ▀▀▀ █ ▀██▀ ▄▄█▄▄▀█ █▀▄████▄▄▄▄ ▀█▀▄ ▄ █▀ ▄ ▄ █▄ ▀▄█▄▀▀▄▀▀ █▄▀▄▄▄▄▄ █▄▄▀ ▄  ▄█▄▀▄▄ ▀▀ ▀▄▀█  
▀▀▀▀▀▀▀ ▀ ▀     ▀ ▀ ▀▀▀ ▀▀ ▀▀  ▀ ▀▀  ▀  ▀ ▀▀▀   ▀▀       ▀▀ ▀▀▀ ▀  ▀    ▀▀ ▀   ▀     ▀ ▀▀▀▀▀ 
{"contact":{"name":"Bob","peer_id":"0024080112209c3cd0da14edbce70c1d19c660b2835750a0931794a08676ddf03c7b655a886e",
"address":"/ip4/127.0.0.1/tcp/23001/p2p/12D3KooWLLFZAuusef2zws9er5e5cTziLd66EKKGiqTa6mZaJr2R"},"seed":{"role":
"Customer","key_id":721853122146939167,"kes_public_key":"61772c23631fa02db2fbe47515dda43fc28a471ee47719930e388d2ba5275016",
"initial_balances":{"merchant":0,"customer":1000000000000},"user_label":"test_merchant-721853122146939167",
"closing_address":"4BH2vFAir1iQCwi2RxgQmsL1qXmnTR9athNhpK31DoMwJgkpFUp2NykFCo4dXJnMhU7w9UZx7uC6qbNGuePkRLYcFo4N7p3"}}
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
[Ready] · Initiate new channel
Paste merchant info: {"contact":{"name":"...  as above ... bNGuePkRLYcFo4N7p3"}}

[2025-06-16T11:34:02Z INFO  grease_p2p::server] 💍️ Sending new channel proposal to merchant
[2025-06-16T11:34:02Z INFO  grease_p2p::delegates] DummyDelegate: Verifying proposal. NewChannelProposal { seed: ChannelSeedInfo { role: Customer, key_id: 721853122146939167, kes_public_key: "61772c23631fa02db2fbe47515dda43fc28a471ee47719930e388d2ba5275016", initial_balances: Balances { merchant: MoneroAmount { amount: 0 }, customer: MoneroAmount { amount: 1000000000000 } }, user_label: "test_merchant-721853122146939167", closing_address: Address { network: Mainnet, addr_type: Standard, public_spend: fec0022be3ee858abd36caee0beeae71ae0936d833cf4df161af676a834e5669, public_view: bbfce3242172c754ea909f94a354532973f87bacbb553ecd77356f7ebb844583 } }, contact_info_proposer: ContactInfo { name: "Alice", peer_id: PeerId("12D3KooWKBUUwYfK3d2JAfm2tW6CqKuzXXLhop6dZB92ThiMxuDB"), address: /ip4/127.0.0.1/tcp/23002/p2p/12D3KooWKBUUwYfK3d2JAfm2tW6CqKuzXXLhop6dZB92ThiMxuDB }, contact_info_proposee: ContactInfo { name: "Bob", peer_id: PeerId("12D3KooWLLFZAuusef2zws9er5e5cTziLd66EKKGiqTa6mZaJr2R"), address: /ip4/127.0.0.1/tcp/23001/p2p/12D3KooWLLFZAuusef2zws9er5e5cTziLd66EKKGiqTa6mZaJr2R }, proposer_label: "Alice-5478350487753156342", closing_address: Address { network: Mainnet, addr_type: Standard, public_spend: 3708501937897f5513732909621a72d106fbe464e45acb7dc03e9f9852d207bd, public_view: 03f8d79546903664fefa2c85377747875d94ece8c9710e106dd624a800d0eedd } }
[2025-06-16T11:34:02Z INFO  grease_p2p::server] 💍️ Proposal accepted. Channel name: XGCbc28bd2783ed9fa5c9d8ca08f6daddd0
[2025-06-16T11:34:02Z INFO  grease_p2p::server] 👛️ Creating new multisig wallet keys for channel XGCbc28bd2783ed9fa5c9d8ca08f6daddd0
[2025-06-16T11:34:02Z INFO  grease_p2p::delegates] DummyDelegate: Splitting secret share
[2025-06-16T11:34:02Z INFO  grease_p2p::server] 🔐️ Verifying KES proofs for channel XGCbc28bd2783ed9fa5c9d8ca08f6daddd0.
[2025-06-16T11:34:02Z INFO  grease_p2p::delegates] DummyDelegate: KES proofs verified successfully
[2025-06-16T11:34:02Z INFO  grease_p2p::delegates] DummyDelegate: Verifying secret share
[2025-06-16T11:34:02Z INFO  grease_p2p::server] 👛️ Multisig wallet has been successfully created for channel XGCbc28bd2783ed9fa5c9d8ca08f6daddd0.
[2025-06-16T11:34:02Z INFO  grease_p2p::delegates]  Registering transaction watcher for channel XGCbc28bd2783ed9fa5c9d8ca08f6daddd0
[2025-06-16T11:34:02Z INFO  grease_p2p::delegates] Watch-only wallet created with birthday Some(66276). Current height is 66276
[2025-06-16T11:34:02Z INFO  grease_p2p::server] 👁️‍🗨️ Generating initial ZK-proofs for channel XGCbc28bd2783ed9fa5c9d8ca08f6daddd0.
[2025-06-16T11:34:02Z INFO  grease_p2p::delegates] DummyDelegate: Generating initial proofs for XGCbc28bd2783ed9fa5c9d8ca08f6daddd0
[2025-06-16T11:34:02Z INFO  grease_p2p::server] 👁️‍🗨️ Exchanging ZK-proofs proofs for channel XGCbc28bd2783ed9fa5c9d8ca08f6daddd0 with merchant.
[2025-06-16T11:34:02Z INFO  grease_p2p::server] 👁️‍🗨️ Verifying merchant's initial transaction proof for channel XGCbc28bd2783ed9fa5c9d8ca08f6daddd0. (ZK-Witness0 proof)
[2025-06-16T11:34:02Z INFO  grease_p2p::delegates] DummyDelegate: Verifying initial proofs for XGCbc28bd2783ed9fa5c9d8ca08f6daddd0
[2025-06-16T11:34:02Z INFO  grease_p2p::server] 👁️‍🗨️ Merchant's initial transaction proof is VALID for channel XGCbc28bd2783ed9fa5c9d8ca08f6daddd0. (ZK-Witness0 proof)
[2025-06-16T11:34:02Z INFO  grease_p2p::server] 👁️‍🗨️ Stored Merchant's initial transaction proof for channel XGCbc28bd2783ed9fa5c9d8ca08f6daddd0.
[2025-06-16T11:34:02Z INFO  grease_cli::interactive] Channels saved.

Ok.
New channel created: XGCbc28bd2783ed9fa5c9d8ca08f6daddd0
```

## Funding the channel

The customer can now fund the channel. Select `Submit funding transactions` to get the funding transaction info:

```console
[Ready] · Submit funding transactions
Ok.
Send 1.000000000 XMR to 4ABxKjD9szyJpg4pMnsQ76LpudchKxJ5DjmuxEFHtiwEh8msFMUP2M8aiXFFGwKvxEUuvuVC3c59oW8KVZ6kxbiHKCkLeGd to fund the channel
```

Send the funds from the customer's wallet and wait for the transaction to confirm [^1].

Customer's wallet:
```text
   66276 out 2025-06-16 11:40:35 1.000000000000 64184300175ac47691b6b79b1812d8ab8d6fa737ec854a35862fdea68792f840 
```

Grease logs:
```console
[2025-06-16T11:40:37Z INFO  grease_p2p::server] 🪙️  Received funding transaction for channel 
[2025-06-16T11:40:37Z INFO  grease_p2p::server] 🪙️  Funding transaction for channel XGCbc28bd2783ed9fa5c9d8ca08f6daddd0 processed successfully.
```

The channel is now open and ready for use.

```console
[^1]: This is a Monero requirement. When FCMP++ goes live, participants will be able to transact immediately. 
      If FCMP++ is heavily delayed, there are workarounds we can look into, but our efforts are better spent elswhere 
      for the moment.  
```

## Sending payments

The customer can now send payments to the merchant. Select `For Customers | Send payment` in the menu.
The ability for merchants to send funds back as refunds will be added soon. Right now it's just a one-way payment flow.

On every update, the parties:
* Create a new Monero transaction for the new balances.
* Shared recovery information in case one party disappears, as well as proofs that the recovery information will work. 

```console
[Ready] · Send payment
Send amount (available: 1.000000000 XMR): .25
[2025-06-16T11:44:03Z INFO  grease_p2p::server] 💸️  Preparing new update for channel XGCbc28bd2783ed9fa5c9d8ca08f6daddd0.
[2025-06-16T11:44:03Z INFO  grease_p2p::delegates] Verifying update 1 proof for 250000000000 picoXMR
[2025-06-16T11:44:03Z INFO  grease_p2p::delegates] Update proof verified successfully for channel XGCbc28bd2783ed9fa5c9d8ca08f6daddd0
[2025-06-16T11:44:03Z INFO  grease_p2p::delegates] Dummy delegate: Verifying adapted signature
[2025-06-16T11:44:03Z INFO  grease_p2p::server] 💸️  Generating witness_1 for channel XGCbc28bd2783ed9fa5c9d8ca08f6daddd0.
[2025-06-16T11:44:03Z INFO  grease_p2p::delegates] DummyDelegate: Generating update 1 proof for channel.  250000000000
[2025-06-16T11:44:03Z INFO  grease_p2p::server] 💸️  Witness_1 for channel XGCbc28bd2783ed9fa5c9d8ca08f6daddd0 successfully generated.
[2025-06-16T11:44:03Z INFO  grease_p2p::server] 💸️  Update 1 successful on channel XGCbc28bd2783ed9fa5c9d8ca08f6daddd0.
Ok.

------------------------------------------------------------------------------
|        Balance update #  1 for channel XGCbc28bd2783ed9fa5c9d8ca08f6daddd0 |
|        Payment amount:   0.250000000 XMR                                   |
|        Merchant balance: 0.250000000 XMR                                   |
|        Customer balance: 0.750000000 XMR                                   |
|        Total:            1.000000000 XMR                                   |
------------------------------------------------------------------------------
```

Make as many payments as you would like.

## Co-operatively Closing a channel

To co-operative close a channel, either party can select `Close channel co-operatively` in the menu. 
This will initiate the channel closure procedure, which includes:
* Sharing the partial secrets so that either party can broadcast the final transaction.
* Verifying the final transaction details.
* Broadcasting the final transaction to the Monero network.

```console
[Ready] · Close channel co-operatively
[2025-06-16T11:48:12Z INFO  grease_p2p::server] 🔚️  Closing channel XGCbc28bd2783ed9fa5c9d8ca08f6daddd0...
[2025-06-16T11:48:12Z INFO  grease_p2p::server] 🔚️  Requesting closing transaction info from peer for channel XGCbc28bd2783ed9fa5c9d8ca08f6daddd0
[2025-06-16T11:48:12Z INFO  grease_p2p::server] 🔚️  Received closing transaction info for channel XGCbc28bd2783ed9fa5c9d8ca08f6daddd0 from peer. Verifying its authenticity.
[2025-06-16T11:48:12Z INFO  grease_p2p::delegates] DummyDelegate: Verifying peer witness for channel XGCbc28bd2783ed9fa5c9d8ca08f6daddd0 is correct.
[2025-06-16T11:48:12Z INFO  grease_p2p::server] 🔚️  Closing transaction details are VALID for channel XGCbc28bd2783ed9fa5c9d8ca08f6daddd0. Moving to close channel.
[2025-06-16T11:48:12Z INFO  grease_p2p::server] 🔚️  Channel XGCbc28bd2783ed9fa5c9d8ca08f6daddd0 is is the closing state. Waiting for final transaction to be confirmed.
SendRawResponse { status: "OK", double_spend: false, fee_too_low: false, invalid_input: false, invalid_output: false, low_mixin: false, not_relayed: false, overspend: false, too_big: false, too_few_outputs: false, reason: "" }
[2025-06-16T11:48:12Z INFO  grease_p2p::server] 🚀️ Broadcast closing transaction for channel XGCbc28bd2783ed9fa5c9d8ca08f6daddd0. Transaction id: 96a575441aafbd1f6921c424da9b58b2ac2511ce2839c31ee4a4ec6e592836e7
[2025-06-16T11:48:12Z INFO  grease_p2p::server] 🚀️  Received response from peer on channel XGCbc28bd2783ed9fa5c9d8ca08f6daddd0. Closed=true.
[2025-06-16T11:48:12Z INFO  grease_cli::interactive] Channels saved.
Ok.
Channel XGCbc28bd2783ed9fa5c9d8ca08f6daddd0 closed successfully. Final transaction should be broadcast shortly.
Closing balances:
Merchant: 0.250000000 XMR
Customer: 0.750000000 XMR
Total:    1.000000000 XMR
```

Both parties will see the final balances in their wallets (minus fees):

Customer wallet:
```text
   pool in locked  2025-06-16 11:51:07   0.748000000000 96a575441aafbd1f6921c424da9b58b2ac2511ce2839c31ee4a4ec6e592836e7
```

Merchant wallet:
```text
   pool in locked  2025-06-16 11:52:01   0.248000000000 96a575441aafbd1f6921c424da9b58b2ac2511ce2839c31ee4a4ec6e592836e7
```


# Still to do

Currently, Grease is a very simple proof-of-concept implementation. Only the happy path is somewhat functional from 
end-to-end.

The long laundry list of things to complete before this could even be considered ready for commercial use includes:

## Core

* [x] Ensure all unit and end-to-end tests (including Cucumber/Gherkin) pass in release mode.
* [x] Develop generic DLEQ proofs for arbitrary curves to support future upgrades (e.g., T25519).
* [ ] Implement a centralized Key Escrow Service (KES) with high-availability and secure key storage as a proof of concept.
* [ ] Integrate channel force closure and dispute resolution mechanisms, contingent on KES implementation.
* [ ] Implement robust handling for channel timeouts and abandonment, including automated recovery or closure protocols.
* [ ] Integrate with Monero's FCMP++ upgrade upon testnet stabilization and hard fork.
* [ ] Develop a secure, encrypted persistence layer for sensitive data, replacing plain text file storage.
* [ ] Implement KES on Aztec or an equivalent ZK-rollup platform, including local simulation for testing.
* [ ] Conduct comprehensive internal code reviews to identify and mitigate vulnerabilities in cryptography and protocol logic.
* [ ] Engage external auditors for security reviews post-MVP stabilization.
* [ ] Implement Grease server as a bitcart plugin.
* [ ] UX field testing.

## Possibly

* [ ] Mobile applications for customers (preferably integrated into existing Monero wallets).
* [ ] Optimize ZK-SNARK proof generation to reduce time below 500ms on modern laptops, exploring T25519 proof.
* [ ] Optimize ZKP and P2P integrations by adopting native Rust APIs, eliminating forked shell processes.
* [ ] Develop extensions for channel value addition/re-allocation without full restarts.
