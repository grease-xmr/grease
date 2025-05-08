# NIZK Circuits for Grease interactive protocol

## Prerequisites

`gcc` version 13 is required to run Noir. Ubuntu 22.04 does not support this version so you may need to look up how 
to upgrade it.

## Install the Noir compiler
```bash
curl -L https://raw.githubusercontent.com/noir-lang/noirup/refs/heads/main/install | bash
```

## Install Noir proving system
```bash
curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/refs/heads/master/barretenberg/bbup/install | bash
bbup
```

## Install Noir nightly version
```bash
noirup --version nightly
```

## Preliminary testing
`Prover.toml` has test vector values.

## Noir proving system shell commands

### Information
```bash
nargo info --workspace`
```

### Preparation
```bash
rm -rf target
```

### Compiler
```bash
nargo check --workspace
nargo compile --workspace
```

### Generate the verification keys and save to ./target/vk
```bash
mkdir target/vk
bb write_vk -b ./target/Greasev0.json -o ./target/vk/vk.key -v
bb write_vk -b ./target/GreaseUpdatev0.json -o ./target/vk/vkUpdate.key -v
nargo execute -p Prover.toml --workspace
```

#### Per-package execution
```bash
nargo execute -p Prover.toml --package Greasev0
nargo execute -p Prover.toml --package GreaseUpdatev0
```

### Prove and save to ./target/proof
```bash
mkdir target/proof
bb prove -b ./target/Greasev0.json -w ./target/Greasev0.gz -o ./target/proof/proof.key -v
bb prove -b ./target/GreaseUpdatev0.json -w ./target/GreaseUpdatev0.gz -o ./target/proof/proofUpdate.key -v
```

### Verify the proofs
```bash
bb verify -v -k ./target/vk/vk.key -p ./target/proof/proof.key   # verify init proof
bb verify -v -k ./target/vk/vkUpdate.key -p ./target/proof/proofUpdate.key   # verify update proof
```

Hint: If you get a `bad_alloc` error, make sure that the `-k` and `-p` paths point to the proof and verification key 
_files_ and not their enclosing folders.

## Circuit costs

| Stage      | Gates      | Proof size |
| :--------- | :--------- | :--------- |
| init       | 28 437     | 2 496 B    |
| update     | 19 332     | 2 272 B    |
