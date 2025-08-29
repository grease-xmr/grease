# NIZK Circuits for Grease interactive protocol

## Prerequisites

`gcc` version 13 is required to run Noir. Ubuntu 22.04 does not support this version, so you may need to look up how 
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

### Install Noir nightly version
```bash
noirup --version nightly
```

### Verify Noir version
```bash
nargo --version
```

## Preliminary testing
`Prover.toml` has test vector values.

## Noir proving system shell commands

### Information
```bash
nargo info --workspace
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

### Execution
```bash
nargo execute -p Prover.toml --workspace
```

#### Per-package execution
```bash
nargo execute -p Prover.toml --package Grease
nargo execute -p Prover.toml --package GreaseUpdate
```

### Generate the verification keys and save to ./target/vk_init and ./target/vk_update
```bash
mkdir target/vk_init
bb write_vk -b ./target/Grease.json -o ./target/vk_init -v
mkdir target/vk_update
bb write_vk -b ./target/GreaseUpdate.json -o ./target/vk_update -v
```

### Prove and save to ./target/proof
```bash
mkdir target/proof_init
bb prove -b ./target/Grease.json -w ./target/Grease.gz -o ./target/proof_init -v
mkdir target/proof_update
bb prove -b ./target/GreaseUpdate.json -w ./target/GreaseUpdate.gz -o ./target/proof_update -v
```

### Verify the proofs
```bash
bb verify -v -k ./target/vk_init/vk -p ./target/proof_init/proof -i ./target/proof_init/public_inputs   # verify init proof
bb verify -v -k ./target/vk_update/vk -p ./target/proof_update/proof -i ./target/proof_update/public_inputs   # verify update proof
```

Hint: If you get a `bad_alloc` error, make sure that the `-k` and `-p` paths point to the proof and verification key 
_files_ and not their enclosing folders.

### Integrated
```bash
rm -rf target && \
nargo compile --workspace && \
nargo execute -p Prover.toml --workspace && \
mkdir target/vk_init && \
bb write_vk -b ./target/Grease.json -o ./target/vk_init -v && \
mkdir target/vk_update && \
bb write_vk -b ./target/GreaseUpdate.json -o ./target/vk_update -v && \
mkdir target/proof_init && \
bb prove -b ./target/Grease.json -w ./target/Grease.gz -o ./target/proof_init -v && \
mkdir target/proof_update && \
bb prove -b ./target/GreaseUpdate.json -w ./target/GreaseUpdate.gz -o ./target/proof_update -v && \
bb verify -v -k ./target/vk_init/vk -p ./target/proof_init/proof -i ./target/proof_init/public_inputs && \
bb verify -v -k ./target/vk_update/vk -p ./target/proof_update/proof -i ./target/proof_update/public_inputs 
```

## Circuit costs

| Stage      | Gates      | Proof size |
| :--------- | :--------- | :--------- |
| init       | 34 215     | 3 456 B    |
| update     | 19 332     | 3 296 B    |
