# NIZK Circuits for Grease Interactive Protocol

These circuits implement Non-Interactive Zero-Knowledge (NIZK) proofs for the Grease protocol. The `Grease` circuit handles channel initialization, while `GreaseUpdate` manages payment updates within the channel. Both leverage zk-SNARKs for privacy-preserving verifications.

## Prerequisites
- A C++ compiler: GCC >=13.
- Recommended OS: Ubuntu 24.04 LTS or later, which natively supports modern GCC versions. For older systems like Ubuntu 22.04, you may need to upgrade your compiler manually.
- For reproducibility, consider using Docker (see optional section below).

## Install the Noir Compiler
```bash
curl -L https://raw.githubusercontent.com/noir-lang/noirup/refs/heads/main/install | bash
```

## Install Noir Proving System (Barretenberg)
```bash
curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/refs/heads/master/barretenberg/bbup/install | bash
bbup
```
Ensure you are using Barretenberg version 0.82.2 or later for optimal performance and Solidity verifier compatibility.

### Install Noir nightly version
```bash
noirup --version nightly
```

### Verify Noir Version
```bash
nargo --version
```

## Preliminary Testing
Use `Prover.toml` for test vector values. This file provides inputs for circuit execution and proof generation.

## Noir Proving System Shell Commands
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

#### Per-Package Execution
```bash
nargo execute -p Prover.toml --package Grease
nargo execute -p Prover.toml --package GreaseUpdate
```

### Generate the Verification Keys and Save to ./target/vk_init and ./target/vk_update
```bash
mkdir target/vk_init
bb write_vk -b ./target/Grease.json -o ./target/vk_init -v
mkdir target/vk_update
bb write_vk -b ./target/GreaseUpdate.json -o ./target/vk_update -v
```

### Prove and Save to ./target/proof
```bash
mkdir target/proof_init
bb prove -b ./target/Grease.json -w ./target/Grease.gz -o ./target/proof_init -v
mkdir target/proof_update
bb prove -b ./target/GreaseUpdate.json -w ./target/GreaseUpdate.gz -o ./target/proof_update -v
```

### Verify the Proofs
```bash
bb verify -v -k ./target/vk_init/vk -p ./target/proof_init/proof -i ./target/proof_init/public_inputs   # verify init proof
bb verify -v -k ./target/vk_update/vk -p ./target/proof_update/proof -i ./target/proof_update/public_inputs   # verify update proof
```

Hint: If you get a `bad_alloc` error, make sure that the `-k` and `-p` paths point to the proof and verification key 
_files_ and not their enclosing directories.

### Integrated Workflow
```bash
rm -rf target && \
nargo compile --workspace && \
nargo execute -p Prover.toml --package Grease && \
nargo execute -p Prover.toml --package GreaseUpdate && \
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
| init       | 34 185     | 14 080 B    |
| update     | 12 679     | 14 080 B    |
