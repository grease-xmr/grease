# NIZK Circuits for Greace interactive protocol

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

## Preliminary testing
`Prover.toml` has test vector values.

## Noir proving system shell commands

### Compiler
`nargo check`
`nargo compile`

### Generate the verification key and save to ./target/vk
```bash
mkdir target/vk
bb write_vk -b ./target/Greasev0.json -o ./target/vk -v
nargo execute -p Prover.toml
```

### Prove and save to ./target/proof
```bash
mkdir target/proof
bb prove -b ./target/Greasev0.json -w ./target/Greasev0.gz -o ./target/proof -v
```

### Verify the proof
```bash
bb verify -v -k ./target/vk/vk -p ./target/proof/proof
```

Hint: If you get a `bad_alloc` error, make sure that the `-k` and `-p` paths point to the proof and verification key 
_files_ and not their enclosing folders.

## Circuit costs

### VerifyWitness0
gates: 28742

### VerifyTi
gates: 4962

### VerifyWitnessSharing
gates: 19664

