# NIZK Circuits for Greace interactive protocol

## Preliminary testing
`Prover.toml` has test vector values.

## Noir proving system shell commands

### Compiler
`nargo check`
`nargo compile`

### Generate the verification key and save to ./target/vk
`bb write_vk -b ./target/Greasev0.json -o ./target/vk -v`
`nargo execute`

### Prove and save to ./target/proof
`bb prove -p Prover.toml -b ./target/Greasev0.json -w ./target/Greasev0.gz -o ./target/proof -v`

### Verify the proof
`bb verify -k ./target/vk -p ./target/proof -v`

## Circuit costs

### VerifyWitness0
gates: 28742

### VerifyTi
gates: 4962

### VerifyWitnessSharing
gates: 19664

