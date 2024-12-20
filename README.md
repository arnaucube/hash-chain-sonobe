# hash-chain-sonobe

Repo showcasing usage of [Sonobe](https://github.com/privacy-scaling-explorations/sonobe) with [Arkworks](https://github.com/arkworks-rs) and [Circom](https://github.com/iden3/circom) circuits.

The main idea is to prove $z_n = H(H(...~H(H(H(z_0)))))$, where $n$ is the number of Keccak256 hashes ($H$) that we compute. Proving this in a 'normal' R1CS circuit for a large $n$ would be too costly, but with folding we can manage to prove it in a reasonable time span.

For more info about Sonobe, check out [Sonobe's docs](https://privacy-scaling-explorations.github.io/sonobe-docs).

<p align="center">
    <img src="https://privacy-scaling-explorations.github.io/sonobe-docs/imgs/folding-main-idea-diagram.png" style="width:70%;" />
</p>


### Usage

### poseidon_chain.rs (arkworks circuit)
Proves a chain of Poseidon hashes, using the [arkworks/poseidon](https://github.com/arkworks-rs/crypto-primitives/blob/main/crypto-primitives/src/sponge/poseidon/constraints.rs) circuit, with [Nova](https://eprint.iacr.org/2021/370.pdf)+[CycleFold](https://eprint.iacr.org/2023/1192.pdf).

- `cargo test --release poseidon_chain -- --nocapture`

### sha_chain_offchain.rs (arkworks circuit)
Proves a chain of SHA256 hashes, using the [arkworks/sha256](https://github.com/arkworks-rs/crypto-primitives/blob/main/crypto-primitives/src/crh/sha256/constraints.rs) circuit, with [Nova](https://eprint.iacr.org/2021/370.pdf)+[CycleFold](https://eprint.iacr.org/2023/1192.pdf).

- `cargo test --release sha_chain_offchain -- --nocapture`

### keccak_chain.rs (circom circuit)
Proves a chain of keccak256 hashes, using the [vocdoni/keccak256-circom](https://github.com/vocdoni/keccak256-circom) circuit, with [Nova](https://eprint.iacr.org/2021/370.pdf)+[CycleFold](https://eprint.iacr.org/2023/1192.pdf).

Assuming rust and circom have been installed:
- `./compile-circuit.sh`
- `cargo test --release keccak_chain -- --nocapture`

Note: the Circom variant currently has a bit of extra overhead since at each folding step it uses Circom witness generation to obtain the witness and then it imports it into the arkworks constraint system.

### Repo structure
- the Circom circuit (that defines the keccak-chain) to be folded is defined at [./circuit/keccak-chain.circom](https://github.com/arnaucube/hash-chain-sonobe/blob/main/circuit/keccak-chain.circom)
- the logic to fold the circuit using Sonobe is defined at [src/{poseidon_chain, sha_chain_{offchain, onchain}, keccak_chain}.rs](https://github.com/arnaucube/hash-chain-sonobe/blob/main/src)



## Other
Additionally there is the `src/naive_approach_{poseidon,sha}_chain.rs` file, which mimics the amount of hashes computed by the `src/{poseidon,sha}_chain.rs` file, but instead of folding it does it by building a big circuit that does all the hashes at once, as we would do before folding existed.

To run it:
- `cargo test --release naive_approach_sha_chain -- --nocapture`
- `cargo test --release naive_approach_poseidon_chain -- --nocapture`
