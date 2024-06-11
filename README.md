# keccak-chain-sonobe

Repo showcasing usage of [Sonobe](https://github.com/privacy-scaling-explorations/sonobe) with [Circom](https://github.com/iden3/circom) circuits.

Proves a chain of keccak256 hashes, using the [vocdoni/keccak256-circom](https://github.com/vocdoni/keccak256-circom) circuit, with [Nova](https://eprint.iacr.org/2021/370.pdf)+[CycleFold](https://eprint.iacr.org/2023/1192.pdf).

The main idea is to prove $z_n = H(H(...~H(H(H(z_0)))))$, where $n$ is the number of Keccak256 hashes ($H$) that we compute. Proving this in a 'normal' R1CS circuit for a large $n$ would be too costly, but with folding we can manage to prove it in a reasonable time span.

For more info about Sonobe, check out [Sonobe's docs](https://privacy-scaling-explorations.github.io/sonobe-docs).

### Usage

Assuming rust and circom have been installed:

- `./compile-circuit.sh`
- `cargo test --release -- --nocapture`

### Repo structure
- the Circom circuit to be folded is defined at [./circuit/keccak-chain.circom](https://github.com/arnaucube/keccak-chain-sonobe/blob/main/circuit/keccak-chain.circom)
- the logic to fold the circuit using Sonobe is defined at [src/lib.rs](https://github.com/arnaucube/keccak-chain-sonobe/blob/main/src/lib.rs)
	- (it contains some extra sanity check that would not be needed in a real-world use case)
