# keccak-chain-sonobe

Repo to test a more complex [Circom](https://github.com/iden3/circom) circuit with [Sonobe](https://github.com/privacy-scaling-explorations/sonobe).

Proves a chain of keccak256 hashes, using the [vocdoni/keccak256-circom](https://github.com/vocdoni/keccak256-circom) circuit.

Assuming rust and circom have been installed:
- `./compile-circuit.sh`
- `cargo test --release -- --nocapture`
