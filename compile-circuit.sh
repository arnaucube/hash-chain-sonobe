#!/bin/bash

# rm previous files
rm -r ./circuit/keccak-chain_js
rm circuit/keccak-chain.r1cs
rm circuit/keccak-chain.sym

cd circuit
npm install
cd ..

circom ./circuit/keccak-chain.circom --r1cs --sym --wasm --prime bn128 --output ./circuit/
