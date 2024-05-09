#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(clippy::upper_case_acronyms)]
///
/// This example performs the full flow:
/// - define the circuit to be folded
/// - fold the circuit with Nova+CycleFold's IVC
/// - generate a DeciderEthCircuit final proof
/// - generate the Solidity contract that verifies the proof
/// - verify the proof in the EVM
///

#[cfg(test)]
mod tests {
    use ark_bn254::{constraints::GVar, Bn254, Fr, G1Projective as G1};
    use ark_grumpkin::{constraints::GVar as GVar2, Projective as G2};

    use ark_crypto_primitives::snark::SNARK;
    use ark_groth16::{Groth16, ProvingKey, VerifyingKey as G16VerifierKey};
    use ark_poly_commit::kzg10::VerifierKey as KZGVerifierKey;

    use ark_std::Zero;

    use std::path::PathBuf;
    use std::time::Instant;

    use folding_schemes::{
        commitment::{
            kzg::{ProverKey as KZGProverKey, KZG},
            pedersen::Pedersen,
            CommitmentScheme,
        },
        folding::nova::{
            decider_eth::{prepare_calldata, Decider as DeciderEth},
            decider_eth_circuit::DeciderEthCircuit,
            get_r1cs, Nova, ProverParams, VerifierParams,
        },
        frontend::{circom::CircomFCircuit, FCircuit},
        transcript::poseidon::poseidon_test_config,
        Decider, FoldingScheme,
    };
    use solidity_verifiers::{
        evm::{compile_solidity, Evm},
        utils::get_function_selector_for_nova_cyclefold_verifier,
        verifiers::nova_cyclefold::get_decider_template_for_cyclefold_decider,
        NovaCycleFoldVerifierKey,
    };

    // This method computes the Nova's Prover & Verifier parameters for the example.
    // Warning: this method is only for testing purposes. For a real world use case those parameters
    // should be generated carefully (both the PoseidonConfig and the PedersenParams).
    #[allow(clippy::type_complexity)]
    fn init_nova_ivc_params<FC: FCircuit<Fr>>(
        F_circuit: FC,
    ) -> (
        ProverParams<G1, G2, KZG<'static, Bn254>, Pedersen<G2>>,
        VerifierParams<G1, G2>,
        KZGVerifierKey<Bn254>,
    ) {
        let mut rng = ark_std::test_rng();
        let poseidon_config = poseidon_test_config::<Fr>();

        // get the CM & CF_CM len
        let (r1cs, cf_r1cs) =
            get_r1cs::<G1, GVar, G2, GVar2, FC>(&poseidon_config, F_circuit).unwrap();
        let cs_len = r1cs.A.n_rows;
        let cf_cs_len = cf_r1cs.A.n_rows;

        // let (pedersen_params, _) = Pedersen::<G1>::setup(&mut rng, cf_len).unwrap();
        let (kzg_pk, kzg_vk): (KZGProverKey<G1>, KZGVerifierKey<Bn254>) =
            KZG::<Bn254>::setup(&mut rng, cs_len).unwrap();
        let (cf_pedersen_params, _) = Pedersen::<G2>::setup(&mut rng, cf_cs_len).unwrap();

        let fs_prover_params = ProverParams::<G1, G2, KZG<Bn254>, Pedersen<G2>> {
            poseidon_config: poseidon_config.clone(),
            cs_params: kzg_pk.clone(),
            cf_cs_params: cf_pedersen_params,
        };
        let fs_verifier_params = VerifierParams::<G1, G2> {
            poseidon_config: poseidon_config.clone(),
            r1cs,
            cf_r1cs,
        };
        (fs_prover_params, fs_verifier_params, kzg_vk)
    }

    /// Initializes Nova parameters and DeciderEth parameters. Only for test purposes.
    #[allow(clippy::type_complexity)]
    fn init_ivc_and_decider_params<FC: FCircuit<Fr>>(
        f_circuit: FC,
    ) -> (
        ProverParams<G1, G2, KZG<'static, Bn254>, Pedersen<G2>>,
        KZGVerifierKey<Bn254>,
        ProvingKey<Bn254>,
        G16VerifierKey<Bn254>,
    ) {
        let mut rng = rand::rngs::OsRng;
        let start = Instant::now();
        let (fs_prover_params, _, kzg_vk) = init_nova_ivc_params::<FC>(f_circuit.clone());
        println!("generated Nova folding params: {:?}", start.elapsed());

        pub type NOVA<FC> = Nova<G1, GVar, G2, GVar2, FC, KZG<'static, Bn254>, Pedersen<G2>>;
        let z_0 = vec![Fr::zero(); f_circuit.state_len()];
        let nova = NOVA::init(&fs_prover_params, f_circuit, z_0.clone()).unwrap();

        let decider_circuit =
            DeciderEthCircuit::<G1, GVar, G2, GVar2, KZG<Bn254>, Pedersen<G2>>::from_nova::<FC>(
                nova.clone(),
            )
            .unwrap();
        let start = Instant::now();
        let (g16_pk, g16_vk) =
            Groth16::<Bn254>::circuit_specific_setup(decider_circuit.clone(), &mut rng).unwrap();
        println!(
            "generated G16 (Decider circuit) params: {:?}",
            start.elapsed()
        );
        (fs_prover_params, kzg_vk, g16_pk, g16_vk)
    }

    #[test]
    fn full_flow() {
        // set the initial state
        let z_0_aux: Vec<u32> = vec![0_u32; 32 * 8];
        let z_0: Vec<Fr> = z_0_aux.iter().map(|v| Fr::from(*v)).collect::<Vec<Fr>>();

        // initialize the Circom circuit
        let r1cs_path = PathBuf::from("./circuit/keccak-chain.r1cs");
        let wasm_path = PathBuf::from("./circuit/keccak-chain_js/keccak-chain.wasm");

        let f_circuit_params = (r1cs_path, wasm_path, 32 * 8, 0);
        let f_circuit = CircomFCircuit::<Fr>::new(f_circuit_params).unwrap();

        let (fs_prover_params, kzg_vk, g16_pk, g16_vk) =
            init_ivc_and_decider_params::<CircomFCircuit<Fr>>(f_circuit.clone());

        pub type NOVA =
            Nova<G1, GVar, G2, GVar2, CircomFCircuit<Fr>, KZG<'static, Bn254>, Pedersen<G2>>;
        pub type DECIDERETH_FCircuit = DeciderEth<
            G1,
            GVar,
            G2,
            GVar2,
            CircomFCircuit<Fr>,
            KZG<'static, Bn254>,
            Pedersen<G2>,
            Groth16<Bn254>,
            NOVA,
        >;

        // initialize the folding scheme engine, in our case we use Nova
        let mut nova = NOVA::init(&fs_prover_params, f_circuit.clone(), z_0).unwrap();
        // run n steps of the folding iteration
        for i in 0..10 {
            let start = Instant::now();
            nova.prove_step(vec![]).unwrap();
            println!("Nova::prove_step {}: {:?}", i, start.elapsed());
        }

        let rng = rand::rngs::OsRng;
        let start = Instant::now();
        let proof = DECIDERETH_FCircuit::prove(
            (g16_pk, fs_prover_params.cs_params.clone()),
            rng,
            nova.clone(),
        )
        .unwrap();
        println!("generated Decider proof: {:?}", start.elapsed());

        let verified = DECIDERETH_FCircuit::verify(
            (g16_vk.clone(), kzg_vk.clone()),
            nova.i,
            nova.z_0.clone(),
            nova.z_i.clone(),
            &nova.U_i,
            &nova.u_i,
            &proof,
        )
        .unwrap();
        assert!(verified);
        println!("Decider proof verification: {}", verified);

        // Now, let's generate the Solidity code that verifies this Decider final proof
        let function_selector =
            get_function_selector_for_nova_cyclefold_verifier(nova.z_0.len() * 2 + 1);

        let calldata: Vec<u8> = prepare_calldata(
            function_selector,
            nova.i,
            nova.z_0,
            nova.z_i,
            &nova.U_i,
            &nova.u_i,
            proof,
        )
        .unwrap();

        // prepare the setup params for the solidity verifier
        let nova_cyclefold_vk =
            NovaCycleFoldVerifierKey::from((g16_vk, kzg_vk, f_circuit.state_len()));

        // generate the solidity code
        let decider_solidity_code = get_decider_template_for_cyclefold_decider(nova_cyclefold_vk);

        // verify the proof against the solidity code in the EVM
        let nova_cyclefold_verifier_bytecode =
            compile_solidity(&decider_solidity_code, "NovaDecider");
        let mut evm = Evm::default();
        let verifier_address = evm.create(nova_cyclefold_verifier_bytecode);
        let (_, output) = evm.call(verifier_address, calldata.clone());
        assert_eq!(*output.last().unwrap(), 1);

        // save smart contract and the calldata
        println!("storing nova-verifier.sol and the calldata into files");
        use std::fs;
        fs::write(
            "./examples/nova-verifier.sol",
            decider_solidity_code.clone(),
        )
        .unwrap();
        fs::write("./examples/solidity-calldata.calldata", calldata.clone()).unwrap();
        let s = solidity_verifiers::utils::get_formatted_calldata(calldata.clone());
        fs::write("./examples/solidity-calldata.inputs", s.join(",\n")).expect("");
    }
}
