///
/// This example performs the IVC:
/// - define the circuit to be folded
/// - fold the circuit with Nova+CycleFold's IVC
/// - verify the IVC proof
///

#[cfg(test)]
mod tests {
    use ark_pallas::{constraints::GVar, Fr, Projective as G1};
    use ark_vesta::{constraints::GVar as GVar2, Projective as G2};

    use ark_crypto_primitives::sponge::{
        constraints::CryptographicSpongeVar,
        poseidon::{constraints::PoseidonSpongeVar, PoseidonConfig, PoseidonSponge},
        Absorb, CryptographicSponge,
    };
    use ark_r1cs_std::fields::fp::FpVar;

    use ark_ff::PrimeField;
    use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
    use std::time::Instant;

    use folding_schemes::{
        commitment::pedersen::Pedersen,
        folding::nova::{Nova, PreprocessorParam},
        frontend::FCircuit,
        transcript::poseidon::poseidon_canonical_config,
        Error, FoldingScheme,
    };

    /// Test circuit to be folded
    #[derive(Clone, Debug)]
    pub struct PoseidonFoldStepCircuit<F: PrimeField, const HASHES_PER_STEP: usize> {
        config: PoseidonConfig<F>,
    }
    impl<F: PrimeField, const HASHES_PER_STEP: usize> FCircuit<F>
        for PoseidonFoldStepCircuit<F, HASHES_PER_STEP>
    where
        F: Absorb,
    {
        type Params = PoseidonConfig<F>;
        fn new(config: Self::Params) -> Result<Self, Error> {
            Ok(Self { config })
        }
        fn state_len(&self) -> usize {
            1
        }
        fn external_inputs_len(&self) -> usize {
            0
        }
        fn step_native(
            &self,
            _i: usize,
            z_i: Vec<F>,
            _external_inputs: Vec<F>,
        ) -> Result<Vec<F>, Error> {
            let mut sponge = PoseidonSponge::<F>::new(&self.config);

            let mut v = z_i.clone();
            for _ in 0..HASHES_PER_STEP {
                sponge.absorb(&v);
                v = sponge.squeeze_field_elements(1);
            }
            Ok(v)
        }
        fn generate_step_constraints(
            &self,
            cs: ConstraintSystemRef<F>,
            _i: usize,
            z_i: Vec<FpVar<F>>,
            _external_inputs: Vec<FpVar<F>>,
        ) -> Result<Vec<FpVar<F>>, SynthesisError> {
            let mut sponge = PoseidonSpongeVar::<F>::new(cs.clone(), &self.config);

            let mut v = z_i.clone();
            for _ in 0..HASHES_PER_STEP {
                sponge.absorb(&v)?;
                v = sponge.squeeze_field_elements(1)?;
            }
            Ok(v)
        }
    }

    #[test]
    fn full_flow() {
        // set how many steps of folding we want to compute
        const N_STEPS: usize = 10;
        const HASHES_PER_STEP: usize = 400;
        println!("running Nova folding scheme on PoseidonFoldStepCircuit, with N_STEPS={}, HASHES_PER_STEP={}. Total hashes = {}", N_STEPS, HASHES_PER_STEP, N_STEPS* HASHES_PER_STEP);

        // set the initial state
        // let z_0_aux: Vec<u32> = vec![0_u32; 32 * 8];
        let z_0_aux: Vec<u8> = vec![0_u8; 1];
        let z_0: Vec<Fr> = z_0_aux.iter().map(|v| Fr::from(*v)).collect::<Vec<Fr>>();

        let poseidon_config = poseidon_canonical_config::<Fr>();
        let f_circuit =
            PoseidonFoldStepCircuit::<Fr, HASHES_PER_STEP>::new(poseidon_config).unwrap();

        // ----------------
        // Sanity check
        // check that the f_circuit produces valid R1CS constraints
        use ark_r1cs_std::alloc::AllocVar;
        use ark_r1cs_std::fields::fp::FpVar;
        use ark_r1cs_std::R1CSVar;
        use ark_relations::r1cs::ConstraintSystem;
        let cs = ConstraintSystem::<Fr>::new_ref();
        let z_0_var = Vec::<FpVar<Fr>>::new_witness(cs.clone(), || Ok(z_0.clone())).unwrap();
        let z_1_var = f_circuit
            .generate_step_constraints(cs.clone(), 1, z_0_var, vec![])
            .unwrap();
        // check z_1_var against the native z_1
        let z_1_native = f_circuit.step_native(1, z_0.clone(), vec![]).unwrap();
        assert_eq!(z_1_var.value().unwrap(), z_1_native);
        // check that the constraint system is satisfied
        assert!(cs.is_satisfied().unwrap());
        println!(
            "number of constraints of a single instantiation of the PoseidonFoldStepCircuit: {}",
            cs.num_constraints()
        );
        // ----------------

        // define type aliases for the FoldingScheme (FS) and Decider (D), to avoid writting the
        // whole type each time
        pub type FS = Nova<
            G1,
            GVar,
            G2,
            GVar2,
            PoseidonFoldStepCircuit<Fr, HASHES_PER_STEP>,
            Pedersen<G1>,
            Pedersen<G2>,
            false,
        >;

        let mut rng = rand::rngs::OsRng;

        // prepare the Nova prover & verifier params
        let nova_preprocess_params = PreprocessorParam::new(poseidon_config, f_circuit.clone());
        let start = Instant::now();
        let nova_params = FS::preprocess(&mut rng, &nova_preprocess_params).unwrap();
        println!("Nova params generated: {:?}", start.elapsed());

        // initialize the folding scheme engine, in our case we use Nova
        let mut nova = FS::init(&nova_params, f_circuit, z_0.clone()).unwrap();

        // run n steps of the folding iteration
        let start_full = Instant::now();
        for _ in 0..N_STEPS {
            let start = Instant::now();
            nova.prove_step(rng, vec![], None).unwrap();
            println!(
                "Nova::prove_step (poseidon) {}: {:?}",
                nova.i,
                start.elapsed()
            );
        }
        println!(
            "Nova's all {} steps time: {:?}",
            N_STEPS,
            start_full.elapsed()
        );

        // verify the last IVC proof
        let ivc_proof = nova.ivc_proof();
        FS::verify(
            nova_params.1.clone(), // Nova's verifier params
            ivc_proof,
        )
        .unwrap();
    }
}
