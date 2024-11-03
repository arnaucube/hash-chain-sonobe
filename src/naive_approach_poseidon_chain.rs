/// This example does the hash chain but in the naive approach: instead of using folding, it does a
/// big circuit containing n instantiations of the Poseidon constraints.

#[cfg(test)]
mod tests {
    use ark_bn254::{Bn254, Fr};

    use ark_groth16::Groth16;
    use ark_snark::SNARK;

    use ark_ff::PrimeField;

    use std::time::Instant;

    use ark_crypto_primitives::sponge::{
        constraints::CryptographicSpongeVar,
        poseidon::{constraints::PoseidonSpongeVar, PoseidonConfig, PoseidonSponge},
        Absorb, CryptographicSponge,
    };
    use ark_r1cs_std::fields::fp::FpVar;
    use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget};
    use ark_r1cs_std::{bits::uint8::UInt8, boolean::Boolean, ToBitsGadget, ToBytesGadget};
    use ark_relations::r1cs::{
        ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError,
    };

    use folding_schemes::transcript::poseidon::poseidon_canonical_config;

    use crate::utils::tests::*;

    /// Test circuit to be folded
    #[derive(Clone, Debug)]
    pub struct PoseidonChainCircuit<F: PrimeField, const N: usize, const HASHES_PER_STEP: usize> {
        z_0: Option<Vec<F>>,
        z_n: Option<Vec<F>>,
        config: PoseidonConfig<F>,
    }
    impl<F: PrimeField, const N: usize, const HASHES_PER_STEP: usize> ConstraintSynthesizer<F>
        for PoseidonChainCircuit<F, N, HASHES_PER_STEP>
    {
        fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
            let z_0 = Vec::<FpVar<F>>::new_witness(cs.clone(), || {
                Ok(self.z_0.unwrap_or(vec![F::zero()]))
            })?;
            let z_n =
                Vec::<FpVar<F>>::new_input(cs.clone(), || Ok(self.z_n.unwrap_or(vec![F::zero()])))?;

            let mut sponge = PoseidonSpongeVar::<F>::new(cs.clone(), &self.config);
            let mut z_i: Vec<FpVar<F>> = z_0.clone();
            for _ in 0..N {
                for _ in 0..HASHES_PER_STEP {
                    sponge.absorb(&z_i)?;
                    z_i = sponge.squeeze_field_elements(1)?;
                }
            }

            z_i.enforce_equal(&z_n)?;
            Ok(())
        }
    }
    // compute natively in rust the expected result
    fn rust_native_result(
        poseidon_config: &PoseidonConfig<Fr>,
        z_0: Vec<Fr>,
        n_steps: usize,
        hashes_per_step: usize,
    ) -> Vec<Fr> {
        let mut z_i: Vec<Fr> = z_0.clone();
        for _ in 0..n_steps {
            let mut sponge = PoseidonSponge::<Fr>::new(&poseidon_config);

            for _ in 0..hashes_per_step {
                sponge.absorb(&z_i);
                z_i = sponge.squeeze_field_elements(1);
            }
        }
        z_i.clone()
    }

    #[test]
    fn full_flow() {
        // set how many iterations of the PoseidonChainCircuit circuit internal loop we want to
        // compute
        const N_STEPS: usize = 10;
        const HASHES_PER_STEP: usize = 400;
        println!("running the 'naive' PoseidonChainCircuit, with N_STEPS={}, HASHES_PER_STEP={}. Total hashes = {}", N_STEPS, HASHES_PER_STEP, N_STEPS* HASHES_PER_STEP);

        let poseidon_config = poseidon_canonical_config::<Fr>();

        // set the initial state
        // let z_0_aux: Vec<u32> = vec![0_u32; 32 * 8];
        let z_0_aux: Vec<u8> = vec![0_u8; 32];
        let z_0: Vec<Fr> = z_0_aux.iter().map(|v| Fr::from(*v)).collect::<Vec<Fr>>();

        // run the N iterations 'natively' in rust to compute the expected `z_n`
        let z_n = rust_native_result(&poseidon_config, z_0.clone(), N_STEPS, HASHES_PER_STEP);

        let circuit = PoseidonChainCircuit::<Fr, N_STEPS, HASHES_PER_STEP> {
            z_0: Some(z_0),
            z_n: Some(z_n.clone()),
            config: poseidon_config,
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.clone().generate_constraints(cs.clone()).unwrap();
        println!(
            "number of constraints of the (naive) PoseidonChainCircuit with N_STEPS*HASHES_PER_STEP={} poseidon hashes in total: {} (num constraints)",
            N_STEPS * HASHES_PER_STEP,
            cs.num_constraints()
        );

        // now let's generate an actual Groth16 proof
        let mut rng = rand::rngs::OsRng;
        let (g16_pk, g16_vk) =
            Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), &mut rng).unwrap();

        let start = Instant::now();
        let proof = Groth16::<Bn254>::prove(&g16_pk, circuit.clone(), &mut rng).unwrap();
        println!(
            "Groth16 proof generation (for the naive PoseidonChainCircuit): {:?}",
            start.elapsed()
        );

        let public_inputs = z_n;
        let valid_proof = Groth16::<Bn254>::verify(&g16_vk, &public_inputs, &proof).unwrap();

        assert!(valid_proof);

        println!("finished running the 'naive' PoseidonChainCircuit, with N_STEPS={}, HASHES_PER_STEP={}. Total hashes = {}", N_STEPS, HASHES_PER_STEP, N_STEPS* HASHES_PER_STEP);
    }
}
