set -e
circom circuit.circom --wasm --r1cs
snarkjs groth16 setup circuit.r1cs powersOfTau28_hez_final_15.ptau circuit_0000.zkey
snarkjs zkey export verificationkey circuit_0000.zkey verification_key.json