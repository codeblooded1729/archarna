pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/switcher.circom";
include "../node_modules/circomlib/circuits/eddsa.circom";

template check_hash() {

    signal input in;
    signal input hash;

    component poseidon = Poseidon(1);
    poseidon.inputs[0] <== in;
    hash === poseidon.out;

}



template check_merkle_proof(k) {
    signal input elem;
    signal input proof[k];
    signal input is_left[k];
    signal input root;
    signal input index;

    component poseidon[k];
    component less_than[k];
    signal curr[k + 1];
    component switcher_1[k];
    component switcher_2[k];
    curr[0] <== elem;

    for(var i = 0; i < k; i++) {
        // (is_left[i] - 1) * is_left[i] === 0;
        poseidon[i] = Poseidon(2);
        switcher_1[i] = Switcher();
        switcher_1[i].sel <== is_left[i];
        switcher_1[i].L <== curr[i];
        switcher_1[i].R <== proof[i];
        poseidon[i].inputs[0] <== switcher_1[i].outL;
        poseidon[i].inputs[1] <== switcher_1[i].outR;

        less_than[i] = LessThan(3);
        less_than[i].in[0] <== i;
        less_than[i].in[1] <== index;

        switcher_2[i] = Switcher();
        switcher_2[i].sel <== less_than[i].out;
        switcher_2[i].L <== poseidon[i].out;
        switcher_2[i].R <== curr[i];
        curr[i + 1] <== switcher_2[i].outR ;        
    }
    curr[k] === root;
}

template check_encryption() {
    signal input public_key;
    signal input msg;
    signal input encrypted_msg;

    public_key * msg === encrypted_msg; 
}


template final_circuit(levels_of_merkle_tree, msg_bitsize) {
    signal input derived_user_identifier;
    signal input application_secret_key;
    signal input merkle_tree_proof[levels_of_merkle_tree];
    signal input is_left[levels_of_merkle_tree];    // 0 if node in the merkle proof is to the right
    signal input merkle_tree_root;
    signal input merkle_proof_size;
    signal input public_key;
    signal input encrypted_identifier_spender;
    signal input commitment;
    signal input spending_key;
    signal input transaction_randomizer;
    signal input value;
    signal input receiver_address;
    signal input msgBits[msg_bitsize];
    signal input r8Bits[256];
    signal input sBits[256];
    signal input aBits[256];

    // verify that DUI = H(ASK)
    component hash_checker = check_hash();
    hash_checker.in <== application_secret_key;
    hash_checker.hash <== derived_user_identifier;

    // verify merkle proof
    component merkle_prover = check_merkle_proof(levels_of_merkle_tree);
    merkle_prover.elem <== derived_user_identifier;
    merkle_prover.proof <== merkle_tree_proof;
    merkle_prover.is_left <== is_left;
    merkle_prover.root <== merkle_tree_root;
    merkle_prover.index <== merkle_proof_size;

    // verify EID_S = encrypt(DUI)
    component encryption_prover = check_encryption();
    encryption_prover.public_key <== public_key;
    encryption_prover.msg <== derived_user_identifier;
    encryption_prover.encrypted_msg <== encrypted_identifier_spender;

    // verify COMM = H(SPD_KY_S, TRR, VAL, RADDR_R)
    component hasher = Poseidon(4);
    hasher.inputs[0] <== spending_key;
    hasher.inputs[1] <== transaction_randomizer;
    hasher.inputs[2] <== value;
    hasher.inputs[3] <== receiver_address;
    hasher.out === commitment;

    // verify eddsa signature
    component eddsa_verifier = EdDSAVerifier(msg_bitsize);
    eddsa_verifier.A <== aBits;
    eddsa_verifier.R8 <== r8Bits;
    eddsa_verifier.S <== sBits;
    eddsa_verifier.msg <== msgBits;
}

component main{public [
    derived_user_identifier, 
    merkle_tree_proof, 
    is_left, 
    merkle_tree_root,
    merkle_proof_size,
    public_key,
    encrypted_identifier_spender,
    commitment,
    spending_key,
    transaction_randomizer,
    value,
    receiver_address,
    msgBits,
    r8Bits,
    sBits,
    aBits
]} = final_circuit(4, 1240);