type kyc_info = {
    name: string,
    derived_user_identifier: any,
    merkle_tree_location: number,
}
type user_info = {
    name: string,
    application_secret_key: bigint,
    spending_key: bigint,
    merkle_tree_location: number,
}

// TODO: find type of commitment
type transaction_attestation = {
    value: number,
    signature_transaction_commitment: any,
}

type receiver_user_info = {
    name: string,
    application_secret_key: bigint,
    spending_key: bigint,
    merkle_tree_location: number,
}


// TODO find types of commitment and proof
type transaction_compliance_proof = {
    transaction_commitment: any,
    value: number,
    snark_proof: any,
}

type transaction_compliance_set = {
    signature_transaction_commitment: [bigint, bigint],
    decrypted_identity_receiver: bigint,
    decrypted_identity_sender: bigint,
    name_sender: string,
    name_receiver: string,
}

type  receiver_address_info = {
    signature: bigint,
    receiver_address: bigint,
    encrypted_identifier_receiver: bigint,
}
