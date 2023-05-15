

// TODO: find type of commitment


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




