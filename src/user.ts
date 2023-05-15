type user_info = {
    name: string,
    application_secret_key: bigint,
    spending_key: bigint,
    merkle_tree_location: number,
    receiver_address: bigint,
}

type transaction_attestation = {
    value: number,
    signature_transaction_commitment: {
        signature: any,
        commitment: bigint,
    },
}

import { Archarna } from "./archarna";
import { KYC, kyc_info } from "./kyc";
import { Reg } from "./reg";
import { decrypt, encrypt, random_elem_in_snark_field, sign_eddsa } from "./utils";
import {poseidon} from 'circomlibjs';


export class User {
    user_info: user_info | null;
    transcaction_attestation_list: transaction_attestation[];
    receiver_address_info: {
        signed_message: {
            signature: any,
            message: {
                receiving_address: bigint,
                encrypted_identifier: bigint,
            }  
        },
    }

    constructor(){
        this.user_info = null;
        this.transcaction_attestation_list = [];
    }

    add_user(name: string, archarna: Archarna, kyc: KYC){
        let application_secret_key = random_elem_in_snark_field();
        let derived_user_identifier = poseidon([application_secret_key]);
        console.log("KYC process started.");
        console.log("KYC process completed...");
        console.log("Continuing Setup...");
        archarna.merkle_tree.addLeaf(Buffer.from(derived_user_identifier.toString()), false)
        let merkle_tree_location = archarna.merkle_tree.getLeafIndex(Buffer.from(derived_user_identifier.toString()));
        let spending_key = random_elem_in_snark_field();

        let kyc_elem: kyc_info = {
            name: name ,
            derived_user_identifier: derived_user_identifier,
            merkle_tree_location: merkle_tree_location,
        }

        kyc.kyc_info_lis.push(kyc_elem);

        this.user_info = {
            name: name,
            application_secret_key: application_secret_key,
            spending_key: spending_key,
            merkle_tree_location: merkle_tree_location,
            receiver_address: null,
        };

        this.setup_receiving_address(derived_user_identifier);
        return; 
    }

    setup_receiving_address(derived_user_identifier: bigint) {
        let receiver_address: bigint = random_elem_in_snark_field();
        this.user_info.receiver_address = receiver_address;
        console.log('Receiptant adress ' + receiver_address.toString());
        console.log('Preparing information');

        let encrypted_identifier_receiver: bigint = encrypt(derived_user_identifier);

        // TODO: Snark Proof. Optional

        let msg = [receiver_address, encrypted_identifier_receiver]
        let signature = sign_eddsa(msg);

        // update receiver_address_info
        this.receiver_address_info = {
            signed_message: {
                signature: signature,
                message: {
                    receiving_address: receiver_address,
                    encrypted_identifier: encrypted_identifier_receiver,
                }
            }
        }

        console.log({
            SIG_RV: signature,
            RADDR: receiver_address,
            EID: encrypted_identifier_receiver,
        });
        console.log("Receiving adress setup completed");
        return true;
    }

    generate_transaction(value: number, receiver: User, archarna: Archarna, reg: Reg){
        console.log("Starting...");

        let transaction_randomizer = random_elem_in_snark_field();
        let commitment: bigint = poseidon([
            this.user_info.spending_key,
            transaction_randomizer,
            value,
            receiver.user_info.receiver_address
        ]);

        console.log("Transaction commitment is: ",  {
            SPD_KY_S: this.user_info.spending_key,
            TRR: transaction_randomizer,
            VAL: value,
            RADDR_R: receiver.user_info.receiver_address,
    });

        let derived_user_identifier: bigint = poseidon([this.user_info.application_secret_key]);
        let encrypted_identifier_spender = encrypt(derived_user_identifier);

        // TODO: Generate snark proof
        let proof = null;

        console.log("Preparation complete");
        console.log('Information sent',  {
            COMM: commitment,
            PRF: proof,
            EID_S: encrypted_identifier_spender,
            EID_R: receiver.receiver_address_info.signed_message.message.encrypted_identifier,
            value: value,

        });

        // TODO: verify proof
        let result = true;

        if(!result) {
            console.log('Compliancy cannot be established');
            return;
        }

        let signature_commitment = {
            signature: sign_eddsa([commitment]),
            commitment: commitment
        };
        console.log('Confirmation received',  {
            SIGM_C: signature_commitment,
        });

        this.transcaction_attestation_list.push({
            value: value,
            signature_transaction_commitment: signature_commitment,
        });

        archarna.transaction_compliance_proof_list.push({
            transaction_commitment: commitment,
            value: value,
            snark_proof: proof,
        });

        reg.transction_compliance_set_list.push({
            signature_transaction_commitment: signature_commitment,
            decrypted_identity_sender: decrypt(encrypted_identifier_spender),
            decrypted_identity_receiver: decrypt(receiver.receiver_address_info.signed_message.message.encrypted_identifier),
            name_sender: "",
            name_receiver: "",
        });

        console.log("trasaction completed");
    }

    get_application_secret_key(): bigint {
        return this.user_info.application_secret_key;
    }
}
