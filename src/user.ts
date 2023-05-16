import snarkjs = require("snarkjs");
import circomlibjs = require("circomlibjs");
const eddsa = circomlibjs.eddsa;
const babyJub = circomlibjs.babyjub;

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
import { buffer2bits, decrypt, encrypt, padbuffer, random_elem_in_snark_field, sign_eddsa } from "./utils";
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
        const application_secret_key = random_elem_in_snark_field();
        const derived_user_identifier = poseidon([application_secret_key]);
        console.log("KYC process started.");
        console.log("KYC process completed...");
        console.log("Continuing Setup...");
        archarna.merkle_tree.addLeaf(Buffer.from(derived_user_identifier.toString()), false)
        const merkle_tree_location = archarna.merkle_tree.getLeafIndex(Buffer.from(derived_user_identifier.toString()));
        const spending_key = random_elem_in_snark_field();

        const kyc_elem: kyc_info = {
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
        const receiver_address: bigint = random_elem_in_snark_field();
        this.user_info.receiver_address = receiver_address;
        console.log('Receiptant adress ' + receiver_address.toString());
        console.log('Preparing information');

        const encrypted_identifier_receiver: bigint = encrypt(derived_user_identifier);

        // TODO: Snark Proof. Optional

        const msg = [receiver_address, encrypted_identifier_receiver]
        const signature = sign_eddsa(msg);

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

    async generate_transaction(value: number, receiver: User, archarna: Archarna, reg: Reg){
        console.log("Starting...");

        const transaction_randomizer = random_elem_in_snark_field();
        const commitment: bigint = poseidon([
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

        const derived_user_identifier: bigint = poseidon([this.user_info.application_secret_key]);
        const encrypted_identifier_spender = encrypt(derived_user_identifier);

        // TODO: Generate snark proof
        // let proof = null;
        const {proof: proof, publicSignals: public_signals} = await this.generate_proof(
            archarna, 
            derived_user_identifier, 
            encrypted_identifier_spender,
            commitment,
            transaction_randomizer,
            value,
            receiver.user_info.receiver_address,
            receiver.receiver_address_info.signed_message.message.encrypted_identifier,
            receiver.receiver_address_info.signed_message.signature,
        ); 


        console.log("Preparation complete");
        console.log('Information sent',  {
            COMM: commitment,
            PRF: proof,
            EID_S: encrypted_identifier_spender,
            EID_R: receiver.receiver_address_info.signed_message.message.encrypted_identifier,
            value: value,

        });

        // TODO: verify proof
        const result = await archarna.verify_proof(proof, public_signals);
        console.log("result is ", result);

        if(!result) {
            console.log('Compliancy cannot be established');
            return;
        }

        const signature_commitment = {
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

    async generate_proof(
        archarna: Archarna,
        derived_user_identifier: bigint,
        encrypted_identifier_spender: bigint,
        commitment: bigint,
        transaction_randomizer: bigint,
        value: number,
        receiver_address: bigint,
        encrypted_identifier_receiver: bigint,
        signature: bigint,
    ): Promise<{
        proof: any,
        publicSignals: any,
    }> {
        const application_secret_key = this.user_info.application_secret_key;
        const merkle_proof = archarna.merkle_tree.getProof(Buffer.from(derived_user_identifier.toString()));
        const is_left = merkle_proof.map(value => (value.position === 'left') ? 1: 0);
        const merkle_tree_proof = merkle_proof.map(value => BigInt(value.data.toString()));
        const merkle_tree_root = BigInt(archarna.merkle_tree.getRoot().toString());
        const merkle_proof_size = BigInt(merkle_proof.length);
        const public_key = BigInt('15307176248879646135452683066383658494295615492562056334044031302984832359642');
        const spending_key = this.user_info.spending_key;
        
        const msg = [receiver_address, encrypted_identifier_receiver];
        let msg_buffer = Buffer.from(msg.map((m) => m.toString()).join('x')); 
        msg_buffer = padbuffer(msg_buffer);

        const prvKey = Buffer.from("0001020304050607080900010203040506070809000102030405060708090001", "hex");
        const pubKey = eddsa.prv2pub(prvKey);
        const pPubKey = babyJub.packPoint(pubKey);
        const pSignature = eddsa.packSignature(signature);
        const msgBits = buffer2bits( msg_buffer);
        const r8Bits = buffer2bits( pSignature.slice(0, 32));
        const sBits = buffer2bits( pSignature.slice(32, 64));
        const aBits = buffer2bits( pPubKey);

        console.log("length is", msgBits.length);

        while(merkle_tree_proof.length < 4) {
            merkle_tree_proof.push(BigInt("0"));
            is_left.push(0);
        }
        const { proof, publicSignals } = await snarkjs.groth16.fullProve(
            {
                derived_user_identifier,
                application_secret_key, 
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
                aBits,
                
            },
            "circuits/circuit_js/circuit.wasm", 
            "circuits/circuit_0000.zkey");
        return {
            proof,
            publicSignals,
        }
    }
}
