import snarkjs = require("snarkjs");
import circomlibjs = require("circomlibjs");
const eddsa = circomlibjs.eddsa;
const babyJub = circomlibjs.babyjub;

/// USR_INF
type user_info = {
    /// NAME
    name: string,
    /// ASK
    application_secret_key: bigint,
    /// SPD_KY
    spending_key: bigint,
    /// MK_LOC
    merkle_tree_location: number,
    /// RADDR
    receiver_address: bigint,
}

/// TR_ATT
type transaction_attestation = {
    value: number,
    signature_transaction_commitment: {
        signature: any,
        commitment: bigint,
    },
}

/// RADDR_INF
type receiver_address_info = {
    signed_message: {
        signature: any,
        message: {
            receiving_address: bigint,
            encrypted_identifier: bigint,
        }  
    },
}

import { Archarna } from "./archarna";
import { KYC, kyc_info } from "./kyc";
import { Reg } from "./reg";
import { buffer2bits, modulo_snark_field, padbuffer, random_elem_in_snark_field,} from "./utils";
import {poseidon} from 'circomlibjs';


export class User {
    user_info: user_info;
    transcaction_attestation_list: transaction_attestation[];
    receiver_address_info: receiver_address_info;

    constructor(){
        this.user_info = null;
        this.transcaction_attestation_list = [];
        this.receiver_address_info = null;
    }

    /**
     * @param name Name of the user 
     * @param archarna Archarna entity
     * @param kyc KYC entity
     * @returns void
     */
    add_user(name: string, archarna: Archarna, kyc: KYC){
        // randomly generate the ASK
        const application_secret_key = random_elem_in_snark_field();

        // hash ASK to get DUI
        const derived_user_identifier = poseidon([application_secret_key]);

        console.log("KYC process started.");
        console.log("KYC process completed...");
        console.log("Continuing Setup...");

        // Add DUI to merkle tree owned by archarna
        archarna.insert_into_merkle_tree(derived_user_identifier);
        // find the location of leaf at which it is inserted
        const merkle_tree_location = archarna.get_merkle_leaf_loc(derived_user_identifier);

        // ranodmly generate the spending key
        const spending_key = random_elem_in_snark_field();

        // prepare KYC_INF
        const kyc_elem: kyc_info = {
            name: name ,
            derived_user_identifier: derived_user_identifier,
            merkle_tree_location: merkle_tree_location,
        }

        // ADD KYC_INF to KYC's list
        kyc.add_kyc(kyc_elem);

        // update USR_INF field of the user entity. Note that receiving address is not set up yet
        this.user_info = {
            name: name,
            application_secret_key: application_secret_key,
            spending_key: spending_key,
            merkle_tree_location: merkle_tree_location,
            receiver_address: null,
        };

        // process the setup of RADDR
        this.setup_receiving_address(derived_user_identifier, archarna);
        return; 
    }

    /**
     * 
     * @param derived_user_identifier The DUI of the user entity
     * @returns void
     */
    setup_receiving_address(derived_user_identifier: bigint, archarna: Archarna) {
        // generate random RADDR
        const receiver_address: bigint = random_elem_in_snark_field();

        //update RADDR field of user entity
        this.user_info.receiver_address = receiver_address;

        console.log('Receiptant adress ' + receiver_address.toString());
        console.log('Preparing information');

        // EID_R = encrypt(DUI)
        const encrypted_identifier_receiver: bigint = this.encrypt(derived_user_identifier, archarna);

        // TODO: Snark Proof. Optional

        // message to be signed is RADDR_R appended to EID_R
        const msg: [bigint, bigint]= [receiver_address, encrypted_identifier_receiver]

        // SIGM_RV. This is signed by Archarna entity
        const signature = archarna.sign_eddsa(msg);

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
    /**
     * @param value amount of transaction
     * @param receiver receiver entity
     * @param archarna Archarna entity
     * @param reg REG entity
     * @returns 
     */
    async generate_transaction(value: number, receiver: User, archarna: Archarna, reg: Reg){
        console.log("Starting...");

        // generate random TRR
        const transaction_randomizer = random_elem_in_snark_field();

        // COMM = H(SPD_KY, TRR, VAL, RADDR_R)
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

        // DUI = H(ASK)
        const derived_user_identifier: bigint = poseidon([this.user_info.application_secret_key]);

        // EID_S = encrypt
        const encrypted_identifier_spender = this.encrypt(derived_user_identifier, archarna);

        // Generate snark proof
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

        // Archarn verifies the proof
        const result = await archarna.verify_proof(proof, public_signals);

        if(!result) {
            console.log('Compliancy cannot be established');
            return;
        }

        // SIGM_C = (SIG_C, COMM )
        const signature_commitment = {
            signature: archarna.sign_eddsa([commitment]),
            commitment: commitment
        };

        console.log('Confirmation received',  {
            SIGM_C: signature_commitment,
        });

        // include (VAL, SIGM_C) in TR_ARR_LIS
        this.transcaction_attestation_list.push({
            value: value,
            signature_transaction_commitment: signature_commitment,
        });

        // include TR_COM_PRF in Archarna
        archarna.insert_transaction_proof({
            transaction_commitment: commitment,
            value: value,
            snark_proof: proof,
        });

        // include TR_COM_ST into in REG
        reg.add_transaction_compliance_set(
            signature_commitment,
            encrypted_identifier_spender,
            receiver.receiver_address_info.signed_message.message.encrypted_identifier,
            archarna,
        );

        console.log("trasaction completed");
    }
    /**
     * 
     * @param archarna Archarna component. Required to procure the merkle inclusion proof for the DUI
     * @param derived_user_identifier  DUI
     * @param encrypted_identifier_spender EID_S
     * @param commitment COMM
     * @param transaction_randomizer TRR
     * @param value VAL
     * @param receiver_address RADDR_R
     * @param encrypted_identifier_receiver EID_R
     * @param signature SIG_RV_R
     * @returns 
     */
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
        const merkle_proof = archarna.get_merkle_proof(derived_user_identifier);
        const is_left = merkle_proof.map(value => (value.position === 'left') ? 1: 0);
        const merkle_tree_proof = merkle_proof.map(value => BigInt(value.data.toString()));
        const merkle_tree_root = archarna.get_merkle_root();
        const merkle_proof_size = BigInt(merkle_proof.length);
        const public_key = archarna.get_public_key();
        const spending_key = this.user_info.spending_key;
        
        const msg = [receiver_address, encrypted_identifier_receiver];
        // join the messages by converting them into string and join by separator 'x'
        let msg_buffer = Buffer.from(msg.map((m) => m.toString()).join('x')); 

        // padbuffer so that it is of correct size. 
        msg_buffer = padbuffer(msg_buffer);

        const pubKey = archarna.get_signature_public_key();
        const pPubKey = babyJub.packPoint(pubKey);
        const pSignature = eddsa.packSignature(signature);
        const msgBits = buffer2bits( msg_buffer);
        const r8Bits = buffer2bits( pSignature.slice(0, 32));
        const sBits = buffer2bits( pSignature.slice(32, 64));
        const aBits = buffer2bits( pPubKey);


        // Since the ciruit demands merkle proof of size 4, we pad it with 0s. 
        while(merkle_tree_proof.length < 4) {
            merkle_tree_proof.push(BigInt("0"));
            is_left.push(0);
        }

        // compute the proof
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

    /// Toy encryption function
    encrypt(data: bigint, archarna: Archarna) {
        return modulo_snark_field(data * archarna.get_public_key());
    }

    
}
