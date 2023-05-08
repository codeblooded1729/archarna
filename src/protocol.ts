import "./objects";
import "./utils"
// @ts-ignore
import {poseidon} from 'circomlibjs';
import { MerkleTree }  from "merkletreejs";
import { buffer_to_bigints, decrypt, encrypt, random_elem_in_snark_field, sign_eddsa } from "./utils";
import { arch } from "node:os";

export class Spender {
    user_info: user_info | null;
    transcaction_attestation_list: transaction_attestation[];

    constructor(){
        this.user_info = null;
        this.transcaction_attestation_list = [];
    }

    setup(name: string, archarna: Archarna, kyc: KYC){
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
        };
        return; 
    }

    generate_transaction(value: number, receiver_address_info: receiver_address_info | null,archarna: Archarna, reg: Reg){
        console.log("Starting...");
        if(receiver_address_info.receiver_address == null) {
            console.log("No recipient address found");
            return;
        }

        let transaction_randomizer = random_elem_in_snark_field();
        let commitment: bigint = poseidon([
            this.user_info.spending_key,
            transaction_randomizer,
            value,
            receiver_address_info.receiver_address
        ]);

        console.log("Transaction commitment is: " + [
            this.user_info.spending_key,
            transaction_randomizer,
            value,
            receiver_address_info.receiver_address
        ].toString());

        let derived_user_identifier: bigint = poseidon([this.get_application_secret_key()]);
        let encrypted_identifier_spender = encrypt(derived_user_identifier);

        // TODO: Generate snark proof
        let proof = null;

        console.log("Preparation complete");
        console.log('Information sent',  {
            commitment: commitment,
            proof: proof,
            EID_S: encrypted_identifier_spender,
            EID_R: receiver_address_info.encrypted_identifier_receiver,
            value: value,

        });

        // TODO: verify proof
        let result = true;

        if(!result) {
            console.log('Compliancy cannot be established');
            return;
        }

        let signature_commitment: [bigint, bigint] = [sign_eddsa([commitment]), commitment];
        console.log('Confirmation received',  {
            SIG_C: signature_commitment,
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
            decrypted_identity_receiver: decrypt(encrypted_identifier_spender),
            decrypted_identity_sender: decrypt(receiver_address_info.encrypted_identifier_receiver),
            name_sender: "",
            name_receiver: "",
        });

        console.log("trasaction completed");
    }

    get_application_secret_key(): bigint {
        return this.user_info.application_secret_key;
    }
}

export class Receiver {
    receiver_user_info: receiver_user_info | null;
    receiver_address_info: receiver_address_info | null;;

    constructor(){
        this.receiver_user_info = null;
        this.receiver_address_info = null;
    }

    setup(name: string, archarna: Archarna, kyc: KYC){
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

        this.receiver_user_info = {
            name: name,
            application_secret_key: application_secret_key,
            spending_key: spending_key,
            merkle_tree_location: merkle_tree_location,
        };
        return; 
    }

    generate_address(): boolean {
        // check existence of receiver_user_info
        if (this.receiver_user_info == null) {
            console.log("Please run receiptant setup");
            return false;
        }
        let receiver_address: bigint = random_elem_in_snark_field();
        console.log('Receiptant adress ' + receiver_address.toString());
        console.log('Preparing information');

        let encrypted_identifier_receiver: bigint = encrypt(poseidon([this.receiver_user_info.application_secret_key]));

        // TODO: Snark Proof. Optional

        let msg = [receiver_address, encrypted_identifier_receiver]
        let signature = sign_eddsa(msg);

        // update receiver_address_info
        this.receiver_address_info = {
            signature: signature,
            receiver_address: receiver_address,
            encrypted_identifier_receiver: encrypted_identifier_receiver,
        }

        console.log({
            signature: signature,
            RADDR: receiver_address,
            EID_R: encrypted_identifier_receiver,
        });
        console.log("Process completed");
        return true;
    }

    get_application_secret_key(): bigint {
        return this.receiver_user_info.application_secret_key;
    }
}
export class Archarna {
    merkle_tree: MerkleTree;
    transaction_compliance_proof_list: transaction_compliance_proof[];
    constructor() {
        this.merkle_tree = new MerkleTree([],
            (x: Buffer ) => Buffer.from(poseidon(buffer_to_bigints(x)).toString()),
            {
                concatenator: (inputs: Buffer[]) => Buffer.from(inputs.map((buff) => buff.toString()).join('x')),
            }
        );
        this.transaction_compliance_proof_list = [];
    }

}

export class Reg {
    transction_compliance_set_list: transaction_compliance_set[];

    constructor(){
        this.transction_compliance_set_list = [];
    }

    post_transaction(commitment: bigint, kyc: KYC) {
        let transaction = null;
        for(var transaction_i of this.transction_compliance_set_list){
            if(transaction_i.signature_transaction_commitment[1] == commitment) {
                transaction = transaction_i;
                break;
            }
        }

        if(transaction == null){
            console.log("Transaction not found");
            return;
        }

        let name_receiver = "";
        let name_sender = "";
        if(transaction.name_receiver.length > 0 && transaction.name_sender.length > 0 ) {
            name_receiver = transaction.name_receiver;
            name_sender = transaction.name_sender;
        }

        else{
            name_receiver = kyc.search_identity(transaction.decrypted_identity_sender);
            name_sender = kyc.search_identity(transaction.decrypted_identity_receiver);
        }

        console.log("Name receiver: " + name_receiver);
        console.log("Name sender: " + name_sender);

        return;
    }
}

export class KYC {
    kyc_info_lis: kyc_info[];

    constructor() {
        this.kyc_info_lis = [];
    }

    search_identity(derived_user_identifier: bigint): string {
        for(var kyc_info_i of this.kyc_info_lis) {
            if(kyc_info_i.derived_user_identifier == derived_user_identifier) {
                return kyc_info_i.name;
            }
        }
        return 'Not found';
    }
}