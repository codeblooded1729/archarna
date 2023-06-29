import { Archarna } from "./archarna";
import {KYC} from "./kyc";
import { SIG_C } from "./user";

/** TR_COM_ST */
type transaction_compliance_set = {
    /** SIGM_C */
    signature_transaction_commitment: {
        signature: SIG_C,
        commitment: bigint,
    },
    /** DEID_R */
    decrypted_identity_receiver: bigint,
    /** DEID_S */
    decrypted_identity_sender: bigint,
    /** NAME_S */
    name_sender: string,
    /** NAME_R */
    name_receiver: string,
}

/** Entity REG */
export class Reg {
    private transction_compliance_set_list: transaction_compliance_set[];

    constructor(){
        this.transction_compliance_set_list = [];
    }
    /**
     * Adds transaction compliance set
     * It requests archarna to decrypt EID_S and EID_R and creates TR_COM_ST
     * with the name fields empty for now
     * @param signature_transaction_commitment 
     * @param encrypted_identifier_spender 
     * @param encrypted_identity_receiver 
     * @param archarna 
     */
    add_transaction_compliance_set(
        signature_transaction_commitment: {
            signature: any,
            commitment: bigint,
        } ,
        encrypted_identifier_spender: bigint,
        encrypted_identity_receiver: bigint,
        archarna: Archarna
    ) {
        const transaction_compliance_set_elem: transaction_compliance_set = {
            signature_transaction_commitment,
            decrypted_identity_receiver: archarna.decrypt(encrypted_identifier_spender),
            decrypted_identity_sender: archarna.decrypt(encrypted_identity_receiver),
            name_sender: "",
            name_receiver: "",
        }
        this.transction_compliance_set_list.push(transaction_compliance_set_elem);
    }
    /**
     * 
     * @param commitment 
     * @param kyc 
     * @returns 
     */
    post_transaction(commitment: bigint, kyc: KYC) {
        let transaction = null;
        for(const transaction_i of this.transction_compliance_set_list){
            if(transaction_i.signature_transaction_commitment.commitment == commitment) {
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