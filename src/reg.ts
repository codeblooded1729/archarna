import {KYC} from "./kyc";

type transaction_compliance_set = {
    signature_transaction_commitment: {
        signature: any,
        commitment: bigint,
    },
    decrypted_identity_receiver: bigint,
    decrypted_identity_sender: bigint,
    name_sender: string,
    name_receiver: string,
}

export class Reg {
    transction_compliance_set_list: transaction_compliance_set[];

    constructor(){
        this.transction_compliance_set_list = [];
    }

    post_transaction(commitment: bigint, kyc: KYC) {
        let transaction = null;
        for(var transaction_i of this.transction_compliance_set_list){
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