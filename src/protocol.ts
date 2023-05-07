import "./objects";
import "./utils"
// @ts-ignore
import {poseidon, babyjub} from 'circomlibjs';
import { MerkleTree }  from "merkletreejs";
import { buffer_to_bigints, random_elem_in_snark_field } from "./utils";

export class Archarna {
    merkle_tree: MerkleTree;
    kyc_info_lis: kyc_info[];
    constructor() {
        this.merkle_tree = new MerkleTree([],
            (x: Buffer ) => Buffer.from(poseidon(buffer_to_bigints(x)).toString()),
            {
                concatenator: (inputs: Buffer[]) => Buffer.from(inputs.map((buff) => buff.toString()).join('x')),
            }
        );
        this.kyc_info_lis = [];
    }

    setup(name: string, type_user: "receiver" | "sender"): user_info | receiver_user_info {
        let application_secret_key = random_elem_in_snark_field();
        let derived_user_identifier = poseidon([application_secret_key]);
        console.log("KYC process started.");
        console.log("KYC process completed...");
        console.log("Continuing Setup...");
        this.merkle_tree.addLeaf(Buffer.from(derived_user_identifier.toString()), false)
        let merkle_tree_location = this.merkle_tree.getLeafIndex(Buffer.from(derived_user_identifier.toString()));
        let spending_key = random_elem_in_snark_field();

        let kyc_elem: kyc_info = {
            name: name ,
            derived_user_identifier: derived_user_identifier,
            merkle_tree_location: merkle_tree_location,
        }

        this.kyc_info_lis.push(kyc_elem);

        if (type_user == "receiver") {
            var usr: receiver_user_info = {
                name: name,
                application_secret_key: application_secret_key,
                spending_key: spending_key,
                merkle_tree_location: merkle_tree_location,
            }
        }
        else{
            var usr: user_info = {
                name: name,
                application_secret_key: application_secret_key,
                spending_key: spending_key,
                merkle_tree_location: merkle_tree_location,
            }
        }

        return usr;
    }

    rand(): number {
        return 1;
    }
}