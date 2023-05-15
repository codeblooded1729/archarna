import "./objects";
import "./utils"
// @ts-ignore
import {poseidon} from 'circomlibjs';
import { MerkleTree }  from "merkletreejs";
import { buffer_to_bigints, decrypt, encrypt, random_elem_in_snark_field, sign_eddsa } from "./utils";
import { arch } from "node:os";


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



