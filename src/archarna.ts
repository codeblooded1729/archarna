import "./objects";
import "./utils"
import snarkjs = require("snarkjs");
import fs = require("fs");
import {poseidon} from 'circomlibjs';
import { MerkleTree }  from "merkletreejs";
import { buffer_to_bigints} from "./utils";

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

    async verify_proof(proof: any, public_signals: any): Promise<boolean> {
        const vKey = JSON.parse(fs.readFileSync("circuits/verification_key.json").toString());
        const res = await snarkjs.groth16.verify(vKey, public_signals, proof);
        return res;
    }

}



