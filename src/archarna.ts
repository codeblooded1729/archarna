import "./utils"
import snarkjs = require("snarkjs");
import fs = require("fs");
import {poseidon, eddsa} from 'circomlibjs';
import { MerkleTree }  from "merkletreejs";
import { buffer_to_bigints, modulo_snark_field, padbuffer} from "./utils";

type EDDSA_SIGNATURE = any;

/** TR_COM_PRF */
type transaction_compliance_proof = {
    /** COMM */
    transaction_commitment: bigint,
    /** VAL */
    value: number,
    /** PRF */
    snark_proof: any,
}

/** Entity ARCHARNA */
export class Archarna {
    /** The merkle tree of DUIs of users */
    private merkle_tree: MerkleTree;
    /** TR_COM_PRF_LIS */
    private transaction_compliance_proof_list: transaction_compliance_proof[];
    /** PUBLIC KEY of the toy encryption algorithm */
    private PUBLIC_KEY_ENC = BigInt('15307176248879646135452683066383658494295615492562056334044031302984832359642');
    /** Private key for EDDSA */
    private SIGNATURE_PRIVATE_KEY = Buffer.from("0001020304050607080900010203040506070809000102030405060708090001", "hex");
    private PRIVATE_KEY = BigInt('20017956399338826398715552396813926701482004149993095445983064824420563697262');
    constructor() {
        // the hashing algorithm used is poseidon on concatenation of bigints in string form by separator 'x'
        this.merkle_tree = new MerkleTree([],
            (x: Buffer ) => Buffer.from(poseidon(buffer_to_bigints(x)).toString()),
            {
                concatenator: (inputs: Buffer[]) => Buffer.from(inputs.map((buff) => buff.toString()).join('x')),
            }
        );
        this.transaction_compliance_proof_list = [];
    }

    /**
     * Verifies the snark proof
     * @param proof 
     * @param public_signals 
     * @returns 
     */
    async verify_proof(proof: any, public_signals: any): Promise<boolean> {
        const vKey = JSON.parse(fs.readFileSync("circuits/verification_key.json").toString());
        const res = await snarkjs.groth16.verify(vKey, public_signals, proof);
        return res;
    }
    /**
     * insert TR_COM_PRF in the corresponding list
     * @param proof 
     */
    insert_transaction_proof(proof: transaction_compliance_proof): void {
        this.transaction_compliance_proof_list.push(proof);
    }

    /**
     * Add the leaf which is supposed to be an element of scalar field
     * It converts the leaf into string form, and then into a buffer
     * which is then inserted into the merkle tree
     * the buffer is not further hashed, because the leaf is supposed to be
     * in encrypted form already.
     * @param leaf 
     */
    insert_into_merkle_tree(leaf: bigint): void {
        this.merkle_tree.addLeaf(Buffer.from(leaf.toString()), false);
    }

    /**
     * get location of merkle tree leaf
     * @param leaf 
     * @returns 
     */
    get_merkle_leaf_loc(leaf: bigint): number {
        return this.merkle_tree.getLeafIndex(Buffer.from(leaf.toString()));
    }

    get_merkle_proof(leaf: bigint): {
        position: "left" | "right";
        data: Buffer;
    }[] {
        return this.merkle_tree.getProof(Buffer.from(leaf.toString()))
    }

    get_merkle_root(): bigint {
        return BigInt(this.merkle_tree.getRoot().toString());
    }

    get_public_key(): bigint {
        return this.PUBLIC_KEY_ENC;
    }

    /**
     * Decription algorithm for toy encryption scheme
     * @param data 
     * @returns 
     */
    decrypt(data: bigint): bigint {
        return modulo_snark_field(data * this.PRIVATE_KEY)
    }

    get_signature_public_key(): Buffer {
        return eddsa.prv2pub(this.SIGNATURE_PRIVATE_KEY);
    }

    /**
     * Signs the message with EDDSA
     * for the purpose of this project, msg is assumed to be array of one or two bigints
     * the buffer to be signed is computed by joining two inputs with separator 'x'
     * @param msg array of two bigints
     * @returns 
     */
    sign_eddsa(msg: [bigint, bigint] | [bigint]): EDDSA_SIGNATURE {
        let buffer = Buffer.from(msg.map((m) => m.toString()).join('x'));
        buffer  = padbuffer(buffer);
        const signature = eddsa.sign(this.SIGNATURE_PRIVATE_KEY, buffer);
        return eddsa.unpackSignature(eddsa.packSignature(signature))
    }

    /**
     * Verifies the EDDSA signature
     * @param msg for the purpose of this project array of one or two bigints
     * @param signature EDDSA signature
     * @returns true if signature is verified, false otherwise
     */
    verify_eddsa(msg: [bigint, bigint] | [bigint], signature: bigint): boolean {
        let buffer = Buffer.from(msg.map((m) => m.toString()).join('x'));
        buffer  = padbuffer(buffer);
        return eddsa.verify(buffer, signature, this.get_signature_public_key());
    }

    /**
     * Get the last transaction commitment
     * @returns 
     */
    get_latest_transaction_commitment(): bigint {
        return this.transaction_compliance_proof_list.slice(-1)[0].transaction_commitment;
    }

}



