import { describe, test, it} from "node:test";
import { Archarna } from "../src/archarna";
import assert = require('assert/strict');
import {poseidon} from 'circomlibjs';
import '../src/utils'
import {decrypt, encrypt, random_elem_in_snark_field, sign_eddsa, verify_eddsa } from "../src/utils";
import { KYC } from "../src/kyc";
import { Reg } from "../src/reg";
import { User } from "../src/user";
import * as log from 'why-is-node-running';

test('Archarna', async (t) => {
    /// Initialize the architecture
    const proto = new Archarna();
    const kyc = new KYC();
    const reg = new Reg();

    /// add the dummy users
    const usr1 = new  User(); usr1.add_user('bob', proto, kyc);
    const usr2 = new  User(); usr2.add_user('alice', proto, kyc);
    const usr3 = new  User(); usr3.add_user('tom', proto, kyc);
    const usr4 = new  User(); usr4.add_user('jerry', proto, kyc);

    // assign receiver and sender
    const receiver = usr1;
    const sender= usr2;

    //sender initiates the transaction
    const value = 100;
    const _ = await sender.generate_transaction(value, receiver, proto, reg);

    // Reg runs post transaction
    const commitment = proto.transaction_compliance_proof_list.slice(-1)[0].transaction_commitment;
    reg.post_transaction(commitment, kyc);

    await t.test('merkle_tree root computed properly',() => {
        const leaves: bigint[] = [usr1, usr2, usr3, usr4].map((x) => poseidon([x.user_info.application_secret_key]));
        const root = BigInt(proto.merkle_tree.getRoot().toString());
        const computed_root = poseidon([poseidon([leaves[0], leaves[1]]), poseidon([leaves[2], leaves[3]])]);
        assert.strictEqual(root, computed_root);
    })

    await t.test('merkle proof is correct', () => {
        const leaf = poseidon([usr2.user_info.application_secret_key]);
        const merkle_tree_proof = proto.merkle_tree.getProof(Buffer.from(leaf.toString()));
        const  is_left = merkle_tree_proof.map(value => (value.position === 'left') ? 1: 0);
        const proof = merkle_tree_proof.map(value => value.data);

        let curr = leaf;
        for (let i =0; i < merkle_tree_proof.length; i++) {
            const other = BigInt(proof[i].toString());
            if(is_left[i]) {
                curr = poseidon([other, curr]);
            }
            else{
                curr = poseidon([curr, other]);
            }
        }

        assert.strictEqual(BigInt(proto.merkle_tree.getRoot().toString()), curr);
    })

    await t.test('check address', () => {
        const msg = [receiver.user_info.receiver_address, receiver.receiver_address_info.signed_message.message.encrypted_identifier ];
        const signature = receiver.receiver_address_info.signed_message.signature;
        assert.strictEqual(verify_eddsa(msg, signature), true);
    })

    // log();
});

describe('Check Encryption and Decryption', () => {
    const num = random_elem_in_snark_field();
    it('encrypt and decrypt gives same thing', () => {
      
        assert.strictEqual(decrypt(encrypt(num)), num);
    })
})

describe('Check signature', () => { 
    const msg = [random_elem_in_snark_field(), random_elem_in_snark_field()];
    const signature = sign_eddsa(msg);
    it('able to verify', () => {
        assert.strictEqual(verify_eddsa(msg, signature), true);
    });
})
