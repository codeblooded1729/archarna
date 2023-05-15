import { before, describe, it, test } from "node:test";
import { Archarna } from "../src/archarna";
import { assert, debug } from "console";
import {poseidon, babyjub} from 'circomlibjs';
import '../src/utils'
import { buffer_to_bigints, decrypt, encrypt, random_elem_in_snark_field, sign_eddsa, verify_eddsa } from "../src/utils";
import { verify } from "crypto";
import { KYC } from "../src/kyc";
import { Reg } from "../src/reg";
import { User } from "../src/user";


test('Archarna', async t => {
    /// Initialize the architecture
    let proto = new Archarna();
    let kyc = new KYC();
    let reg = new Reg();

    /// add the dummy users
    let usr1 = new  User(); usr1.add_user('bob', proto, kyc);
    let usr2 = new  User();; usr2.add_user('alice', proto, kyc);
    let usr3 = new  User();; usr3.add_user('tom', proto, kyc);
    let usr4 = new  User();; usr4.add_user('jerry', proto, kyc);

    // assign receiver and sender
    let receiver = usr1;
    let sender= usr2;

    // sender initiates the transaction
    let value = 100;
    sender.generate_transaction(value, receiver, proto, reg);

    // Reg runs post transaction
    let commitment = proto.transaction_compliance_proof_list.slice(-1)[0].transaction_commitment;
    reg.post_transaction(commitment, kyc);

    await t.test('merkle_tree root computed properly',() => {
        let leaves: bigint[] = [usr1, usr2, usr3, usr4].map((x) => poseidon([x.get_application_secret_key()]));
        let root = BigInt(proto.merkle_tree.getRoot().toString());
        let computed_root = poseidon([poseidon([leaves[0], leaves[1]]), poseidon([leaves[2], leaves[3]])]);
        assert(root == computed_root);
    });

    await t.test('check address', () => {
        let msg = [receiver.user_info.receiver_address, receiver.receiver_address_info.signed_message.message.encrypted_identifier ];
        let signature = receiver.receiver_address_info.signed_message.signature;
        assert(verify_eddsa(msg, signature));
    });
});

describe('Check Encryption and Decryption', () => {
    let num = random_elem_in_snark_field();
    it('encrypt and decrypt gives same thing', () => {
      
        assert(decrypt(encrypt(num)) === num);
    })
})

describe('Check signature', () => { 
    let msg = [random_elem_in_snark_field(), random_elem_in_snark_field()];
    let signature = sign_eddsa(msg);
    it('able to verify', () => {
        assert(verify_eddsa(msg, signature));
    });
})
