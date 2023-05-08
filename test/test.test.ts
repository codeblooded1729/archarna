import { before, describe, it, test } from "node:test";
import { Archarna, KYC, Receiver, Reg, Spender } from "../src/protocol";
import { assert, debug } from "console";
import {poseidon, babyjub} from 'circomlibjs';
import '../src/utils'
import { buffer_to_bigints, decrypt, encrypt, random_elem_in_snark_field, sign_eddsa, verify_eddsa } from "../src/utils";
import { verify } from "crypto";


test('Archarna', async t => {
    /// Initialize the architecture
    let proto = new Archarna();
    let kyc = new KYC();
    let reg = new Reg();

    /// add the dummy users
    let usr1 = new  Receiver(); usr1.setup('receiver1', proto, kyc);
    let usr2 = new  Spender(); usr2.setup('sender1', proto, kyc);
    let usr3 = new  Receiver(); usr3.setup('receiver2', proto, kyc);
    let usr4 = new  Spender(); usr4.setup('sender2', proto, kyc);

    // assign receiver and sender
    let receiver: Receiver = usr1;
    let sender: Spender = usr2;

    // receiver generates the address
    receiver.generate_address();

    // sender initiates the transaction
    let value = 100;
    sender.generate_transaction(value, receiver.receiver_address_info, proto, reg);

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
        let msg = [receiver.receiver_address_info.receiver_address, receiver.receiver_address_info.encrypted_identifier_receiver ];
        let signature = receiver.receiver_address_info.signature;
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
