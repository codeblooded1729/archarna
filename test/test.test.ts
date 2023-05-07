import { describe, it } from "node:test";
import { Archarna } from "../src/protocol";
import { assert, debug } from "console";
import {poseidon, babyjub} from 'circomlibjs';
import '../src/utils'
import { buffer_to_bigints } from "../src/utils";
describe('merkle_tree', () => {
    let proto = new Archarna();
    let usr1 = proto.setup("bruh", 'sender');
    let usr2 = proto.setup("bruh2", 'receiver');
    let usr3 = proto.setup("bruh3", 'sender');
    let usr4 = proto.setup("bruh4", 'receiver');

    let leaves = [usr1, usr2, usr3, usr4].map((x) => poseidon([x.application_secret_key]));

    let root = BigInt(proto.merkle_tree.getRoot().toString());
    let computed_root = poseidon([poseidon([leaves[0], leaves[1]]), poseidon([leaves[2], leaves[3]])]);
    it('merkle_tree root computed properly',() => {
        assert(root == computed_root);
    })
});