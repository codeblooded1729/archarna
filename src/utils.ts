import * as crypto from 'crypto';
import circomlibjs = require("circomlibjs");
import { assert } from 'console';
const eddsa = circomlibjs.eddsa;
const SNARK_FIELD_SIZE = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');
const PUBLIC_KEY = BigInt('15307176248879646135452683066383658494295615492562056334044031302984832359642');
const PRIVATE_KEY = BigInt('20017956399338826398715552396813926701482004149993095445983064824420563697262');
const SIGNATURE_PRIVATE_KEY = Buffer.from("0001020304050607080900010203040506070809000102030405060708090001", "hex");
const SIGNATURE_PUBLIC_KEY = eddsa.prv2pub(SIGNATURE_PRIVATE_KEY);

export function modulo_snark_field(x: bigint): bigint {
    return x % SNARK_FIELD_SIZE;
}

export function random_elem_in_snark_field(): bigint {
    return modulo_snark_field(BigInt('0x' + crypto.randomBytes(32).toString('hex')));
}

export function buffer_to_bigints(buffer: Buffer): bigint[] {
    return buffer.toString().split('x').map((s) => BigInt(s));  
}

/// Toy encryption function
export function encrypt(data: bigint) {
    return modulo_snark_field(data * PUBLIC_KEY);
}

/// Toy decryption function
export function decrypt(encrypted_data: bigint) {
    return modulo_snark_field(encrypted_data * PRIVATE_KEY);
}

/// Sign the stuff using EDDSA
export function sign_eddsa(msg: bigint[]): any {
    let buffer = Buffer.from(msg.map((m) => m.toString()).join('x'));
    buffer  = padbuffer(buffer);
    const signature = eddsa.sign(SIGNATURE_PRIVATE_KEY, buffer);
    return eddsa.unpackSignature(eddsa.packSignature(signature))
}

/// Verify the eddsa signature
export function verify_eddsa(msg: bigint[], signature: bigint): boolean {
    let buffer = Buffer.from(msg.map((m) => m.toString()).join('x'));
    buffer  = padbuffer(buffer);
    return eddsa.verify(buffer, signature, SIGNATURE_PUBLIC_KEY);
}

export function buffer2bits(buff: Buffer): bigint[] {
    const res = [];
    for (let i=0; i<buff.length; i++) {
        for (let j=0; j<8; j++) {
            if ((buff[i]>>j)&1) {
                res.push(BigInt(1));
            } else {
                res.push(BigInt(0));
            }
        }
    }
    return res;
}

export function padbuffer(buffer: Buffer): Buffer {
    assert(buffer.length <= 155);
    if (buffer.length < 155) {
        let pad = "";
        for(let i = buffer.length; i < 155; i++) {
            pad = pad + "p";
        }
        buffer = Buffer.concat([buffer, Buffer.from(pad)]);
    }
    return buffer;
}