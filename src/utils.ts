import * as crypto from 'crypto';
import { assert } from 'console';
/** modulus of F_r of BN254 */
const SNARK_FIELD_SIZE = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');

export function modulo_snark_field(x: bigint): bigint {
    return x % SNARK_FIELD_SIZE;
}

export function random_elem_in_snark_field(): bigint {
    return modulo_snark_field(BigInt('0x' + crypto.randomBytes(32).toString('hex')));
}

export function buffer_to_bigints(buffer: Buffer): bigint[] {
    return buffer.toString().split('x').map((s) => BigInt(s));  
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

/**
 * Pad the buffer by 'p' so that its bitsize matches the size required by the snark circuit.
 * @param buffer 
 * @returns 
 */
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