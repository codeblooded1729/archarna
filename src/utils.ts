import * as crypto from 'crypto';
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
