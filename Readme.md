## Archarna PoC implementation details

### Parameters
- Elliptic curve is chosen to be BN254, default in circom
- BabyJub is used as the curve for both EDDSA signatures `SIG_C` and `SIG_RV`. Again, default in circom.
- Public Key and Private Keys for signatures as well as toy encryption alogorith can be found [utils.ts](src/utils.ts)\
- Hash function is chosen to be Poseidon

### Design choices
- When message of singature consists of two field element, the actual message hashed is is found by concatenating 
  them as strings with 'x' separator
- Hashing of multiple field elements is done as it should be done, that is, passing the array of field elements to `poseidon` function.
  That is, addition of inputs is not done.
- Archarna is responsible for signing both  signatures, `SIG_C` and `SIG_RV`.
- Archarna is responsible for keeping the merkle tree.
- User can encrypt using the public key but only Archarna can decrypt.
- REG consults Archarna for decrypting EIDs






