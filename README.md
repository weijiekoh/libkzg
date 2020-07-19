# libkzg

This is a Typescript library which implements the [KZG10 polynominal
commitment](https://www.iacr.org/archive/asiacrypt2010/6477178/6477178.pdf)
scheme.

It can produce and verify proofs of one point per proof, or multiple points per
proof.

## Functions

### `genCoefficients`: generate a polynominal from arbitrary values
**`genCoefficients = (values: bigint[]): Coefficient[]`**

Given a list of arbitrary values, use polynominal interpolation to generate the
coefficients of a polynominal to commit. Each value must be lower than the
BabyJub field size:

`21888242871839275222246405745257275088548364400416034343698204186575808495617`

### `commit`: generate a polynominal commitment

**`commit = (coefficients: bigint[]): Commitment`**

Generate a commitment to the polynominal with the specified coefficients.

### `genProof`: generate a proof of evaluation at one point

**`genProof = (coefficients: Coefficient[], index: number | bigint): Proof`**

Generate a proof (also known as a witness) that the polynominal will evaluate
to `p(index)` given `index` as the x-value.

### `verify`: verify a proof of evaluation at one point

**`verify = (commitment: Commitment, proof: Proof, index: number | bigint, value: bigint): boolean`**

Given a proof, verify that the polynominal with the specified commitment
evaluates to the y-value `value` at the x-value `index`.

### `genMultiProof`: generate a proof of evaluation at multiple points

**`genMultiProof = (coefficients: Coefficient[], indices: number[] | bigint[]): MultiProof`**

Generate a proof (also known as a witness) that the polynominal will evaluate
to `p(indices[i])` per `i`.

### `verifyMulti`: verify a proof of evaulation at multiple points

**`verifyMulti = (commitment: Commitment, proof: MultiProof, indices: number[] | bigint[], values: bigint[])`**

Given a proof, verify that the polynominal with the specified commitment
evaluates to the each y-value in `values` at the corresponding x-value in
`indices`.

### `genVerifierContractParams`: generate parameters to the verifier contract's `verify()` function

**`genVerifierContractParams = (commitment: Commitment, proof: Proof, index: number | bigint, value: bigint)`**

A helper function which generates parameters to the `KZGVerifier.verify()`.

Example usage: 

```ts
const params = genVerifierContractParams(commitment, proof, i, yVal)
const result = await verifierContract.verify(
    params.commitment,
    params.proof,
    params.index,
    params.value,
)
```

## Solidity contract

The repository contains a Solidity contract with a `verify()` function which
performs on-chain proof verification for single-point proofs:

```sol
function verify(
    Pairing.G1Point memory _commitment,
    Pairing.G1Point memory _proof,
    uint256 _index,
    uint256 _value
) public view returns (bool)
```

It consumes about 178078 gas when called by a contract.

It also provides a `commit()` function which can generate KZG commitments for
up to 128 coefficients. This function is intended for multi-point proof
verification.

| Coefficients | Execution cost |
|-|-|
| 1 | 34929 |
| 2 | 47496 |
| 4 | 72608 |
| 8 | 122889 |
| 16 | 223476 |
| 32 | 424786 |
| 64 | 827980 |
| 128 | 1649494 |

The `verifyMulti()` function provides multi-point proof verification.

```
function verifyMulti(
    Pairing.G1Point memory _commitment,
    Pairing.G2Point memory _proof,
    uint256[] memory _indices,
    uint256[] memory _values,
    uint256[] memory _iCoeffs,
    uint256[] memory _zCoeffs
) public view returns (bool)
```

It consumes the following gas per point:

| Points | Cost | % Savings |
|-|-|-|
| 1 | 193084 | -8 |
| 2 | 221505 | 38 |
| 3 | 250283 | 53 |
| 4 | 280075 | 61 |
| 5 | 310152 | 65 |
| 6 | 341279 | 68 |
| 7 | 372763 | 70 |
| 8 | 405237 | 72 |
| 9 | 438008 | 73 |
| 50 | 2368081 | 73 |
| 75 | 4098829 | 69 |
| 100 | 6245670 | 65 |
| 128 | 9145327 | 60 |

## Try it out

Clone this repository, install dependencies, and build the source:

```bash
git clone git@github.com:weijiekoh/libkzg.git &&
cd libkzg &&
npm i &&
npm run build
```

Run the tests:

```bash
npm run test
```

The output should look like:

```
 PASS  ts/__tests__/libkzg.test.ts (12.513 s)
  libkzg
    commit, prove, and verify the polynomial [5, 0, 2 1]
      ✓ compute the coefficients to commit using genCoefficients() (4 ms)
      ✓ generate a KZG commitment (1 ms)
      ✓ generate the coefficients of a quotient polynomial
      ✓ generate a KZG proof (1 ms)
      ✓ verify a KZG proof (1553 ms)
      ✓ not verify an invalid KZG proof (2154 ms)
    commit, prove, and verify a random polynomial
      ✓ generate a valid proof (1400 ms)
    pairing checks
      ✓ perform a pairing check than e(xg, yg) = e(yg, xg) (696 ms)
      ✓ perform a pairing check than e(xyg, g) = e(xg, yg) (709 ms)
      ✓ perform pairing checks using ffjavascript (2154 ms)
      ✓ perform pairing checks using rustbn.js (1083 ms)
    multiproofs
      ✓ should generate and verify a multiproof (713 ms)
      ✓ not verify an invalid multiproof (728 ms)
```

The repository also includes a Solidity verifier. To test it, first launch
Ganache in a different terminal:

```bash
npm run ganache
```

Next, run:

```bash
npm run test-sol-verifier
```

The output should look like:

```
 PASS  ts/__tests__/solVerifier.test.ts (39.603 s)
  Solidity verifier
    ✓ evalPolyAt() should work (21 ms)
    ✓ should generate a matching commitment (170 ms)
    multi-point proof verification
      ✓ should verify valid proofs (12498 ms)
      ✓ should reject an invalid proof (184 ms)
      ✓ should reject a valid proof with invalid iCoeffs and zCoeffs (1212 ms)
      ✓ should pass a stress test (15296 ms)
    single-point proof verification
      ✓ should verify a valid proof (4355 ms)
      ✓ should not verify an invalid proof (309 ms)
      ✓ should not verify an invalid commitment (468 ms)
```

## Trusted setup

The trusted setup for this library is the [Perpetual Powers of Tau Ceremony
(PPOT)](https://github.com/weijiekoh/perpetualpowersoftau<Paste>). It comes
packaged with the first 65536 G1 and the first two G2 powers of tau from the
46th contribution to the ceremony, which means that it can commit up to 65536
values.

The Blake2b hash of this challenge file is:

```
939038cd 2dc5a1c0 20f368d2 bfad8686 
950fdf7e c2d2e192 a7d59509 3068816b
becd914b a293dd8a cb6d18c7 b5116b66 
ea54d915 d47a89cc fbe2d5a3 444dfbed
```

The challenge file can be retrieved at:

https://ppot.blob.core.windows.net/public/challenge_0046

The ceremony transcript can be retrieved at:

https://github.com/weijiekoh/perpetualpowersoftau

Anyone can verify the transcript to ensure that the values in the challenge
file have not been tampered with. Moreover, as long as one participant in the
ceremony has discarded their toxic waste, the whole ceremony is secure. Please
read [this blog
post](https://medium.com/coinmonks/announcing-the-perpetual-powers-of-tau-ceremony-to-benefit-all-zk-snark-projects-c3da86af8377)
for more information.

## Credits

Many thanks to [Chih-Cheng Liang](https://twitter.com/chihchengliang), [Kobi
Gurkan](https://github.com/kobigurk/), and [Barry
WhiteHat](https://github.com/barryWhiteHat/) for their guidance.
