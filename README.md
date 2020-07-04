# libkzg

This is a Typescript library which implements the [KZG10 polynominal
commitment](https://www.iacr.org/archive/asiacrypt2010/6477178/6477178.pdf)
scheme.

Currently, it can produce and verify proofs of one point per proof. Multi-point
proofs have not been implemented yet.

## Functions

### `genCoefficients`: generate a polynominal from arbitrary values
**`genCoefficients = (values: bigint[]): Coefficient[]`**

Given a list of arbitrary values, use polynominal interpolation to generate the
coefficients of a polynominal to commit. Each value must be lower than the BabyJub field size:

`21888242871839275222246405745257275088548364400416034343698204186575808495617`

### `commit`: generate a polynominal commitment

**`commit = (coefficients: bigint[]): Commitment`**

Generate a commitment to the polynominal with the specified coefficients.

### `genProof`: generate a proof of evaluation at one point

**`genProof = (coefficients: Coefficient[], index: number | bigint): Proof`**

Generate a proof (also known as a witness) that the polynominal will evaluate
to `coefficients[index]` given `index` as the x-value.

### `verify`: verify a proof of evaluation at one point

**`verify = (commitment: Commitment, proof: Proof, index: number | bigint, value: bigint): boolean`**

Given a proof, verify that the polynominal with the specified commitment
evaluates to the y-value `value` at the x-value `index`.

### `genVerifierContractParams`: generate parameters to the verifier contract's `verifyKZG()` function

**`genVerifierContractParams = (commitment: Commitment, proof: Proof, index: number | bigint, value: bigint)`**

A helper function which generates parameters to the `KZGVerifier.verifyKZG()`.

Example usage: 

```ts
const params = genVerifierContractParams(commitment, proof, i, yVal)
const result = await verifierContract.verifyKZG(
    params.commitmentX,
    params.commitmentY,
    params.proofX,
    params.proofY,
    params.index,
    params.value,
)
```

## Solidity verifier contract

The repository contains a Solidity contract with a `verifyKZG()` function which
performs on-chain proof verification:

```sol
function verifyKZG(
    uint256 _commitmentX,
    uint256 _commitmentY,
    uint256 _proofX,
    uint256 _proofY,
    uint256 _index,
    uint256 _value
) public view returns (bool)
```

It consumes about 178078 gas when called by a contract.

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
 PASS  ts/__tests__/libkzg.test.ts (13.256 s)
  libkzg
    commit, prove, and verify the polynominal [5, 0, 2 1]
      ✓ compute the coefficients to commit using genCoefficients() (4 ms)
      ✓ generate a KZG commitment (3 ms)
      ✓ generate the coefficients of a quotient polynominal
      ✓ generate a KZG proof (3 ms)
      ✓ verify a KZG proof (1657 ms)
      ✓ not verify an invalid KZG proof (2322 ms)
    commit, prove, and verify a random polynominal
      ✓ generate a valid proof (3333 ms)
    pairing checks
      ✓ perform pairing checks using ffjavascript (2315 ms)
      ✓ perform pairing checks using rustbn.js (1180 ms)
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
 PASS  ts/__tests__/solVerifier.test.ts (7.467 s)
  Solidity verifier
    ✓ should verify a valid proof (3825 ms)
    ✓ should not verify an invalid proof (376 ms)
```

## Warnings

The trusted setup for this library has not been perfomed yet. The test SRS
values are based on a secret of `1234`, so anyone can create fake proofs.
Moreover, the code has not been audited. Do not use it in production.

## Credits

Many thanks to [Chih-Cheng Liang](https://twitter.com/chihchengliang) and
[Barry WhiteHat](https://github.com/barryWhiteHat/) for their guidance.

For more information, please refer to: https://hackmd.io/PGjV5nwdTWyYnLp_u1xsDQ
(note that this document is slightly outdated and inaccurate).
