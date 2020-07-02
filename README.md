# libkzg

This is a Typescript library which implements the [KZG10 polynominal
commitment](https://www.iacr.org/archive/asiacrypt2010/6477178/6477178.pdf)
scheme.

Currently, it can produce and verify proofs of one point per proof. Multi-point
proofs have not been implemented yet.

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
 PASS  ts/__tests__/libkzg.test.ts (12.329 s)
  libkzg
    commit, prove, and verify the polynominal [5, 0, 2 1]
      ✓ compute the coefficients to commit using genCoefficients() (4 ms)
      ✓ generate a KZG commitment (3 ms)
      ✓ generate the coefficients of a quotient polynominal (1 ms)
      ✓ generate a KZG proof (4 ms)
      ✓ verify a KZG proof (843 ms)
      ✓ not verify an invalid KZG proof (2305 ms)
    commit, prove, and verify a random polynominal
      ✓ generate a valid proof (3284 ms)
    pairing checks
      ✓ perform pairing checks using ffjavascript (2321 ms)
      ✓ perform pairing checks using rustbn.js (1458 ms)
```

A Solidity verifier is a work in progress.

## Warnings

The trusted setup for this library has not been perfomed yet. The test SRS
values are based on a secret of `1234`.

## Credits

Many thanks to [Chih-Cheng Liang](https://twitter.com/chihchengliang) and
[Barry WhiteHat](https://github.com/barryWhiteHat/) for their guidance.

For more information, please refer to: https://hackmd.io/PGjV5nwdTWyYnLp_u1xsDQ
(note that this document is slightly outdated and inaccurate).
