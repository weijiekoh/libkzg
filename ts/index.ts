require('module-alias/register')
import * as assert from 'assert'
import * as galois from '@guildofweavers/galois'
import * as bn128 from 'rustbn.js'
import * as ffjavascript from 'ffjavascript'
import { ec } from 'elliptic'

type G1Point = ec
type G2Point = ec
type Coefficient = bigint
type Polynomial = Coefficient[]
type Commitment = G1Point
type Proof = G1Point
type MultiProof = G2Point

interface PairingInputs {
    G1: G1Point;
    G2: G2Point;
}

const G1 = ffjavascript.bn128.G1
const G2 = ffjavascript.bn128.G2

const FIELD_SIZE = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617')

const genBabyJubField = () => {
    return galois.createPrimeField(FIELD_SIZE)
}

const srsg1DataRaw = require('@libkzg/taug1_65536.json')
const srsg2DataRaw = require('@libkzg/taug2_65536.json')

/*
 * @return Up to 65536 G1 values of the structured reference string.
 * These values were taken from challenge file #46 of the Perpetual Powers of
 * Tau ceremony. The Blake2b hash of challenge file is:
 *
 * 939038cd 2dc5a1c0 20f368d2 bfad8686 
 * 950fdf7e c2d2e192 a7d59509 3068816b
 * becd914b a293dd8a cb6d18c7 b5116b66 
 * ea54d915 d47a89cc fbe2d5a3 444dfbed
 *
 * The challenge file can be retrieved at:
 * https://ppot.blob.core.windows.net/public/challenge_0046
 *
 * The ceremony transcript can be retrieved at:
 * https://github.com/weijiekoh/perpetualpowersoftau
 *
 * Anyone can verify the transcript to ensure that the values in the challenge
 * file have not been tampered with. Moreover, as long as one participant in
 * the ceremony has discarded their toxic waste, the whole ceremony is secure.
 * Please read the following for more information:
 * https://medium.com/coinmonks/announcing-the-perpetual-powers-of-tau-ceremony-to-benefit-all-zk-snark-projects-c3da86af8377
 */
const srsG1 = (depth: number): G1Point[] => {
    assert(depth > 0)
    assert(depth <= 65536)

    const g1: G1Point[] = []
    for (let i = 0; i < depth; i ++) {
        g1.push([
            BigInt(srsg1DataRaw[i][0]),
            BigInt(srsg1DataRaw[i][1]),
            BigInt(1),
        ])
    }

    assert(g1[0][0] === G1.g[0])
    assert(g1[0][1] === G1.g[1])
    assert(g1[0][2] === G1.g[2])

    return g1
}

/*
 * @return Up to 65536 G2 values of the structured reference string.
 * They were taken from challenge file #46 of the Perpetual Powers of
 * Tau ceremony as described above.
 */
const srsG2 = (depth: number): G2Point[] => {
    assert(depth > 0)
    assert(depth <= 65536)

    const g2: G2Point[] = []
    for (let i = 0; i < depth; i ++) {
        g2.push([
            [ srsg2DataRaw[i][0], srsg2DataRaw[i][1] ].map(BigInt),
            [ srsg2DataRaw[i][2], srsg2DataRaw[i][3] ].map(BigInt),
            [ BigInt(1), BigInt(0) ],
        ])
    }
    assert(g2[0][0][0] === G2.g[0][0])
    assert(g2[0][0][1] === G2.g[0][1])
    assert(g2[0][1][0] === G2.g[1][0])
    assert(g2[0][1][1] === G2.g[1][1])
    assert(g2[0][2][0] === G2.g[2][0])
    assert(g2[0][2][1] === G2.g[2][1])

    return g2
}

/*
 * @return A KZG commitment to a polynomial.
 * @param coefficients The coefficients of the polynomial to commit. To
 *        generate these coefficients from arbitary values, use
 *        genCoefficients().
 * @param p The field size. Defaults to the BabyJub field size.
 */
const commit = (
    coefficients: bigint[],
): Commitment => {
    const srs = srsG1(coefficients.length)
    return polyCommit(coefficients, G1, srs)
}

const polyCommit = (
    coefficients: bigint[],
    G: G1Point | G2Point,
    srs: G1Point[] | G2Point[],
): G1Point | G2Point => {
    let result = G.zero
    for (let i = 0; i < coefficients.length; i ++) {
        let coeff = BigInt(coefficients[i])
        assert(coeff >= BigInt(0))

        result = G.affine(G.add(result, G.mulScalar(srs[i], coeff)))

        //if (coeff < 0) {
            //coeff = BigInt(-1) * coeff
            //result = G.affine(G.add(result, G.neg(G.mulScalar(srs[i], coeff))))
        //} else {
            //result = G.affine(G.add(result, G.mulScalar(srs[i], coeff)))
        //}
    }

    return result
}

/*
 * @return A the coefficients to the quotient polynomial used to generate a
 *         KZG proof.
 * @param coefficients The coefficients of the polynomial.
 * @param xVal The x-value for the polynomial evaluation proof.
 * @param p The field size. Defaults to the BabyJub field size.
 */
const genQuotientPolynomial = (
    coefficients: Coefficient[],
    xVal: bigint,
    p: bigint = FIELD_SIZE,
): Coefficient[] => {
    const field = galois.createPrimeField(p)
    const poly = field.newVectorFrom(coefficients)

    const yVal = field.evalPolyAt(poly, xVal)
    const y = field.newVectorFrom([yVal])

    const x = field.newVectorFrom([0, 1].map(BigInt))

    const z = field.newVectorFrom([xVal].map(BigInt))

    return field.divPolys(
        field.subPolys(poly, y),
        field.subPolys(x, z),
    ).toValues()
}

/*
 * @return A KZG commitment proof of evaluation at a single point.
 * @param coefficients The coefficients of the polynomial associated with the
 *        KZG commitment.
 * @param index The x-value for the polynomial evaluation proof.
 * @param p The field size. Defaults to the BabyJub field size.
 */
const genProof = (
    coefficients: Coefficient[],
    index: number | bigint,
    p: bigint = FIELD_SIZE,
): Proof => {
    const quotient = genQuotientPolynomial(coefficients, BigInt(index), p)
    return commit(quotient)
}

const genZeroPoly = (
    field: galois.FiniteField,
    indices: number[] | bigint[],
): galois.Vector => {
    let zPoly = field.newVectorFrom([
        BigInt(-1) * BigInt(indices[0]),
        BigInt(1),
    ])

    for (let i = 1; i < indices.length; i ++) {
        zPoly = field.mulPolys(
            zPoly,
            field.newVectorFrom([
                BigInt(-1) * BigInt(indices[i]),
                BigInt(1),
            ]),
        )
    }

    return zPoly
}

const genInterpolatingPoly = (
    field: galois.FiniteField,
    poly: galois.Vector,
    indices: number[] | bigint[],
): galois.Vector => {
    const x: bigint[] = []
    const values: bigint[] = []

    for (let i = 0; i < indices.length; i ++) {
        const index = BigInt(indices[i])
        const yVal = field.evalPolyAt(poly, index)
        x.push(index)
        values.push(yVal)
    }

    const iPoly = field.interpolate(
        field.newVectorFrom(x),
        field.newVectorFrom(values),
    )

    return iPoly
}

const genMultiProof = (
    coefficients: Coefficient[],
    indices: number[] | bigint[],
    p: bigint = FIELD_SIZE,
): MultiProof => {

    const field = galois.createPrimeField(p)
    const poly = field.newVectorFrom(coefficients)

    const iPoly = genInterpolatingPoly(field, poly, indices)
    const zPoly = genZeroPoly(field, indices)
    const qPoly = field.divPolys(
        field.subPolys(poly, iPoly),
        zPoly,
    )

    const qPolyCoeffs = qPoly.toValues()
    const multiProof = polyCommit(qPolyCoeffs, G2, srsG2(qPolyCoeffs.length))

    return multiProof
}


const verifyMulti = (
    commitment: Commitment,
    proof: MultiProof,
    indices: number[] | bigint[],
    values: bigint[],
    p: bigint = FIELD_SIZE,
) => {
    const field = galois.createPrimeField(p)
    const x: bigint[] = []

    for (let i = 0; i < indices.length; i ++) {
        const index = BigInt(indices[i])
        x.push(index)
    }
    const iPoly = field.interpolate(
        field.newVectorFrom(x),
        field.newVectorFrom(values),
    )
    const zPoly = genZeroPoly(field, indices)

    // e(proof, commit(zPoly)) = e(commitment - commit(iPoly), g)

    const zPolyCoeffs = zPoly.toValues()
    const zCommit = commit(zPolyCoeffs)
    const iCommit = commit(iPoly.toValues())

    const lhs = ffjavascript.bn128.pairing(
        G1.affine(zCommit),
        G2.affine(proof),
    )

    const rhs = ffjavascript.bn128.pairing(
        G1.affine(G1.sub(commitment, iCommit)),
        G2.g,
    )

    return ffjavascript.bn128.F12.eq(lhs, rhs)
}

/*
 * Returns true if the proof (that for the polynomial committed to, the
 * evaluation at the given index equals the given value) is valid, and false
 * otherwise.
 */
const verify = (
    commitment: Commitment,
    proof: Proof,
    index: number | bigint,
    value: bigint,
    p: bigint = FIELD_SIZE,
): boolean => {
    // To verify the proof, use the following equation:
    // (p - a) == proof * (x - z)
    // (p - a) / (x - z) == proof

    // Check that 
    // e(commitment - aCommit, G2.g) == e(proof, xCommit - zCommit)
    //
    // xCommit = commit([0, 1]) = SRS_G2_1
    // zCommit = commit([_index]) = SRS_G2_1 * _index
    // e((index * proof) + (commitment - aCommit), G2.g) == e(proof, xCommit)
    //
    index = BigInt(index)
    const field = galois.createPrimeField(p)
    const srs = srsG2(2)
    
    const aCommit = commit([BigInt(value)])
    const xCommit = srs[1] // polyCommit(x.toValues(), G2, srs)

    const lhs = ffjavascript.bn128.pairing(
        G1.affine(
            G1.add(
                G1.mulScalar(proof, index), // index * proof
                G1.sub(commitment, aCommit), // commitment - aCommit
            ),
        ),
        G2.g,
    )

    const rhs = ffjavascript.bn128.pairing(
        G1.affine(proof),
        srs[1], // xCommit
    )

    return ffjavascript.bn128.F12.eq(lhs, rhs)
}

const verifyViaEIP197 = (
    commitment: Commitment,
    proof: Proof,
    index: number | bigint,
    value: bigint,
    p: bigint = FIELD_SIZE,
) => {
    // Check that:
    // e(commitment - aCommitment, G2.g) == e(proof, xCommit - yCommit)
    // which is equivalent to
    // e(commitment - aCommitment, G2.g) * e(-proof, xCommit) * e(index * proof, G2.g) == 1
    // which is equivalent to
    // e((index * proof) + (commitment - aCommitment), G2.g) * e(-proof, xCommit) == 1
    // as this is what the Solidity verifier needs to check
    const field = galois.createPrimeField(p)
    const srs = srsG2(2)

    const a = field.newVectorFrom([value].map(BigInt))
    const aCommit = commit(a.toValues())
    const x = field.newVectorFrom([0, 1].map(BigInt))
    const xCommit = polyCommit(x.toValues(), G2, srs)

    const z = field.newVectorFrom([index].map(BigInt))
    const zCommit = polyCommit(z.toValues(), G2, srs)

    const inputs = [
        {
            G1: G1.affine(
                G1.add(
                    G1.mulScalar(proof, index),
                    G1.sub(commitment, aCommit),
                )
            ),
            G2: G2.g,
        },
        {
            G1: G1.affine(G1.neg(proof)),
            G2: xCommit,
        },
    ]

    return isValidPairing(inputs)
}

const genVerifierContractParams = (
    commitment: Commitment,
    proof: Proof,
    index: number | bigint,
    value: bigint,
) => {
    return {
        commitmentX: '0x' + commitment[0].toString(16),
        commitmentY: '0x' + commitment[1].toString(16),
        proofX: '0x' + proof[0].toString(16),
        proofY: '0x' + proof[1].toString(16),
        index: '0x' + BigInt(index).toString(16),
        value: '0x' + BigInt(value).toString(16),
    }
}

/*
 * @return The coefficient to a polynomial which intersects the points (0,
 *         values[0]) ... (n, values[n]). Each value must be less than
 *         FIELD_SIZE. Likewise, each resulting coefficient will be less than
 *         FIELD_SIZE. This is because all operations in this function work in
 *         a finite field of prime order p = FIELD_SIZE. The output of this
 *         function can be fed into commit() to produce a KZG polynomial
 *         commitment to said polynomial.
 * @param values The values to interpolate.
 * @param p The field size. Defaults to the BabyJub field size.
 */
const genCoefficients = (
    values: bigint[],
    p: bigint = FIELD_SIZE,
): Coefficient[] => {
    // Check the inputs
    for (let value of values) {
        assert(typeof(value) === 'bigint')
        assert(value < FIELD_SIZE)
    }

    // Perform the interpolation
    const field = galois.createPrimeField(p)
    const x: bigint[] = []
    for (let i = 0; i < values.length; i ++) {
        x.push(BigInt(i))
    }
    const xVals = field.newVectorFrom(x)
    const yVals = field.newVectorFrom(values)
    const coefficients = field.interpolate(xVals, yVals).toValues()
 
    // Check the outputs
    for (let coefficient of coefficients) {
        assert(coefficient < FIELD_SIZE)
    }
    return coefficients
}

/*
 * @return The hexadecimal representation of a value, padded to have 64
 *         characters. Does not add the 0x prefix.
 */
const hexify = (value: bigint) => {
    const p = value.toString(16)
    assert(p.length <= 64)
    return p.padStart(64, '0')
}

/*
 * Performs a pairing check in the style of EIP-197.
 * See: https://eips.ethereum.org/EIPS/eip-197
 * @return True if a EIP-197 style pairing check is valid, and false otherwise.
 * @param inputs An array of PairingInputs such that
 * input[0] * input[1] * ... * input[n] = 1
 */
const isValidPairing = (
    inputs: PairingInputs[],
): boolean => {
    assert(inputs.length > 0)

    let hexStr = ''
    for (const input of inputs) {
        // Convert the points to their affine form
        const affineG1 = ffjavascript.bn128.G1.affine(input.G1)
        const affineG2 = ffjavascript.bn128.G2.affine(input.G2)

        hexStr += hexify(affineG1[0])
        hexStr += hexify(affineG1[1])

        // Note the order of the G2 point coefficients
        hexStr += hexify(affineG2[0][1])
        hexStr += hexify(affineG2[0][0])
        hexStr += hexify(affineG2[1][1])
        hexStr += hexify(affineG2[1][0])
    }

    const pairingResult = bn128.pairing(Buffer.from(hexStr, 'hex'))

    if (pairingResult.length === 0) {
        return false
    } else {
        return BigInt('0x' + pairingResult.toString('hex')) === BigInt(1)
    }
}

export {
    FIELD_SIZE,
    genBabyJubField,
    genCoefficients,
    genQuotientPolynomial,
    commit,
    genProof,
    genMultiProof,
    verify,
    verifyViaEIP197,
    verifyMulti,
    genVerifierContractParams,
    isValidPairing,
    Coefficient,
    Polynomial,
    Commitment,
    genZeroPoly,
    Proof,
}
