import * as assert from 'assert'
import { babyJub } from 'circomlib'
import * as galois from '@guildofweavers/galois'
import * as bn128 from 'rustbn.js'
import * as ffjavascript from 'ffjavascript'
import { ec } from 'elliptic'


type G1Point = ec
type G2Point = ec
type Coefficient = bigint
type Polynominal = Coefficient[]
type Commitment = G1Point
type Proof = G1Point

interface PairingInputs {
    G1: G1Point;
    G2: G2Point;
}

const G1 = ffjavascript.bn128.G1
const G2 = ffjavascript.bn128.G2

const FIELD_SIZE = babyJub.p
const TEST_SECRET = BigInt(1234)

const genBabyJubField = () => {
    const prime = babyJub.p
    return galois.createPrimeField(prime)
}

/*
 * @return The G1 values of the structured reference string.
 * TODO: add production values from PPOT
 */
const srsG1 = (
    depth: number,
    secret: bigint = TEST_SECRET,
): G1Point[] => {
    const g1: G1Point[] = [G1.g]
    let s = BigInt(secret)

    for (let i = 0; i < depth; i ++) {
        g1.push(G1.affine(G1.mulScalar(G1.g, s)))
        s = s * BigInt(secret)
    }

    return g1
}

/*
 * @return The G2 values of the structured reference string.
 * TODO: add production values from PPOT
 */
const srsG2 = (
    secret: bigint = TEST_SECRET,
): G2Point[] => {
    return [
        G2.g,
        G2.affine(G2.mulScalar(G2.g, secret)),
    ]
}

/*
 * @return A KZG commitment to a polynominal.
 * @param coefficients The coefficients of the polynominal to commit. To
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
        let coeff = coefficients[i]
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
 * @return A the coefficients to the quotient polynominal used to generate a
 *         KZG proof.
 * @param coefficients The coefficients of the polynominal.
 * @param xVal The x-value for the polynominal evaluation proof.
 * @param p The field size. Defaults to the BabyJub field size.
 */
const genQuotientPolynominal = (
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
 * @param coefficients The coefficients of the polynominal associated with the
 *        KZG commitment.
 * @param index The x-value for the polynominal evaluation proof.
 * @param p The field size. Defaults to the BabyJub field size.
 */
const genProof = (
    coefficients: Coefficient[],
    index: number | bigint,
    p: bigint = FIELD_SIZE,
): Proof => {
    const quotient = genQuotientPolynominal(coefficients, BigInt(index), p)
    return commit(quotient)
}

const verify = (
    commitment: Commitment,
    proof: Proof,
    index: number | bigint,
    value: bigint,
    p: bigint = FIELD_SIZE,
): boolean => {
    const field = galois.createPrimeField(p)
    const srs = srsG2()
    
    const a = field.newVectorFrom([value].map(BigInt))
    const x = field.newVectorFrom([0, 1].map(BigInt))
    const z = field.newVectorFrom([index].map(BigInt))

    // Note that the verifier needs to know the first 2 elements from the G1
    // SRS and the first 2 values from the G2 SRS
    const aCommit = commit(a.toValues())
    const xCommit = srs[1] //polyCommit(x.toValues(), G2, srs)
    const zCommit = polyCommit(z.toValues(), G2, srs)

    // To verify the proof, use the following equation:
    // (p - a) == proof * (x - z)
    // (p - a) / (x - z) == proof

    // Check that 
    // e(commitment - aCommitment, G2.g) == e(proof, xCommit - yCommit)
    const lhs = ffjavascript.bn128.pairing(
        G1.affine(G1.sub(commitment, aCommit)),
        G2.g,
    )

    const rhs = ffjavascript.bn128.pairing(
        proof,
        G2.affine(
            G2.sub(xCommit, zCommit)
        ),
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
    const srs = srsG2()

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
 * @return The coefficient to a polynominal which intersects the points (0,
 *         values[0]) ... (n, values[n]). Each value must be less than
 *         FIELD_SIZE. Likewise, each resulting coefficient will be less than
 *         FIELD_SIZE. This is because all operations in this function work in
 *         a finite field of prime order p = FIELD_SIZE. The output of this
 *         function can be fed into commit() to produce a KZG polynominal
 *         commitment to said polynominal.
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
    genQuotientPolynominal,
    commit,
    genProof,
    verify,
    verifyViaEIP197,
    genVerifierContractParams,
    isValidPairing,
    Coefficient,
    Polynominal,
    Commitment,
    Proof,
}
