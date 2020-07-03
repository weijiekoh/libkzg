import {
    FIELD_SIZE,
    genCoefficients,
    genQuotientPolynominal,
    genProof,
    verify,
    verifyViaEIP197,
    isValidPairing,
    genVerifierContractParams,
    commit,
} from '../'

import * as galois from '@guildofweavers/galois'
import { bn128 } from 'ffjavascript'
const Fr = bn128.Fr
const G1 = bn128.G1
const G2 = bn128.G2

import { ec } from 'elliptic'
type CurvePoint = ec

const mod = (n: any, m: any): BigInt => {
    return BigInt( 
        ((n % m) + m) % m
    )
}

import { babyJub } from 'circomlib'
const prime = babyJub.p
const field = galois.createPrimeField(prime)
const coefficients = [5, 0, 2, 1].map(BigInt)

describe('libkzg', () => {
    describe('commit, prove, and verify the polynominal [5, 0, 2 1]', () => {
        let proof
        let commitment
        const xVal = BigInt(6)
        let yVal

        it('compute the coefficients to commit using genCoefficients()', () => {
            const p = BigInt(127)
            const field = galois.createPrimeField(p)
            const values = [5, 25, 125].map(BigInt)
            const c = genCoefficients(values, p)
            expect(c).toEqual(
                [BigInt(5), BigInt(107), BigInt(40)]
            )

            for (let i = 0; i < c.length; i ++) {
                const expectedEval =
                    field.evalPolyAt(field.newVectorFrom(c), BigInt(i))
                expect(expectedEval).toEqual(values[i])
            }
        })

        it('generate a KZG commitment', () => {
            commitment = commit(coefficients)
            expect(commitment.length === 3)
        })

        it('generate the coefficients of a quotient polynominal', () => {
            const quotientPolyCoefficients = genQuotientPolynominal(coefficients, xVal)
            expect(quotientPolyCoefficients[0]).toEqual(BigInt(48))
            expect(quotientPolyCoefficients[1]).toEqual(BigInt(8))
            expect(quotientPolyCoefficients[2]).toEqual(BigInt(1))
        })

        it('generate a KZG proof', () => {
            yVal = field.evalPolyAt(field.newVectorFrom(coefficients), xVal)
            proof = genProof(coefficients, xVal)
            expect(proof.length === 3).toBeTruthy()
        })

        it('verify a KZG proof', () => {
            const isValid = verify(
                commitment,
                proof,
                xVal,
                yVal,
            )
            expect(isValid).toBeTruthy()

            expect(
                verifyViaEIP197(
                    commitment,
                    proof,
                    xVal,
                    yVal,
                )
            ).toBeTruthy()

            console.log(
                genVerifierContractParams(
                    commitment,
                    proof,
                    xVal,
                    yVal,
                )
            )
        })

        it('not verify an invalid KZG proof', () => {
            expect(
                verify(
                    commitment,
                    [
                        proof[0] + BigInt(1),
                        proof[1],
                        proof[2],
                    ],
                    xVal,
                    yVal,
                )
            ).toBeFalsy()

            expect(
                verify(
                    commitment,
                    proof,
                    xVal + BigInt(1),
                    yVal,
                )
            ).toBeFalsy()

            expect(
                verify(
                    commitment,
                    proof,
                    xVal,
                    yVal + BigInt(1),
                )
            ).toBeFalsy()
        })
    })

    describe('commit, prove, and verify a random polynominal', () => {
        it('generate a valid proof', () => {
            const degree = 128
            const values: bigint[] = []
            for (let i = 0; i < degree; i ++) {
                const value = field.rand()
                values.push(value)
            }
            const coefficients = genCoefficients(values)
            const commitment = commit(coefficients)
            const xVal = BigInt(6)
            const yVal = field.evalPolyAt(field.newVectorFrom(coefficients), xVal)
            const proof = genProof(coefficients, xVal)
            const isValid = verify(commitment, proof, xVal, yVal)
            expect(isValid).toBeTruthy()
        })
    })

    describe('pairing checks', () => {
        // The result of e(a, b) * e(c, d) is in the F12 field
        const F12 = bn128.F12

        // P is in the G1 field
        const P = G1.mulScalar(G1.g, Fr.e(1111))
        const negP = G1.neg(P)

        // Q and R are in the G1 field
        const Q = G2.mulScalar(G2.g, Fr.e(2222))
        const R = G2.mulScalar(G2.g, Fr.e(3333))
        const QplusR = G2.add(Q, R)

        it('perform pairing checks using ffjavascript', () => {

            // Check that e(P, Q) * e(-P, Q) = 1
            const m = F12.mul(
                bn128.pairing(P, Q),
                bn128.pairing(negP, Q),
            )
            expect(F12.eq(F12.one, m)).toBeTruthy()

            // Check that e(P, Q+R) == e(P, Q) * e(P, R)

            const lhs = bn128.pairing(P, QplusR)

            const rhs = F12.mul(
                bn128.pairing(P, Q),
                bn128.pairing(P, R),
            )

            expect(F12.eq(lhs, rhs)).toBeTruthy()

            // Check that e(P, Q) * e(P, R) * e(-P, Q + R) == 1
            const m2 = F12.mul(
                rhs,
                bn128.pairing(negP, QplusR),
            )
            expect(F12.eq(F12.one, m2)).toBeTruthy()
        })

        it('perform pairing checks using rustbn.js', () => {
            // https://gist.github.com/chriseth/f9be9d9391efc5beb9704255a8e2989d
            // Check if e(P1, P2) * e(-P1, P2) == 1 where P1 and P2 are the
            // generators of G1 and G2 respectively.

            const P1 = G1.g
            const negP1 = G1.neg(P1)

            const P2 = G2.g

            const negP = G1.neg(P)

            const input = [
                {
                    G1: P1,
                    G2: P2,
                },
                {
                    G1: negP1,
                    G2: P2,
                },
            ]
            const result = isValidPairing(input)
            expect(result).toBeTruthy()

            // Check that e(5 * P1, P2) * e(-P1, 5 * P2) == 1

            const fiveP1 = G1.mulScalar(P1, 5)
            const fiveP2 = G2.mulScalar(P2, 5)

            const input2 = [
                {
                    G1: fiveP1,
                    G2: P2,
                },
                {
                    G1: negP1,
                    G2: fiveP2,
                },
            ]
            const result2 = isValidPairing(input2)
            expect(result2).toBeTruthy()
        })
    })
})
