jest.setTimeout(90000)
const Verifier = require('../../compiled/Verifier.json')
import * as ethers from 'ethers'
import * as etherlime from 'etherlime-lib'
import {
    genBabyJubField,
    genCoefficients,
    commit,
    genProof,
    genMultiProof,
    verify,
    verifyMulti,
    genVerifierContractParams,
    genMultiVerifierContractParams,
} from '../'

const mnemonic =
    'candy maple cake sugar pudding cream honey rich smooth crumble sweet treat'

const genTestAccounts = (
    numAccounts: number,
) => {
    const accounts: ethers.Wallet[] = []

    for (let i=0; i<numAccounts; i++) {
        const path = `m/44'/60'/${i}'/0/0`
        const wallet = ethers.Wallet.fromMnemonic(mnemonic, path)
        accounts.push(wallet)
    }

    return accounts
}

const field = genBabyJubField()

describe('Solidity verifier', () => {
    const account = genTestAccounts(1)[0]
    const deployer = new etherlime.JSONRPCPrivateKeyDeployer(
        account.privateKey,
        'http://localhost:8545',
    )

    let verifierContract
    let values: bigint[] = []
    let commitment
    const degree = 10
    let coefficients

    beforeAll(async () => {
        verifierContract = await deployer.deploy(
            Verifier,
            {},
        )

        for (let i = 0; i < degree; i ++) {
            const value = field.rand()
            values.push(value)
        }
        coefficients = genCoefficients(values)
        commitment = commit(coefficients)
    })

    it('evalPolyAt() should work', async () => {
        const index = BigInt(2)
        const y = field.evalPolyAt(field.newVectorFrom(coefficients), index)
        const expectedY = await verifierContract.evalPolyAt(
            coefficients.map((x) => x.toString()),
            index.toString(),
        )
        expect(y.toString()).toEqual(expectedY.toString())
    })

    it('should generate a matching commitment', async () => {
        const result = await verifierContract.commit(coefficients.map((x) => x.toString()))
        expect(result.X.toString()).toEqual(commitment[0].toString())
        expect(result.Y.toString()).toEqual(commitment[1].toString())
    })

    /*
    it('commit() benchmarks', async () => {
        const NUM_COEFFS = 128
        let coeffs: bigint[] = []
        for (let i = 0; i < NUM_COEFFS; i ++) {
            coeffs.push(BigInt(field.rand()))
        }

        //const commitment = commit(coeffs)
        const tx = await verifierContract.commitBenchmark(coeffs.map((x) => x.toString()))
        const receipt = await tx.wait()
        console.log(receipt.gasUsed.toString())
    })
    */

    describe('multi-point proof verification', () => {
        it('should verify valid proofs', async () => {
            let indices: bigint[] = []
            for (let i = 0; i < coefficients.length - 1; i ++) {
                indices.push(BigInt(i))
                const proof = genMultiProof(coefficients, indices)
                const values = indices.map((x) => field.evalPolyAt(field.newVectorFrom(coefficients), x))

                expect(verifyMulti(commitment, proof, indices, values)).toBeTruthy()

                const params = genMultiVerifierContractParams(
                    commitment,
                    proof,
                    indices,
                    values,
                )

                const result = await verifierContract.verifyMulti(
                    params.commitment,
                    params.proof,
                    params.indices,
                    params.values,
                    params.iCoeffs,
                    params.zCoeffs,
                )

                expect(result).toBeTruthy()

                //// For gas benchmarking
                //const tx = await verifierContract.verifyMultiBenchmark(
                    //params.commitment,
                    //params.proof,
                    //params.indices,
                    //params.values,
                    //params.iCoeffs,
                    //params.zCoeffs,
                    //{ gasLimit: 10000000 },
                //)
                //const receipt = await tx.wait()

                //const savings = 1 - (parseInt(receipt.gasUsed.toString(), 10) / (params.indices.length * 178078))
                //console.log(params.indices.length, receipt.gasUsed.toString(), savings)
            }
        })

        it('should reject an invalid proof', async () => {
            const indices = [BigInt(0), BigInt(2)]
            const proof = genMultiProof(coefficients, indices)
            const values = indices.map((x) => field.evalPolyAt(field.newVectorFrom(coefficients), x))

            const params = genMultiVerifierContractParams(
                commitment,
                proof,
                indices,
                values,
            )
            expect.assertions(1)
            try {
                await verifierContract.verifyMulti(
                    params.commitment,
                    [
                        params.proof[1],
                        params.proof[0],
                    ],
                    params.indices,
                    params.values,
                    params.iCoeffs,
                    params.zCoeffs,
                )
            } catch {
                expect(true).toBeTruthy()
            }
        })

        it('should reject a valid proof with invalid iCoeffs and zCoeffs', async () => {
            const indices = [BigInt(0), BigInt(2)]
            const proof = genMultiProof(coefficients, indices)
            const values = indices.map((x) => field.evalPolyAt(field.newVectorFrom(coefficients), x))
            expect(verifyMulti(commitment, proof, indices, values)).toBeTruthy()

            const params = genMultiVerifierContractParams(
                commitment,
                proof,
                indices,
                values,
            )

            expect.assertions(2)
            try {
                await verifierContract.verifyMulti(
                    params.commitment,
                    params.proof,
                    params.indices,
                    params.values,
                    [0],
                    params.zCoeffs,
                )
            } catch (e) {
                expect(e.message.endsWith('Verifier.verifyMulti: invalid _iCoeffs')).toBeTruthy()
            }
            try {
                await verifierContract.verifyMulti(
                    params.commitment,
                    params.proof,
                    params.indices,
                    params.values,
                    params.iCoeffs,
                    [0],
                )
            } catch (e) {
                expect(e.message.endsWith('Verifier.verifyMulti: invalid _zCoeffs')).toBeTruthy()
            }
        })

        it('should pass a stress test', async () => {
            const NUM_COEFFS = 129
            let coeffs: bigint[] = []
            let indices: bigint[] = []
            let values: bigint[] = []
            for (let i = 0; i < NUM_COEFFS; i ++) {
                coeffs.push(BigInt(field.rand()))
            }

            for (let i = 0; i < NUM_COEFFS - 1; i ++) {
                indices.push(BigInt(i))
                values.push(BigInt(field.evalPolyAt(field.newVectorFrom(coeffs), BigInt(i))))
            }

            const comm = commit(coeffs)
            const proof = genMultiProof(coeffs, indices)
            expect(verifyMulti(comm, proof, indices, values))

            const params = genMultiVerifierContractParams(
                commitment,
                proof,
                indices,
                values,
            )

            const tx = await verifierContract.verifyMultiBenchmark(
                params.commitment,
                params.proof,
                params.indices,
                params.values,
                params.iCoeffs,
                params.zCoeffs,
                { gasLimit: 10000000 },
            )
            const receipt = await tx.wait()
            const savings = 1 - (parseInt(receipt.gasUsed.toString(), 10) / (params.indices.length * 178078))
            console.log(params.indices.length, receipt.gasUsed.toString(), savings)
        })
    })

    describe('single-point proof verification', () => {
        it('should verify a valid proof', async () => {
            expect.assertions(degree)
            for (let i = 0; i < degree; i ++) {
                const proof = genProof(coefficients, i)
                const yVal = values[i]
                const params = genVerifierContractParams(commitment, proof, i, yVal)

                const result = await verifierContract.verify(
                    params.commitment,
                    params.proof,
                    params.index,
                    params.value,
                )
                expect(result).toBeTruthy()
            }
        })

        it('should not verify an invalid proof', async() => {
            const i = 0
            const proof = genProof(coefficients, i)
            const yVal = values[i]
            const params = genVerifierContractParams(commitment, proof, i, yVal)

            const result = await verifierContract.verify(
                params.commitment,
                ['0x0', '0x0'],
                params.index,
                params.value,
            )
            expect(result).toBeFalsy()
        })

        it('should not verify an invalid commitment', async() => {
            const i = 0
            const proof = genProof(coefficients, i)
            const yVal = values[i]
            const params = genVerifierContractParams(commitment, proof, i, yVal)

            const result = await verifierContract.verify(
                ['0x0', '0x0'],
                params.proof,
                params.index,
                params.value,
            )
            expect(result).toBeFalsy()
        })
    })
})
