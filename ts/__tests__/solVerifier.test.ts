const Verifier = require('../../compiled/Verifier.json')
import * as ethers from 'ethers'
import * as etherlime from 'etherlime-lib'
import {
    genBabyJubField,
    genCoefficients,
    commit,
    genProof,
    verify,
    genVerifierContractParams,
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

    it('should verify a valid proof', async() => {
        expect.assertions(degree)
        for (let i = 0; i < degree; i ++) {
            const proof = genProof(coefficients, i)
            const yVal = values[i]
            const params = genVerifierContractParams(commitment, proof, i, yVal)

            const result = await verifierContract.verifyKZG(
                params.commitmentX,
                params.commitmentY,
                params.proofX,
                params.proofY,
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

        const result = await verifierContract.verifyKZG(
            params.commitmentX,
            params.commitmentY,
            '0x0',
            '0x0',
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

        const result = await verifierContract.verifyKZG(
            '0x0',
            '0x0',
            params.proofX,
            params.proofY,
            params.index,
            params.value,
        )
        expect(result).toBeFalsy()
    })
})
