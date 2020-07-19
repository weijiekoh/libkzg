import * as assert from 'assert'
import * as fs from 'fs'
import * as path from 'path'
import * as argparse from 'argparse'

if (require.main === module) {
    const parser = new argparse.ArgumentParser({ 
        description: 'Generate Constants.sol',
    })

    parser.addArgument(
        ['-t', '--template'],
        {
            action: 'store',
            required: true,
        },
    )

    parser.addArgument(
        ['-o', '--output'],
        {
            action: 'store',
            required: true,
        },
    )

    parser.addArgument(
        ['-g1', '--tau-g1'],
        {
            action: 'store',
            required: true,
        },
    )

    parser.addArgument(
        ['-g2', '--tau-g2'],
        {
            action: 'store',
            required: true,
        },
    )

    parser.addArgument(
        ['-a', '--num-g1'],
        {
            action: 'store',
            required: false,
            defaultValue: 129,
        },
    )

    parser.addArgument(
        ['-b', '--num-g2'],
        {
            action: 'store',
            required: false,
            defaultValue: 2,
        },
    )

    const args = parser.parseArgs()

    const NUM_G1_POINTS = args.num_g1
    const NUM_G2_POINTS = args.num_g2
    const TAU_G1_PATH = path.join(process.cwd(), args.tau_g1)
    const TAU_G2_PATH = path.join(process.cwd(), args.tau_g2)

    // Import the points
    const tauG1 = require(TAU_G1_PATH)
    const tauG2 = require(TAU_G2_PATH)

    // Extract the points
    const srsG1X: string[] = []
    const srsG1Y: string[] = []
    for (let i = 0; i < NUM_G1_POINTS; i ++) {
        srsG1X.push(tauG1[i][0])
        srsG1Y.push(tauG1[i][1])
    }

    const srsG2X0: string[] = []
    const srsG2X1: string[] = []
    const srsG2Y0: string[] = []
    const srsG2Y1: string[] = []
    for (let i = 0; i < NUM_G2_POINTS; i ++) {
        srsG2X0.push(tauG2[i][1])
        srsG2X1.push(tauG2[i][0])
        srsG2Y0.push(tauG2[i][3])
        srsG2Y1.push(tauG2[i][2])
    }

    let SRS_G1_X_VALUES = ''
    let SRS_G1_Y_VALUES = ''

    for (let i = 0; i < NUM_G1_POINTS; i ++) {
        SRS_G1_X_VALUES += `        uint256(${srsG1X[i]})`
        SRS_G1_Y_VALUES += `        uint256(${srsG1Y[i]})`
        if (i !== NUM_G1_POINTS - 1) {
            SRS_G1_X_VALUES += ',\n'
            SRS_G1_Y_VALUES += ',\n'
        }
    }

    let SRS_G2_X_0_VALUES = ''
    let SRS_G2_Y_0_VALUES = ''
    let SRS_G2_X_1_VALUES = ''
    let SRS_G2_Y_1_VALUES = ''
    for (let i = 0; i < NUM_G2_POINTS; i ++) {
        SRS_G2_X_0_VALUES += `        uint256(${srsG2X0[i]})`
        SRS_G2_X_1_VALUES += `        uint256(${srsG2X1[i]})`
        SRS_G2_Y_0_VALUES += `        uint256(${srsG2Y0[i]})`
        SRS_G2_Y_1_VALUES += `        uint256(${srsG2Y1[i]})`
        if (i !== NUM_G2_POINTS - 1) {
            SRS_G2_X_0_VALUES += ',\n'
            SRS_G2_X_1_VALUES += ',\n'
            SRS_G2_Y_0_VALUES += ',\n'
            SRS_G2_Y_1_VALUES += ',\n'
        }
    }

    // Read the template
    let template = fs.readFileSync(path.join(process.cwd(), args.template)).toString()
    
    // Replace values
    template = template.replace('        // SRS_G1_X_VALUES', SRS_G1_X_VALUES)
    template = template.replace('        // SRS_G1_Y_VALUES', SRS_G1_Y_VALUES)
    template = template.replace('        // SRS_G2_X_0_VALUES', SRS_G2_X_0_VALUES)
    template = template.replace('        // SRS_G2_X_1_VALUES', SRS_G2_X_1_VALUES)
    template = template.replace('        // SRS_G2_Y_0_VALUES', SRS_G2_Y_0_VALUES)
    template = template.replace('        // SRS_G2_Y_1_VALUES', SRS_G2_Y_1_VALUES)

    // Write to the contract file
    fs.writeFileSync(path.join(process.cwd(), args.output), template)
}
