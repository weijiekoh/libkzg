import * as fs from 'fs'
import * as argparse from 'argparse'

const processTauG1 = (data: string) => {
    const regex = /G1\(x=Fq\((0x[a-zA-Z0-9]+)\), y=Fq\((0x[a-zA-Z0-9]+)\)\)/
    const result: string[][] = []
    for (const line of data.split('\n')) {
        const m = line.match(regex)
        if (m) {
            result.push([m[1], m[2]])
        }
    }
    return result
}

const processTauG2 = (data: string) => {
    const result: string[][] = []
    const regex = /G2\(x=Fq2\(Fq\((0x[a-zA-Z0-9]+)\) \+ Fq\((0x[a-zA-Z0-9]+)\) \* u\), y=Fq2\(Fq\((0x[a-zA-Z0-9]+)\) \+ Fq\((0x[a-zA-Z0-9]+)\) \* u\)\)/
    for (const line of data.split('\n')) {
        const m = line.match(regex)
        if (m) {
            result.push([m[1], m[2], m[3], m[4]])
        }
    }
    return result
}

if (require.main === module) {
    const parser = new argparse.ArgumentParser({ 
        description: 'Convert PPOT values to JSON',
    })

    parser.addArgument(
        ['-t', '--type'],
        {
            action: 'store',
            choices: ['taug1', 'taug2'],
            required: true,
        },
    )

    parser.addArgument(
        ['-i', '--input'],
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

    const args = parser.parseArgs()

    const data = fs.readFileSync(args.input).toString()

    let output

    if (args.type === 'taug1') {
        output = processTauG1(data)
    } else if (args.type === 'taug2') {
        output = processTauG2(data)
    } else {
        console.error('Unexpected -t/--type value provided. Exiting.')
        process.exit(1)
    }

    const outputJson = JSON.stringify(output)
    fs.writeFileSync(args.output, outputJson)
}
