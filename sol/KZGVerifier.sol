// Modified from https://github.com/appliedzkp/semaphore/blob/master/contracts/sol/verifier.sol

pragma solidity ^0.5.0;

library Pairing {

    uint256 constant PRIME_Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    struct G1Point {
        uint256 X;
        uint256 Y;
    }

    // Encoding of field elements is: X[0] * z + X[1]
    struct G2Point {
        uint256[2] X;
        uint256[2] Y;
    }

    /*
     * @return The negation of p, i.e. p.plus(p.negate()) should be zero. 
     */
    function negate(G1Point memory p) internal pure returns (G1Point memory) {

        // The prime q in the base field F_q for G1
        if (p.X == 0 && p.Y == 0) {
            return G1Point(0, 0);
        } else {
            return G1Point(p.X, PRIME_Q - (p.Y % PRIME_Q));
        }
    }

    /*
     * @return The sum of two points of G1
     */
    function plus(
        G1Point memory p1,
        G1Point memory p2
    ) internal view returns (G1Point memory r) {

        uint256[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;

        // solium-disable-next-line security/no-inline-assembly
        assembly {
            success := staticcall(sub(gas, 2000), 6, input, 0xc0, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }

        require(success,"pairing-add-failed");
    }

    /*
     * @return The product of a point on G1 and a scalar, i.e.
     *         p == p.scalar_mul(1) and p.plus(p) == p.scalar_mul(2) for all
     *         points p.
     */
    function mulScalar(G1Point memory p, uint256 s) internal view returns (G1Point memory r) {

        uint256[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            success := staticcall(sub(gas, 2000), 7, input, 0x80, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require (success,"pairing-mul-failed");
    }

    /* @return The result of computing the pairing check
     *         e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
     *         For example,
     *         pairing([P1(), P1().negate()], [P2(), P2()]) should return true.
     */
    function pairing(
        G1Point memory a1,
        G2Point memory a2,
        G1Point memory b1,
        G2Point memory b2
    ) internal view returns (bool) {

        G1Point[2] memory p1 = [a1, b1];
        G2Point[2] memory p2 = [a2, b2];

        uint256 inputSize = 12;
        uint256[] memory input = new uint256[](inputSize);

        for (uint256 i = 0; i < 2; i++) {
            uint256 j = i * 6;
            input[j + 0] = p1[i].X;
            input[j + 1] = p1[i].Y;
            input[j + 2] = p2[i].X[0];
            input[j + 3] = p2[i].X[1];
            input[j + 4] = p2[i].Y[0];
            input[j + 5] = p2[i].Y[1];
        }

        uint256[1] memory out;
        bool success;

        // solium-disable-next-line security/no-inline-assembly
        assembly {
            success := staticcall(sub(gas, 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }

        require(success,"pairing-opcode-failed");

        return out[0] != 0;
    }
}

contract Verifier {

    using Pairing for *;

    uint256 constant SNARK_SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 constant PRIME_Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    Pairing.G2Point g2Generator = Pairing.G2Point({
        X: [
            uint256(11559732032986387107991004021392285783925812861821192530917403151452391805634), 
            uint256(10857046999023057135944570762232829481370756359578518086990519993285655852781) 
        ],
        Y: [
            uint256(4082367875863433681332203403145435568316851327593401208105741076214120093531),
            uint256(8495653923123431417604973247489272438418190587263600148770280649306958101930) 
        ]

    });

    // These are test SRS values using a secret 1234
    Pairing.G1Point SRS_G1_0 = Pairing.G1Point({ X: 1, Y: 2 });

    Pairing.G2Point SRS_G2_1 = Pairing.G2Point({
        X: [
            uint256(20581924060851364827089112084266116502083385887431055789664064343317555539927), 
            uint256(11092999225633600247987762624347164490249105779527674870198751554395839697955) 
        ],
        Y: [
            uint256(18968046579869378264211454225940124683613790899808490038348890384662573052093),
            uint256(745165978236660430257472951680766366710880332450354657023528496579863883583) 
        ]
    });

    function verifyKZG(
        uint256 commitmentX,
        uint256 commitmentY,
        uint256 proofX,
        uint256 proofY,
        uint256 index,
        uint256 value
    ) public view returns (bool) {
        // Make sure each parameter is less than the prime q
        require(commitmentX < SNARK_SCALAR_FIELD, "Verifier.verifyKZG: commitmentX is out of range");
        require(commitmentY < SNARK_SCALAR_FIELD, "Verifier.verifyKZG: commitmentY is out of range");
        require(proofX < SNARK_SCALAR_FIELD, "Verifier.verifyKZG: proofX is out of range");
        require(proofY < SNARK_SCALAR_FIELD, "Verifier.verifyKZG: proofY is out of range");
        require(index < SNARK_SCALAR_FIELD, "Verifier.verifyKZG: index is out of range");
        require(value < SNARK_SCALAR_FIELD, "Verifier.verifyKZG: value is out of range");

        // Check that 
        // e(commitment - aCommitment, G2.g) == e(proof, xCommit - zCommit)
        // which is equivalent to:
        // e((index * proof) + (commitment - aCommitment), G2.g) * e(-proof, xCommit) == 1

        // commitment - aCommitment
        Pairing.G1Point memory commitmentMinusA = Pairing.plus(
            Pairing.G1Point({ X: commitmentX, Y: commitmentY }),
            Pairing.negate(
                Pairing.mulScalar(SRS_G1_0, value)
            )
        );

        // proof
        Pairing.G1Point memory proofPoint = 
            Pairing.G1Point({
                X: proofX,
                Y: proofY
            });

        // -proof
        Pairing.G1Point memory negProof = Pairing.negate(proofPoint);

        // xCommit
        Pairing.G2Point memory xCommit = SRS_G2_1;

        // index * proof
        Pairing.G1Point memory indexMulProof = Pairing.mulScalar(proofPoint, index);

        // e((index * proof) + (commitment - aCommitment), G2.g) * e(-proof, xCommit) == 1
        return Pairing.pairing(
            Pairing.plus(indexMulProof, commitmentMinusA),
            g2Generator,
            negProof,
            xCommit
        );
    }
}
