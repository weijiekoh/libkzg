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

        require(success, "pairing-add-failed");
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
        require (success, "pairing-mul-failed");
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

    uint256 constant BABYJUB_P = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

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

    Pairing.G1Point SRS_G1_0 = Pairing.G1Point({ X: 1, Y: 2 });

    // A test SRS value using the secret 1234. Do not use it in production!
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

    /*
     * Verifies a single-point evaluation of a polynominal using the KZG
     * commitment scheme.
     *    - p(X) is a polynominal
     *    - _value = p(_index) 
     *    - commitment = commit(p)
     *    - proof = genProof(p, _index, _value)
     * Returns true if and only if the following hold:
     *     - e(commitment - commit([_value]), G2.g) == e(proof, commit([0, 1]) - zCommit)
     * @param _commitmentX The X-coordinate of the commitment.
     * @param _commitmentY The Y-coordinate of the commitment.
     * @param _proofX The X-coordinate of the proof.
     * @param _proofY The Y-coordinate of the proof.
     * @param _index The x-value at which to evaluate the polynominal.
     * @param _value The result of the polynominal evaluation.
     */
    function verifyKZG(
        uint256 _commitmentX,
        uint256 _commitmentY,
        uint256 _proofX,
        uint256 _proofY,
        uint256 _index,
        uint256 _value
    ) public view returns (bool) {
        // Make sure each parameter is less than the prime q
        require(_commitmentX < BABYJUB_P, "Verifier.verifyKZG: commitmentX is out of range");
        require(_commitmentY < BABYJUB_P, "Verifier.verifyKZG: commitmentY is out of range");
        require(_proofX < BABYJUB_P, "Verifier.verifyKZG: proofX is out of range");
        require(_proofY < BABYJUB_P, "Verifier.verifyKZG: proofY is out of range");
        require(_index < BABYJUB_P, "Verifier.verifyKZG: index is out of range");
        require(_value < BABYJUB_P, "Verifier.verifyKZG: value is out of range");

        // Check that 
        //     e(commitment - aCommit, G2.g) == e(proof, xCommit - zCommit)
        //     e(commitment - aCommit, G2.g) / e(proof, xCommit - zCommit) == 1
        //     e(commitment - aCommit, G2.g) * e(proof, xCommit - zCommit) ^ -1 == 1
        //     e(commitment - aCommit, G2.g) * e(-proof, xCommit - zCommit) == 1
        // where:
        //     aCommit = commit([_value]) = SRS_G1_0 * _value
        //     xCommit = commit([0, 1]) = SRS_G2_1
        //     zCommit = commit([_index]) = SRS_G2_1 * _index

        // To avoid having to perform an expensive operation in G2 to compute
        // xCommit - zCommit, we instead check the equivalent equation:
        //     e(commitment - aCommit, G2.g) * e(-proof, xCommit) * e(-proof, -zCommit) == 1
        //     e(commitment - aCommit, G2.g) * e(-proof, xCommit) * e(proof, zCommit) == 1
        //     e(commitment - aCommit, G2.g) * e(-proof, xCommit) * e(index * proof, G2.g) == 1
        //     e((index * proof) + (commitment - aCommit), G2.g) * e(-proof, xCommit) == 1


        // Compute commitment - aCommitment
        Pairing.G1Point memory commitmentMinusA = Pairing.plus(
            Pairing.G1Point({ X: _commitmentX, Y: _commitmentY }),
            Pairing.negate(
                Pairing.mulScalar(SRS_G1_0, _value)
            )
        );

        // The proof as a G1 point
        Pairing.G1Point memory proofPoint = 
            Pairing.G1Point({
                X: _proofX,
                Y: _proofY
            });

        // Negate the proof
        Pairing.G1Point memory negProof = Pairing.negate(proofPoint);

        // Compute index * proof
        Pairing.G1Point memory indexMulProof = Pairing.mulScalar(proofPoint, _index);

        // Returns true if and only if
        // e((index * proof) + (commitment - aCommitment), G2.g) * e(-proof, xCommit) == 1
        return Pairing.pairing(
            Pairing.plus(indexMulProof, commitmentMinusA),
            g2Generator,
            negProof,
            SRS_G2_1
        );
    }
}
