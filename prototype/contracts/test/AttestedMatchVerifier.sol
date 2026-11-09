// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Strong local comparison: the authorized module attests a full match.
/// @dev Uses the existing verifier ABI only to keep the gateway identical.
///      pA carries (r,s), pB[0][0] carries v; other proof slots must be zero.
///      These words are NOT a Groth16 proof. A real attested matcher must check
///      the policy, both commitment openings, ranges, and the distance relation
///      before signing. The evaluation uses a software model of that module.
contract AttestedMatchVerifier {
    address public immutable matcher;

    constructor(address matcherAddress) {
        require(matcherAddress != address(0));
        matcher = matcherAddress;
    }

    function matchDigest(uint256[5] calldata signals) public view returns (bytes32) {
        return keccak256(abi.encode(
            "UBCA/attested-match/v1", block.chainid, address(this), signals
        ));
    }

    function verifyProof(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256[5] calldata signals
    ) external view returns (bool) {
        if (
            (pB[0][0] != 27 && pB[0][0] != 28) ||
            pB[0][1] != 0 || pB[1][0] != 0 || pB[1][1] != 0 ||
            pC[0] != 0 || pC[1] != 0 ||
            pA[1] > 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0
        ) return false;
        return ecrecover(matchDigest(signals), uint8(pB[0][0]),
            bytes32(pA[0]), bytes32(pA[1])) == matcher;
    }
}
