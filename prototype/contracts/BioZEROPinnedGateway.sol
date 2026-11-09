// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./UBCAAuthGateway.sol";

/// @notice Local artifact-pinned BioZERO profile for the existing 128/512-D
///         benchmark circuits. Re-pin these constants for a journal ceremony.
/// @dev Verifier hashes are optimized solc 0.8.36 Shanghai deployed bytecode
///      with metadata.bytecodeHash="none". This makes the hashes independent
///      of the compilation-unit source set, unlike Solidity's default IPFS
///      metadata hash. Exact compiler settings remain part of the profile.
///      hashes; circuit hashes are SHA-256 of the compiled R1CS files. The
///      artifact manifest checks their correspondence to the benchmark zkeys.
contract BioZEROPinnedGateway is UBCAAuthGateway {
    bytes32 public constant VERIFIER128_CODEHASH =
        0x2f53d382abcb18f4ce04cf591304bb4819c11ea43f6a50f2cbce657102f4f26b;
    bytes32 public constant VERIFIER512_CODEHASH =
        0x58d747996cfbab413e6d802b592e58ce48c4daa7acdd05b903377e9a6940f537;
    bytes32 public constant CIRCUIT128_R1CS_SHA256 =
        0x02ec476683bc75358db02aa216c8a02b5da4545049f8cf1a9d130fa1eada7dea;
    bytes32 public constant CIRCUIT512_R1CS_SHA256 =
        0xc214cefdd0bbbdbd9f18f5f8d98db9812741b245e050eec187525cd48abf4bb3;

    uint32 public immutable pinnedDimension;
    bytes32 public immutable pinnedCircuitHash;

    constructor(address verifierAddress) UBCAAuthGateway(verifierAddress) {
        bytes32 actualCodeHash = verifierAddress.codehash;
        if (actualCodeHash == VERIFIER128_CODEHASH) {
            pinnedDimension = 128;
            pinnedCircuitHash = CIRCUIT128_R1CS_SHA256;
        } else if (actualCodeHash == VERIFIER512_CODEHASH) {
            pinnedDimension = 512;
            pinnedCircuitHash = CIRCUIT512_R1CS_SHA256;
        } else {
            revert InvalidVerifier();
        }
    }

    function _validateCanonicalPolicy(CanonicalPolicySpec calldata spec)
        internal
        view
        override
    {
        super._validateCanonicalPolicy(spec);
        if (
            spec.dimension != pinnedDimension ||
            spec.circuitHash != pinnedCircuitHash
        ) revert InvalidMatchPolicy();
    }
}
