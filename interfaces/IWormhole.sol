// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IWormhole {
    struct VM {
        uint8 version;
        uint32 timestamp;
        uint32 nonce;
        uint16 emitterChainId;
        bytes32 emitterAddress;
        uint64 sequence;
        uint8 consistencyLevel;
        bytes payload;
        uint32 guardianSetIndex;
        bytes signatures;
        bytes32 hash;
    }

    function parseAndVerifyVM(bytes calldata encodedVM) 
        external 
        view 
        returns (
            VM memory vm,
            bool valid,
            string memory reason
        );
}