// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "../interfaces/IWormhole.sol";
import "../interfaces/IVerifier.sol";
import "../interfaces/IBridgeVerifier.sol";

contract BridgeVerifier is IBridgeVerifier, Ownable, ReentrancyGuard, Pausable {
    // Constants
    uint32 public constant GUARDIAN_SET_EXPIRY = 24 hours;
    uint16 public constant CURRENT_CHAIN_ID = 1; // Solana chain ID
    uint8 public constant CONSISTENCY_LEVEL = 1;
    uint256 public constant MSG_TIMEOUT = 24 hours;

    // State variables
    IWormhole public wormhole;
    IVerifier public verifier;
    
    mapping(bytes32 => CrossChainMessage) public messages;
    mapping(bytes32 => bool) public nullifierUsed;
    mapping(uint32 => GuardianSet) public guardianSets;
    mapping(bytes32 => uint256) public messageTimestamps;
    
    uint32 public currentGuardianSetIndex;
    VerifyingKey private verifyingKey;

    constructor(
        address initialOwner,
        address _wormhole,
        address _verifier,
        address[] memory _guardians,
        uint256[2] memory _alpha,
        uint256[2][2] memory _beta,
        uint256[2] memory _gamma,
        uint256[2] memory _delta,
        uint256[2][] memory _ic
    ) Ownable(initialOwner) {
        require(_wormhole != address(0), "Invalid wormhole address");
        require(_verifier != address(0), "Invalid verifier address");
        require(_guardians.length > 0, "Empty guardian set");

        wormhole = IWormhole(_wormhole);
        verifier = IVerifier(_verifier);
        
        verifyingKey = VerifyingKey({
            alpha: _alpha,
            beta: _beta,
            gamma: _gamma,
            delta: _delta,
            ic: _ic
        });

        _updateGuardianSet(_guardians);
    }

    function verifyMessage(
        bytes memory encodedVM,
        bytes memory proof
    ) external override nonReentrant whenNotPaused {
        require(encodedVM.length > 0, "Empty VM");
        require(proof.length > 0, "Empty proof");

        // Parse and verify Wormhole message
        (
            IWormhole.VM memory vm,
            bool valid,
            string memory reason
        ) = wormhole.parseAndVerifyVM(encodedVM);
        
        require(valid, reason);
        require(
            vm.emitterChainId != CURRENT_CHAIN_ID,
            "Invalid source chain"
        );

        // Decode payload
        (
            bytes32 messageHash,
            bytes32 nullifier,
            address sender,
            address recipient,
            bytes memory payload
        ) = decodePayload(vm.payload);

        require(!nullifierUsed[nullifier], "Nullifier used");
        require(
            verifier.verifyBridgeProof(
                messageHash,
                nullifier,
                sender,
                recipient,
                proof
            ),
            "Invalid proof"
        );

        messages[messageHash] = CrossChainMessage({
            messageHash: messageHash,
            sourceChain: vm.emitterChainId,
            targetChain: CURRENT_CHAIN_ID,
            payloadHash: keccak256(payload),
            nullifier: nullifier,
            sender: sender,
            recipient: recipient,
            executed: false,
            timestamp: block.timestamp,
            proof: keccak256(proof)
        });

        nullifierUsed[nullifier] = true;
        messageTimestamps[messageHash] = block.timestamp;

        emit MessageVerified(
            messageHash,
            vm.emitterChainId,
            CURRENT_CHAIN_ID,
            sender,
            recipient,
            block.timestamp
        );

        emit ProofVerified(
            messageHash,
            keccak256(proof),
            block.timestamp
        );
    }

    function decodePayload(
    bytes memory payload
) public pure override returns (
    bytes32 messageHash,
    bytes32 nullifier,
    address sender,
    address recipient,
    bytes memory data
) {
    require(payload.length >= 128, "Invalid payload length");

    // Use assembly to efficiently decode fixed-size data
    assembly {
        // Load message hash (first 32 bytes)
        messageHash := mload(add(payload, 32))
        
        // Load nullifier (next 32 bytes)
        nullifier := mload(add(payload, 64))
        
        // Load sender address (next 20 bytes, but we load full 32 bytes and mask)
        sender := and(mload(add(payload, 96)), 0xffffffffffffffffffffffffffffffffffffffff)
        
        // Load recipient address (next 20 bytes, but we load full 32 bytes and mask)
        recipient := and(mload(add(payload, 128)), 0xffffffffffffffffffffffffffffffffffffffff)
    }

    // Copy remaining bytes for data
    uint256 dataLength = payload.length - 128;
    data = new bytes(dataLength);
    
    if (dataLength > 0) {
        assembly {
            // Copy remaining bytes to data
            let dataPtr := add(data, 32)  // Skip length field
            let payloadPtr := add(payload, 160)  // Skip first 128 bytes + 32 bytes length field
            
            // Copy dataLength bytes
            for { let i := 0 } lt(i, dataLength) { i := add(i, 32) } {
                if lt(sub(dataLength, i), 32) {
                    // Last iteration - copy remaining bytes
                    let remaining := sub(dataLength, i)
                    mstore(add(dataPtr, i), 
                           and(
                               mload(add(payloadPtr, i)),
                               sub(shl(mul(8, sub(32, remaining)), 1), 1)
                           ))
                    break
                }
                mstore(add(dataPtr, i), mload(add(payloadPtr, i)))
            }
        }
    }

    return (messageHash, nullifier, sender, recipient, data);
}

    function updateGuardianSet(
        address[] memory newGuardians
    ) external override onlyOwner {
        _updateGuardianSet(newGuardians);
    }

    function _updateGuardianSet(
        address[] memory newGuardians
    ) internal {
        require(newGuardians.length > 0, "Empty guardian set");

        if (currentGuardianSetIndex > 0) {
            GuardianSet storage oldSet = guardianSets[currentGuardianSetIndex];
            oldSet.expirationTime = uint32(block.timestamp + GUARDIAN_SET_EXPIRY);
            oldSet.isActive = false;
        }

        currentGuardianSetIndex++;
        GuardianSet storage newSet = guardianSets[currentGuardianSetIndex];
        newSet.guardians = newGuardians;
        newSet.isActive = true;
        newSet.expirationTime = 0;

        emit GuardianSetUpdated(
            currentGuardianSetIndex,
            newGuardians,
            block.timestamp
        );
    }

    function isMessageTimedOut(
        bytes32 messageHash
    ) public view override returns (bool) {
        uint256 timestamp = messageTimestamps[messageHash];
        if (timestamp == 0) return false;
        return block.timestamp > timestamp + MSG_TIMEOUT;
    }

    function getGuardians() external view override returns (address[] memory) {
        return guardianSets[currentGuardianSetIndex].guardians;
    }

    function getVerifyingKey() external view onlyOwner returns (VerifyingKey memory) {
        return verifyingKey;
    }

    function updateVerifyingKey(
        uint256[2] memory _alpha,
        uint256[2][2] memory _beta,
        uint256[2] memory _gamma,
        uint256[2] memory _delta,
        uint256[2][] memory _ic
    ) external onlyOwner {
        verifyingKey = VerifyingKey({
            alpha: _alpha,
            beta: _beta,
            gamma: _gamma,
            delta: _delta,
            ic: _ic
        });
    }

    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }
}