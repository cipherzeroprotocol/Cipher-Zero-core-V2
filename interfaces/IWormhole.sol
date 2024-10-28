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

    /**
     * @notice Publish a message to be attested by the Wormhole network
     * @param nonce Unique nonce for the message
     * @param message Message bytes to be attested
     * @param consistencyLevel Desired finality (0 = instant, 1 = finalized)
     * @return sequence Sequence number of the published message
     */
    function publishMessage(
        uint32 nonce,
        bytes memory message,
        uint8 consistencyLevel
    ) external payable returns (uint64 sequence);

    /**
     * @notice Get the fee required to publish a message
     * @return fee The required fee in wei
     */
    function messageFee() external view returns (uint256);

    /**
     * @notice Parse and verify a VAA (Verified Action Approval)
     * @param encodedVM The encoded VAA
     * @return vm The parsed VM struct
     * @return valid Whether the VAA is valid
     * @return reason Reason for invalidity if not valid
     */
    function parseAndVerifyVM(bytes calldata encodedVM) 
        external 
        view 
        returns (
            VM memory vm,
            bool valid,
            string memory reason
        );
}