// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

interface IVerifier {
    /**
     * @notice Verify a file proof
     * @param fileHash Hash of the file
     * @param owner Address of the file owner
     * @param proof Zero-knowledge proof
     * @return bool True if proof is valid
     */
    function verifyFileProof(
        bytes32 fileHash,
        address owner,
        bytes calldata proof
    ) external view returns (bool);

    /**
     * @notice Verify possession proof
     * @param fileHash Hash of the file
     * @param claimer Address claiming possession
     * @param proof Zero-knowledge proof
     * @return bool True if proof is valid
     */
    function verifyPossessionProof(
        bytes32 fileHash,
        address claimer,
        bytes calldata proof
    ) external view returns (bool);
    function verifyBridgeProof(
        bytes32 messageHash,
        bytes32 nullifier,
        address sender,
        address recipient,
        bytes memory proof
    ) external view returns (bool);
}