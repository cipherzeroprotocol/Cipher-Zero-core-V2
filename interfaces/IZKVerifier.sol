// SPDX-License-Identifier: MIT

pragma solidity ^0.8.26;

interface IZKVerifier {
    function verifyProof(uint256[8] calldata proof, uint256[1] calldata input) external view returns (bool);
      /**
     * @notice Verify a transfer proof
     * @param nullifier Nullifier to prevent replay attacks
     * @param commitment Commitment to the transfer details
     * @param amount Amount being transferred
     * @param sender Sender address
     * @param recipient Recipient address
     * @param proof ZK proof data
     * @return bool True if proof is valid
     */
    function verifyTransferProof(
        bytes32 nullifier,
        bytes32 commitment,
        uint256 amount,
        address sender,
        address recipient,
        bytes calldata proof
    ) external view returns (bool);

    /**
     * @notice Verify a pool creation proof
     * @param amount Amount to deposit in pool
     * @param creator Pool creator address
     * @param proof ZK proof data
     * @return bool True if proof is valid
     */
    function verifyPoolCreationProof(
        uint256 amount,
        address creator,
        bytes calldata proof
    ) external view returns (bool);

    /**
     * @notice Generate a mixing proof for privacy pools
     * @param merkleRoot Current merkle root
     * @param participantCount Number of participants
     * @param denomination Pool denomination
     * @return bytes Generated proof data
     */
    function generateMixProof(
        bytes32 merkleRoot,
        uint256 participantCount,
        uint256 denomination
    ) external view returns (bytes memory);

    /**
     * @notice Verify a mixing proof
     * @param proof ZK proof data
     * @param merkleRoot Current merkle root
     * @param participantCount Number of participants
     * @param denomination Pool denomination
     * @return bool True if proof is valid
     */
    function verifyMixProof(
        bytes calldata proof,
        bytes32 merkleRoot,
        uint256 participantCount,
        uint256 denomination
    ) external view returns (bool);

    /**
     * @notice Verify a withdrawal proof
     * @param proof ZK proof data
     * @param nullifier Withdrawal nullifier
     * @param merkleRoot Current merkle root
     * @param denomination Pool denomination
     * @param withdrawer Address performing withdrawal
     * @return bool True if proof is valid
     */
    function verifyWithdrawalProof(
        bytes calldata proof,
        bytes32 nullifier,
        bytes32 merkleRoot,
        uint256 denomination,
        address withdrawer
    ) external view returns (bool);

    /**
     * @notice Update verifier parameters
     * @param newParams New verification parameters
     */
    function updateVerificationParameters(bytes calldata newParams) external;

    /**
     * @notice Check if an account is verified
     * @param account Address to check
     * @return bool True if account is verified
     */
    function isVerified(address account) external view returns (bool);
}