// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

interface IVerifier {
          function verifyPieceProof(
        bytes32 pieceHash,
        bytes32 piecesRoot,
        bytes calldata proof
    ) external view returns (bool);

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
    
    function verifyFileProof(
        bytes32 fileCommitment, 
        bytes calldata proof,
        address sender
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
    function verifyMessageProof(
        bytes32 commitment,
        bytes32 nullifier,
        address sender,
        address recipient,
        bytes calldata encryptedContent,
        bytes calldata proof
    ) external view returns (bool);



     /**
     * @notice Verify deposit proof
     * @param commitment The note commitment
     * @param amount The deposit amount
     * @param sender The depositor address
     * @param proof The zero-knowledge proof
     * @return bool True if proof is valid
     */
    function verifyDepositProof(
        bytes32 commitment,
        uint256 amount,
        address sender,
        bytes calldata proof
    ) external view returns (bool);

    /**
     * @notice Verify withdrawal proof
     * @param nullifier The note nullifier
     * @param commitment The note commitment
     * @param recipient The withdrawal recipient
     * @param amount The withdrawal amount
     * @param proof The zero-knowledge proof
     * @return bool True if proof is valid
     */
    function verifyWithdrawProof(
        bytes32 nullifier,
        bytes32 commitment,
        address recipient,
        uint256 amount,
        bytes calldata proof
    ) external view returns (bool);

    /**
     * @notice Verify transfer proof
     * @param nullifierFrom Input note nullifier
     * @param commitmentFrom Input note commitment
     * @param commitmentTo Output note commitment
     * @param amount Transfer amount
     * @param proof Zero-knowledge proof
     * @return bool True if proof is valid
     */
    function verifyTransferProof(
        bytes32 nullifierFrom,
        bytes32 commitmentFrom,
        bytes32 commitmentTo,
        uint256 amount,
        bytes calldata proof
    ) external view returns (bool);
      
    
    function verifyRelationshipProof(
        bytes32 peerId1,
        bytes32 peerId2,
        bytes calldata proof
    ) external view returns (bool);
    
    function verifyMisbehaviorProof(
        bytes32 peerId,
        bytes calldata proof
    ) external view returns (bool);
    
   




    function verifyIdentityProof(
        bytes32 commitment,
        bytes32 proof
    ) external view returns (bool);
    
    function verifyStatusProof(
        bytes32 commitment,
        bytes32 proof
    ) external view returns (bool);
    
    function verifyReputationProof(
        bytes32 commitment,
        bytes32 proof
    ) external view returns (bool);
    
    function verifyBanProof(
        bytes32 commitment,
        bytes32 proof
    ) external view returns (bool);
    
    function verifyMixingProof(
        bytes32 sessionId,
        bytes32 proof
    ) external view returns (bool);
    function verifyIdentityProof(
        bytes32 commitment,
        bytes calldata proof
    ) external view returns (bool);
    
    function verifyStatusProof(
        bytes32 commitment,
        bytes calldata proof
    ) external view returns (bool);
    
    function verifyReputationProof(
        bytes32 commitment,
        bytes calldata proof
    ) external view returns (bool);
    
    function verifyBanProof(
        bytes32 commitment,
        bytes calldata proof
    ) external view returns (bool);
    
    function verifyAppealProof(
        bytes32 commitment,
        bytes calldata proof
    ) external view returns (bool);
    
    function verifyMixingProof(
        bytes32 sessionId,
        bytes calldata proof
    ) external view returns (bool);
}