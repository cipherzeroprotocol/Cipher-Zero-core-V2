// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

interface IFileRegistry {
    // Structs
    struct FileInfo {
        bytes32 fileHash;       // Hash of the file
        address owner;          // Owner of the file
        uint256 size;          // Size in bytes
        uint256 timestamp;      // Upload timestamp
        bool isEncrypted;       // Whether file is encrypted
        bytes32 encryptionProof; // Proof of encryption if encrypted
        bool exists;            // Whether file exists
    }

    /**
     * @notice Add a new file to the registry
     * @param fileHash Hash of the file
     * @param owner Address of the file owner
     * @param size Size of the file in bytes
     */
    function addFile(
        bytes32 fileHash, 
        address owner, 
        uint256 size
    ) external;

    /**
     * @notice Check if a user has access to a file
     * @param fileHash Hash of the file
     * @param user Address of the user to check
     * @return bool True if user has access
     */
    function checkAccess(
        bytes32 fileHash, 
        address user
    ) external view returns (bool);

    /**
     * @notice Get file information
     * @param fileHash Hash of the file
     * @return FileInfo struct containing file information
     */
    function getFileInfo(
        bytes32 fileHash
    ) external view returns (FileInfo memory);

    /**
     * @notice Grant access to a file
     * @param fileHash Hash of the file
     * @param user Address to grant access to
     */
    function grantAccess(
        bytes32 fileHash, 
        address user
    ) external;

    /**
     * @notice Revoke access to a file
     * @param fileHash Hash of the file
     * @param user Address to revoke access from
     */
    function revokeAccess(
        bytes32 fileHash, 
        address user
    ) external;

    /**
     * @notice Update file encryption status and proof
     * @param fileHash Hash of the file
     * @param encryptionProof Proof of encryption
     */
    function updateFileEncryption(
        bytes32 fileHash, 
        bytes32 encryptionProof
    ) external;

    /**
     * @notice Remove a file from the registry
     * @param fileHash Hash of the file to remove
     */
    function removeFile(
        bytes32 fileHash
    ) external;

    /**
     * @notice Get all files owned by a user
     * @param owner Address of the owner
     * @return bytes32[] Array of file hashes
     */
    function getUserFiles(
        address owner
    ) external view returns (bytes32[] memory);

    // Events
    event FileAdded(
        bytes32 indexed fileHash, 
        address indexed owner, 
        uint256 size
    );
    
    event FileRemoved(
        bytes32 indexed fileHash, 
        address indexed owner
    );
    
    event AccessGranted(
        bytes32 indexed fileHash, 
        address indexed grantee
    );
    
    event AccessRevoked(
        bytes32 indexed fileHash, 
        address indexed user
    );
    
    event FileEncrypted(
        bytes32 indexed fileHash, 
        bytes32 encryptionProof
    );
}