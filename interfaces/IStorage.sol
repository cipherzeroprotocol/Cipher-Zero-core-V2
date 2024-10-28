// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/**
 * @title IStorage
 * @notice Interface for storage management in Cipher Zero Protocol
 * @dev Handles decentralized storage with encryption and ZK proofs
 */
interface IStorage {
    // Structs
    
    /**
     * @dev Structure for file metadata
     * @param fileHash Hash of the file
     * @param owner Address of the file owner
     * @param size Size of file in bytes
     * @param created Timestamp when file was created
     * @param isEncrypted Whether file is encrypted
     * @param encryptionProof Proof of encryption if encrypted
     * @param chunks Number of chunks file is split into
     */
    struct FileMetadata {
        bytes32 fileHash;
        address owner;
        uint256 size;
        uint256 created;
        bool isEncrypted;
        bytes32 encryptionProof;
        uint256 chunks;
        bool exists;
    }

    /**
     * @dev Structure for storage chunk information
     * @param index Chunk index
     * @param size Size of chunk in bytes
     * @param hash Hash of chunk data
     * @param proof Proof of chunk integrity
     */
    struct ChunkInfo {
        uint256 index;
        uint256 size;
        bytes32 hash;
        bytes32 proof;
    }

    // Events
    
    /**
     * @dev Emitted when a file is stored
     */
    event FileStored(
        bytes32 indexed fileHash,
        address indexed owner,
        uint256 size,
        uint256 chunks,
        bool encrypted
    );

    /**
     * @dev Emitted when a file is retrieved
     */
    event FileRetrieved(
        bytes32 indexed fileHash,
        address indexed requester
    );

    /**
     * @dev Emitted when a file is removed
     */
    event FileRemoved(
        bytes32 indexed fileHash,
        address indexed owner
    );

    /**
     * @dev Emitted when a chunk is stored
     */
    event ChunkStored(
        bytes32 indexed fileHash,
        uint256 indexed chunkIndex,
        bytes32 chunkHash
    );

    /**
     * @dev Emitted when encryption status changes
     */
    event EncryptionUpdated(
        bytes32 indexed fileHash,
        bytes32 encryptionProof
    );

    // Core Functions

    /**
     * @notice Store file data
     * @param fileHash Hash of the file
     * @param data File data to store
     * @param isEncrypted Whether the file is encrypted
     * @param encryptionProof Proof of encryption if encrypted
     */
    function storeFile(
        bytes32 fileHash,
        bytes calldata data,
        bool isEncrypted,
        bytes32 encryptionProof
    ) external;

    /**
     * @notice Store file chunk
     * @param fileHash Hash of the file
     * @param chunkIndex Index of the chunk
     * @param chunkData Chunk data to store
     * @param proof Proof of chunk integrity
     */
    function storeChunk(
        bytes32 fileHash,
        uint256 chunkIndex,
        bytes calldata chunkData,
        bytes32 proof
    ) external;

    

    function storeFile(
        bytes32 fileHash,
        uint256 size,
        uint256 chunkCount,
        string calldata contentType,
        bool isEncrypted,
        string calldata encryptionType,
        bytes32 encryptionKey
    ) external returns (bool);

    function storeChunk(
        bytes32 fileHash,
        uint256 index,
        bytes calldata data,
        bool isEncrypted
    ) external returns (bool);


    // View Functions

    /**
     * @notice Get file metadata
     * @param fileHash Hash of the file
     * @return FileMetadata struct
     */
    

    /**
     * @notice Get chunk information
     * @param fileHash Hash of the file
     * @param chunkIndex Index of the chunk
     * @return ChunkInfo struct
     */
    

    /**
     * @notice Check if file exists
     * @param fileHash Hash of the file
     * @return bool True if file exists
     */
   

    /**
     * @notice Get total chunks for a file
     * @param fileHash Hash of the file
     * @return uint256 Number of chunks
     */
   

    /**
     * @notice Get file size
     * @param fileHash Hash of the file
     * @return uint256 File size in bytes
     */
   

    // Validation Functions

    /**
     * @notice Verify chunk integrity
     * @param fileHash Hash of the file
     * @param chunkIndex Index of chunk
     * @param chunkData Chunk data to verify
     * @param proof Proof to verify against
     * @return bool True if chunk is valid
     */
    function verifyChunk(
        bytes32 fileHash,
        uint256 chunkIndex,
        bytes calldata chunkData,
        bytes32 proof
    ) external view returns (bool);

    /**
     * @notice Check if user has access to file
     * @param fileHash Hash of the file
     * @param user Address to check
     * @return bool True if user has access
     */
    

    /**
     * @notice Update file encryption status
     * @param fileHash Hash of the file
     * @param encryptionProof New encryption proof
     */
    function updateEncryption(
        bytes32 fileHash,
        bytes32 encryptionProof
    ) external;
    //////
    ///// TODO: Add tests
    

    function storeFile(
        bytes32 fileHash,
        uint256 size,
        uint256 chunks,
        bool encrypted,
        string calldata contentType
    ) external returns (bool);

    function storeChunk(
        bytes32 fileHash,
        uint256 index,
        bytes calldata data
    ) external returns (bool);

    function retrieveFile(bytes32 fileHash) 
        external view returns (FileMetadata memory);

    function retrieveChunk(
        bytes32 fileHash,
        uint256 index
    ) external view returns (bytes memory);

    function removeFile(bytes32 fileHash) external;

    function getFileMetadata(bytes32 fileHash)
        external view returns (FileMetadata memory);

    function getChunkInfo(
        bytes32 fileHash,
        uint256 index
    ) external view returns (ChunkInfo memory);

    function fileExists(bytes32 fileHash) 
        external view returns (bool);

    function getChunkCount(bytes32 fileHash)
        external view returns (uint256);

    function getFileSize(bytes32 fileHash)
        external view returns (uint256);

    function verifyChunk(
        bytes32 fileHash,
        uint256 index,
        bytes32 chunkHash
    ) external view returns (bool);

    function hasAccess(
        bytes32 fileHash,
        address user
    ) external view returns (bool);

    function updateEncryption(
        bytes32 fileHash,
        bool encrypted
    ) external returns (bool);
}