// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "../interfaces/IStorage.sol";

contract Storage is IStorage, Ownable, ReentrancyGuard {
    uint256 public constant MAX_CHUNK_SIZE = 1024 * 1024; // 1MB
    uint256 public constant MAX_FILE_SIZE = 1024 * 1024 * 1024; // 1GB

    mapping(bytes32 => FileMetadata) private files;
    mapping(bytes32 => mapping(uint256 => ChunkInfo)) private chunks;
    mapping(bytes32 => mapping(address => bool)) private accessControl;

    constructor(address initialOwner) Ownable(initialOwner) {}

    // File existence check
    function fileExists(bytes32 fileHash) public view override returns (bool) {
        return files[fileHash].exists;
    }

    // Access control check
    function hasAccess(bytes32 fileHash, address user) public view override returns (bool) {
        return accessControl[fileHash][user];
    }

    // Get file metadata
    function getFileMetadata(bytes32 fileHash) external view override returns (FileMetadata memory) {
        require(fileExists(fileHash), "File not found");
        return files[fileHash];
    }

    // Get chunk info
    function getChunkInfo(bytes32 fileHash, uint256 index) external view override returns (ChunkInfo memory) {
        require(fileExists(fileHash), "File not found");
        require(index < files[fileHash].chunks, "Invalid chunk index");
        return chunks[fileHash][index];
    }

    // Get chunk count
    function getChunkCount(bytes32 fileHash) external view override returns (uint256) {
        require(fileExists(fileHash), "File not found");
        return files[fileHash].chunks;
    }

    // Get file size
    function getFileSize(bytes32 fileHash) external view override returns (uint256) {
        require(fileExists(fileHash), "File not found");
        return files[fileHash].size;
    }

    // Store file implementation
    function storeFile(
        bytes32 fileHash,
        bytes calldata data,
        bool isEncrypted,
        bytes32 encryptionProof
    ) external override {
        require(data.length <= MAX_FILE_SIZE, "File too large");
        uint256 chunkCount = (data.length + MAX_CHUNK_SIZE - 1) / MAX_CHUNK_SIZE;
        
        _createFile(fileHash, data.length, chunkCount, isEncrypted, encryptionProof);
    }

    // Alternative store file implementation
    function storeFile(
        bytes32 fileHash,
        uint256 size,
        uint256 chunks,
        bool encrypted,
        string calldata contentType
    ) external override returns (bool) {
        _createFile(fileHash, size, chunks, encrypted, bytes32(0));
        return true;
    }

    // Store chunk
    function storeChunk(
        bytes32 fileHash,
        uint256 chunkIndex,
        bytes calldata data,
        bytes32 proof
    ) external override {
        _storeChunk(fileHash, chunkIndex, data, proof);
    }

    // Alternative store chunk implementation
    function storeChunk(
        bytes32 fileHash,
        uint256 index,
        bytes calldata data
    ) external override returns (bool) {
        _storeChunk(fileHash, index, data, bytes32(0));
        return true;
    }

    // Retrieve file
    function retrieveFile(bytes32 fileHash) external view override returns (FileMetadata memory) {
        require(fileExists(fileHash), "File not found");
        require(hasAccess(fileHash, msg.sender), "No access");
        return files[fileHash];
    }

    // Remove file
    function removeFile(bytes32 fileHash) external override {
        require(fileExists(fileHash), "File not found");
        require(files[fileHash].owner == msg.sender, "Not owner");
        
        delete files[fileHash];
        emit FileRemoved(fileHash, msg.sender);
    }

    // Internal functions
    function _createFile(
        bytes32 fileHash,
        uint256 size,
        uint256 chunkCount,
        bool encrypted,
        bytes32 encryptionProof
    ) internal {
        require(size > 0 && size <= MAX_FILE_SIZE, "Invalid file size");
        require(chunkCount > 0, "Invalid chunk count");
        require(!fileExists(fileHash), "File already exists");

        files[fileHash] = FileMetadata({
            fileHash: fileHash,
            owner: msg.sender,
            size: size,
            created: block.timestamp,
            isEncrypted: encrypted,
            encryptionProof: encryptionProof,
            chunks: chunkCount,
            exists: true
        });

        accessControl[fileHash][msg.sender] = true;
        emit FileStored(fileHash, msg.sender, size, chunkCount, encrypted);
    }

    function _storeChunk(
        bytes32 fileHash,
        uint256 index,
        bytes calldata data,
        bytes32 proof
    ) internal {
        require(fileExists(fileHash), "File not found");
        require(hasAccess(fileHash, msg.sender), "No access");
        require(data.length <= MAX_CHUNK_SIZE, "Chunk too large");
        require(index < files[fileHash].chunks, "Invalid chunk index");

        bytes32 chunkHash = keccak256(data);
        chunks[fileHash][index] = ChunkInfo({
            index: index,
            size: data.length,
            hash: chunkHash,
            proof: proof
        });

        emit ChunkStored(fileHash, index, chunkHash);
    }

    // Implement remaining interface functions
    function storeFile(
        bytes32 fileHash,
        uint256 size,
        uint256 chunkCount,
        string calldata contentType,
        bool isEncrypted,
        string calldata encryptionType,
        bytes32 encryptionKey
    ) external override returns (bool) {
        _createFile(fileHash, size, chunkCount, isEncrypted, encryptionKey);
        return true;
    }

    function storeChunk(
        bytes32 fileHash,
        uint256 index,
        bytes calldata data,
        bool isEncrypted
    ) external override returns (bool) {
        _storeChunk(fileHash, index, data, bytes32(0));
        return true;
    }

    function retrieveChunk(
        bytes32 fileHash,
        uint256 index
    ) external view override returns (bytes memory) {
        require(fileExists(fileHash), "File not found");
        require(hasAccess(fileHash, msg.sender), "No access");
        require(index < files[fileHash].chunks, "Invalid chunk index");
        // Note: Actual chunk data retrieval would be implemented differently
        // This is just a placeholder
        return "";
    }
    function updateEncryption(
        bytes32 fileHash,
        bytes32 encryptionProof
    ) external override {
        require(fileExists(fileHash), "File not found");
        require(files[fileHash].owner == msg.sender, "Not owner");
        
        files[fileHash].encryptionProof = encryptionProof;
        emit EncryptionUpdated(fileHash, encryptionProof);
    }

    // Second updateEncryption implementation
    function updateEncryption(
        bytes32 fileHash,
        bool encrypted
    ) external override returns (bool) {
        require(fileExists(fileHash), "File not found");
        require(files[fileHash].owner == msg.sender, "Not owner");
        
        files[fileHash].isEncrypted = encrypted;
        emit EncryptionUpdated(fileHash, files[fileHash].encryptionProof);
        return true;
    }

    // First verifyChunk implementation
    function verifyChunk(
        bytes32 fileHash,
        uint256 chunkIndex,
        bytes calldata data,
        bytes32 proof
    ) external view override returns (bool) {
        require(fileExists(fileHash), "File not found");
        require(chunkIndex < files[fileHash].chunks, "Invalid chunk index");
        
        ChunkInfo storage chunk = chunks[fileHash][chunkIndex];
        bytes32 computedHash = keccak256(data);
        
        if (proof != bytes32(0)) {
            return chunk.proof == proof && chunk.hash == computedHash;
        }
        
        return chunk.hash == computedHash;
    }

    // Second verifyChunk implementation
    function verifyChunk(
        bytes32 fileHash,
        uint256 index,
        bytes32 chunkHash
    ) external view override returns (bool) {
        require(fileExists(fileHash), "File not found");
        require(index < files[fileHash].chunks, "Invalid chunk index");
        
        return chunks[fileHash][index].hash == chunkHash;
    }
}