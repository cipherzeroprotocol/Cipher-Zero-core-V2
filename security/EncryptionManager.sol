// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title EncryptionManager
 * @dev Advanced encryption key management system with optimized operations
 */
contract EncryptionManager is Ownable, ReentrancyGuard, Pausable {
    // Storage mappings
    mapping(bytes32 => bytes32) private encryptedKeys;
    mapping(bytes32 => KeyMetadata) private keyMetadata;

    // Key status flags
    uint8 private constant STATUS_ACTIVE = 1;
    uint8 private constant STATUS_REVOKED = 2;
    
    // Cooling period for key rotations (24 hours)
    uint256 private constant KEY_ROTATION_COOLING_PERIOD = 24 hours;
    
    struct KeyMetadata {
        uint256 creationTime;
        uint256 lastRotationTime;
        uint8 status;
        uint256 useCount;
    }

    // Events
    event EncryptionKeyGenerated(
        bytes32 indexed keyHash,
        uint256 indexed timestamp,
        bytes32 indexed publicPart
    );
    event EncryptionKeyStored(
        bytes32 indexed keyHash,
        uint256 indexed timestamp
    );
    event EncryptionKeyRotated(
        bytes32 indexed oldKeyHash,
        bytes32 indexed newKeyHash,
        uint256 indexed timestamp
    );
    event EncryptionKeyRevoked(
        bytes32 indexed keyHash,
        uint256 indexed timestamp,
        string reason
    );

    constructor(address initialOwner) Ownable(initialOwner) {
        require(initialOwner != address(0), "Invalid owner");
        _pause(); // Start paused for security
    }

    /**
     * @dev Generates a new encryption key using assembly for gas optimization
     */
    function generateEncryptionKey(
        bytes32 entropy
    ) external nonReentrant whenNotPaused onlyOwner returns (bytes32 keyHash, bytes32 publicPart) {
        require(entropy != bytes32(0), "Zero entropy");

        assembly {
            // Generate key hash using block data and entropy
            let ptr := mload(0x40)
            mstore(ptr, number())
            mstore(add(ptr, 0x20), timestamp())
            mstore(add(ptr, 0x40), entropy)
            
            keyHash := keccak256(ptr, 0x60)
            publicPart := xor(keyHash, entropy)
            
            // Clear memory
            mstore(ptr, 0)
        }

        // Store metadata
        keyMetadata[keyHash] = KeyMetadata({
            creationTime: block.timestamp,
            lastRotationTime: block.timestamp,
            status: STATUS_ACTIVE,
            useCount: 0
        });

        emit EncryptionKeyGenerated(keyHash, block.timestamp, publicPart);
        return (keyHash, publicPart);
    }

    /**
     * @dev Stores an encrypted key
     */
    function storeEncryptionKey(
        bytes32 keyHash,
        bytes32 encryptedKey
    ) external nonReentrant whenNotPaused onlyOwner {
        require(keyHash != bytes32(0), "Invalid key hash");
        require(encryptedKey != bytes32(0), "Invalid encrypted key");
        require(encryptedKeys[keyHash] == bytes32(0), "Key already exists");

        encryptedKeys[keyHash] = encryptedKey;
        
        KeyMetadata storage metadata = keyMetadata[keyHash];
        metadata.useCount++;

        emit EncryptionKeyStored(keyHash, block.timestamp);
    }

    /**
     * @dev Rotates an encryption key with cooling period check
     */
    function rotateEncryptionKey(
        bytes32 oldKeyHash,
        bytes32 newKeyHash,
        bytes32 newEncryptedKey
    ) external nonReentrant whenNotPaused onlyOwner {
        KeyMetadata storage oldMetadata = keyMetadata[oldKeyHash];
        require(oldMetadata.status == STATUS_ACTIVE, "Invalid old key");
        require(
            block.timestamp >= oldMetadata.lastRotationTime + KEY_ROTATION_COOLING_PERIOD,
            "Cooling period active"
        );
        require(encryptedKeys[newKeyHash] == bytes32(0), "New key already exists");

        // Rotate keys
        delete encryptedKeys[oldKeyHash];
        encryptedKeys[newKeyHash] = newEncryptedKey;

        // Update metadata
        oldMetadata.status = STATUS_REVOKED;
        keyMetadata[newKeyHash] = KeyMetadata({
            creationTime: block.timestamp,
            lastRotationTime: block.timestamp,
            status: STATUS_ACTIVE,
            useCount: 0
        });

        emit EncryptionKeyRotated(oldKeyHash, newKeyHash, block.timestamp);
    }

    /**
     * @dev Retrieves an encryption key with access control
     */
    function getEncryptionKey(
        bytes32 keyHash
    ) external view whenNotPaused onlyOwner returns (bytes32 encryptedKey, KeyMetadata memory metadata) {
        metadata = keyMetadata[keyHash];
        require(metadata.status == STATUS_ACTIVE, "Key not active");
        
        encryptedKey = encryptedKeys[keyHash];
        require(encryptedKey != bytes32(0), "Key not found");
    }

    /**
     * @dev Revokes an encryption key with reason
     */
    function revokeEncryptionKey(
        bytes32 keyHash,
        string calldata reason
    ) external nonReentrant whenNotPaused onlyOwner {
        KeyMetadata storage metadata = keyMetadata[keyHash];
        require(metadata.status == STATUS_ACTIVE, "Key not active");

        delete encryptedKeys[keyHash];
        metadata.status = STATUS_REVOKED;

        emit EncryptionKeyRevoked(keyHash, block.timestamp, reason);
    }

    // Emergency functions
    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }
}