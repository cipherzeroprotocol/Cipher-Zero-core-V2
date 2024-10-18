// SPDX-License-Identifier: MIT

pragma solidity ^0.8.26;

import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title EncryptionManager
 * @dev Manages encryption keys for the protocol, including key generation, storage, and rotation.
 *      Only the contract owner can perform certain sensitive operations such as rotating or revoking keys.
 */
contract EncryptionManager is Ownable {
    constructor() Ownable(msg.sender) {}
    // Mapping to store encrypted keys associated with their hashes
    mapping(bytes32 => bytes32) private encryptionKeys;

    // Event emitted when a new encryption key is generated
    event EncryptionKeyGenerated(bytes32 indexed keyHash);

    // Event emitted when an encryption key is stored
    event EncryptionKeyStored(bytes32 indexed keyHash);

    // Event emitted when an encryption key is rotated
    event EncryptionKeyRotated(bytes32 indexed oldKeyHash, bytes32 indexed newKeyHash);

    // Event emitted when an encryption key is revoked
    event EncryptionKeyRevoked(bytes32 indexed keyHash);

    /**
     * @dev Generates a new encryption key by hashing random data.
     * @param keyData The input data for the encryption key hash (should be a random value from the caller).
     * @return keyHash The hash of the newly generated encryption key.
     */
    function generateEncryptionKey(bytes memory keyData) external onlyOwner returns (bytes32 keyHash) {
        keyHash = keccak256(keyData);
        emit EncryptionKeyGenerated(keyHash);
    }

    /**
     * @dev Stores a generated encryption key securely.
     * @param keyHash The hash of the encryption key to be stored.
     * @param encryptedKey The actual encryption key, stored securely (should be encrypted off-chain).
     */
    function storeEncryptionKey(bytes32 keyHash, bytes32 encryptedKey) external onlyOwner {
        require(encryptionKeys[keyHash] == bytes32(0), "Encryption key already exists");
        encryptionKeys[keyHash] = encryptedKey;
        emit EncryptionKeyStored(keyHash);
    }

    /**
     * @dev Rotates an encryption key, replacing the old key with a new one.
     * @param oldKeyHash The hash of the old encryption key.
     * @param newKeyHash The hash of the new encryption key.
     * @param newEncryptedKey The new encryption key, securely stored (should be encrypted off-chain).
     */
    function rotateEncryptionKey(bytes32 oldKeyHash, bytes32 newKeyHash, bytes32 newEncryptedKey) external onlyOwner {
        require(encryptionKeys[oldKeyHash] != bytes32(0), "Old encryption key does not exist");
        require(encryptionKeys[newKeyHash] == bytes32(0), "New encryption key already exists");

        delete encryptionKeys[oldKeyHash];
        encryptionKeys[newKeyHash] = newEncryptedKey;
        emit EncryptionKeyRotated(oldKeyHash, newKeyHash);
    }

    /**
     * @dev Retrieves the encrypted encryption key corresponding to the key hash.
     * @param keyHash The hash of the encryption key.
     * @return The encrypted encryption key.
     */
    function getEncryptionKey(bytes32 keyHash) external view onlyOwner returns (bytes32) {
        return encryptionKeys[keyHash];
    }

    /**
     * @dev Revokes an encryption key, removing it from storage.
     * @param keyHash The hash of the encryption key to be revoked.
     */
    function revokeEncryptionKey(bytes32 keyHash) external onlyOwner {
        require(encryptionKeys[keyHash] != bytes32(0), "Encryption key does not exist");
        delete encryptionKeys[keyHash];
        emit EncryptionKeyRevoked(keyHash);
    }
}
