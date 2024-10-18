// SPDX-License-Identifier: MIT

pragma solidity ^0.8.26;

/**
 * @title IStorage
 * @dev Interface for the decentralized storage module of Cipher Zero Protocol
 */
interface IStorage {
    
    /// @notice Emitted when a new data hash is stored
    /// @param dataHash Hash of the stored data
    /// @param sender Address that submitted the data
    /// @param timestamp Time when data was stored
    event DataStored(bytes32 indexed dataHash, address indexed sender, uint256 timestamp);
    
    /// @notice Emitted when data is retrieved
    /// @param dataHash Hash of the retrieved data
    /// @param retriever Address that retrieved the data
    /// @param timestamp Time of retrieval
    event DataRetrieved(bytes32 indexed dataHash, address indexed retriever, uint256 timestamp);

    /// @notice Emitted when data is updated
    /// @param dataHash Hash of the updated data
    /// @param updater Address that updated the data
    /// @param timestamp Time when data was updated
    event DataUpdated(bytes32 indexed dataHash, address indexed updater, uint256 timestamp);

    /// @notice Emitted when data is deleted
    /// @param dataHash Hash of the deleted data
    /// @param deleter Address that deleted the data
    /// @param timestamp Time when data was deleted
    event DataDeleted(bytes32 indexed dataHash, address indexed deleter, uint256 timestamp);

    /**
     * @notice Store data on-chain by submitting a hash and off-chain URI
     * @dev Only the data owner can update or delete stored data
     * @param dataHash The hash of the data being stored
     * @param dataUri The URI pointing to the actual data (stored off-chain)
     */
    function storeData(bytes32 dataHash, string calldata dataUri) external;

    /**
     * @notice Retrieve the URI of the data by its hash
     * @param dataHash The hash of the data to be retrieved
     * @return The URI where the data can be accessed
     */
    function retrieveData(bytes32 dataHash) external view returns (string memory);

    /**
     * @notice Update existing data's URI
     * @param dataHash The hash of the data to update
     * @param newUri The new URI for the data
     */
    function updateData(bytes32 dataHash, string calldata newUri) external;

    /**
     * @notice Permanently delete data by its hash
     * @dev Can only be called by the original uploader of the data
     * @param dataHash The hash of the data to delete
     */
    function deleteData(bytes32 dataHash) external;

    /**
     * @notice Check if the data exists on-chain
     * @param dataHash The hash of the data to check
     * @return True if the data exists, false otherwise
     */
    function dataExists(bytes32 dataHash) external view returns (bool);

    /**
     * @notice Get the owner of the stored data
     * @param dataHash The hash of the data to check ownership for
     * @return Address of the data owner
     */
    function getDataOwner(bytes32 dataHash) external view returns (address);
    
    /**
     * @notice Get the metadata associated with the data hash
     * @param dataHash The hash of the data to fetch metadata for
     * @return URI string of the data and timestamp when it was stored
     */
    function getDataMetadata(bytes32 dataHash) external view returns (string memory, uint256);
}
