// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "../interfaces/IStorage.sol";

/**
 * @title Storage
 * @dev Manages on-chain storage of small files or metadata and interacts with off-chain storage solutions
 */
contract Storage is IStorage, Ownable, ReentrancyGuard {
    uint256 public constant MAX_ON_CHAIN_DATA_SIZE = 1024; // 1 KB

    struct StorageItem {
        bytes data;
        string offChainIdentifier;
        bool isOffChain;
    }

    mapping(bytes32 => StorageItem) private storageItems;

    event DataStored(bytes32 indexed dataHash, uint256 size, bool isOffChain);
    event OffChainStorageLinked(
        bytes32 indexed dataHash,
        string storageIdentifier
    );

    /**
     * @dev Stores small amounts of data on-chain
     * @param _data The data to be stored
     * @return dataHash The hash of the stored data
     */
    function storeData(
        bytes calldata _data,
    ) external nonReentrant returns (bytes32) {
        require(_data.length > 0, "Data cannot be empty");
        require(
            _data.length <= MAX_ON_CHAIN_DATA_SIZE,
            "Data too large for on-chain storage"
        );

        bytes32 dataHash = keccak256(_data);
        require(storageItems[dataHash].data.length == 0, "Data already exists");

        storageItems[dataHash] = StorageItem({
            data: _data,
            offChainIdentifier: "",
            isOffChain: false
        });

        emit DataStored(dataHash, _data.length, false);
        return dataHash;
    }

    /**
     * @dev Retrieves stored data
     * @param _dataHash The hash of the data to retrieve
     * @return The stored data and a boolean indicating if it's off-chain
     */
    function retrieveData(
        bytes32 _dataHash
    ) external view override returns (bytes memory, bool) {
        StorageItem storage item = storageItems[_dataHash];
        require(
            item.data.length > 0 || bytes(item.offChainIdentifier).length > 0,
            "Data not found"
        );

        return (item.data, item.isOffChain);
    }

    /**
     * @dev Links off-chain stored data
     * @param _dataHash The hash of the data
     * @param _storageIdentifier The identifier for the off-chain storage location
     */
    function linkOffChainStorage(
        bytes32 _dataHash,
        string calldata _storageIdentifier
    ) external nonReentrant {
        require(
            bytes(_storageIdentifier).length > 0,
            "Invalid storage identifier"
        );
        require(
            storageItems[_dataHash].data.length == 0 &&
                bytes(storageItems[_dataHash].offChainIdentifier).length == 0,
            "Data already exists"
        );

        storageItems[_dataHash] = StorageItem({
            data: "",
            offChainIdentifier: _storageIdentifier,
            isOffChain: true
        });

        emit OffChainStorageLinked(_dataHash, _storageIdentifier);
    }

    /**
     * @dev Checks if data exists (either on-chain or off-chain)
     * @param _dataHash The hash of the data to check
     * @return bool indicating if the data exists
     */
    function dataExists(bytes32 _dataHash) external view returns (bool) {
        return
            storageItems[_dataHash].data.length > 0 ||
            bytes(storageItems[_dataHash].offChainIdentifier).length > 0;
    }

    /**
     * @dev Retrieves the off-chain storage identifier for a given data hash
     * @param _dataHash The hash of the data
     * @return The off-chain storage identifier
     */
    function getOffChainIdentifier(
        bytes32 _dataHash
    ) external view returns (string memory) {
        require(
            storageItems[_dataHash].isOffChain,
            "Data is not stored off-chain"
        );
        return storageItems[_dataHash].offChainIdentifier;
    }

    function storeData(
        bytes32 dataHash,
        string calldata dataUri
    ) external {}

    function updateData(
        bytes32 dataHash,
        string calldata newUri
    ) external {}

    function deleteData(bytes32 dataHash) external {}

    function getDataOwner(
        bytes32 dataHash
    ) external view returns (address) {}

    function getDataMetadata(
        bytes32 dataHash
    ) external view returns (string memory, uint256) {}
}