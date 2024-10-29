// IBitTorrent.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

interface IBitTorrent {
    /**
     * @notice Register a file in the BitTorrent network
     * @param commitment File commitment hash
     * @param metadataHash IPFS/BitTorrent metadata hash
     * @return success Whether the file was successfully registered
     */
    function addFile(bytes32 commitment, bytes32 metadataHash) external returns (bool);

    /**
     * @notice Remove a file from the BitTorrent network
     * @param commitment File commitment hash
     * @return success Whether the file was successfully removed
     */
    function removeFile(bytes32 commitment) external returns (bool);

    /**
     * @notice Check if a file exists in the BitTorrent network
     * @param commitment File commitment hash
     * @return exists Whether the file exists
     */
    function fileExists(bytes32 commitment) external view returns (bool);

    /**
     * @notice Get file metadata hash
     * @param commitment File commitment hash
     * @return metadataHash IPFS/BitTorrent metadata hash
     */
    function getFileMetadataHash(bytes32 commitment) external view returns (bytes32);

    /**
     * @notice Update file metadata hash
     * @param commitment File commitment hash
     * @param newMetadataHash New IPFS/BitTorrent metadata hash
     * @return success Whether the metadata was successfully updated
     */
    function updateFileMetadata(bytes32 commitment, bytes32 newMetadataHash) external returns (bool);
}