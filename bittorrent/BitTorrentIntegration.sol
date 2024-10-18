// SPDX-License-Identifier: MIT

pragma solidity ^0.8.26;

import "@openzeppelin/contracts/access/Ownable.sol";

contract BitTorrentIntegration is Ownable {
    constructor() Ownable(msg.sender) {}
    // Mapping to store magnet links associated with file hashes
    mapping(bytes32 => string) private magnetLinks;

    // Event to log magnet link generation
    event MagnetLinkGenerated(bytes32 indexed fileHash, string magnetLink);

    // Event to log magnet link storage
    event MagnetLinkStored(bytes32 indexed fileHash, string magnetLink);

    // Function to generate a magnet link for a file
    function generateMagnetLink(bytes32 _fileHash, uint256 _size) public pure returns (string memory) {
        // Simple magnet link generation (can be customized further)
        return string(abi.encodePacked("magnet:?xt=urn:btih:", toHexString(_fileHash), "&dn=File&xl=", uint2str(_size)));
    }

    // Function to store a magnet link for a file
    function storeMagnetLink(bytes32 _fileHash, string memory _magnetLink) public onlyOwner {
        // Store the magnet link in the mapping
        magnetLinks[_fileHash] = _magnetLink;

        // Emit event for the stored link
        emit MagnetLinkStored(_fileHash, _magnetLink);
    }

    // Function to retrieve a magnet link for a file
    function getMagnetLink(bytes32 _fileHash) public view returns (string memory) {
        return magnetLinks[_fileHash];
    }

    // Utility function to convert bytes32 to a hexadecimal string
    function toHexString(bytes32 _data) internal pure returns (string memory) {
        bytes memory hexChars = "0123456789abcdef";
        bytes memory result = new bytes(64);
        for (uint256 i = 0; i < 32; i++) {
            result[i * 2] = hexChars[uint8(_data[i] >> 4)];
            result[i * 2 + 1] = hexChars[uint8(_data[i] & 0x0f)];
        }
        return string(result);
    }

    // Utility function to convert uint256 to string
    function uint2str(uint256 _i) internal pure returns (string memory) {
        if (_i == 0) {
            return "0";
        }
        uint256 j = _i;
        uint256 length;
        while (j != 0) {
            length++;
            j /= 10;
        }
        bytes memory bstr = new bytes(length);
        uint256 k = length;
        j = _i;
        while (j != 0) {
            bstr[--k] = bytes1(uint8(48 + j % 10));
            j /= 10;
        }
        return string(bstr);
    }
}
