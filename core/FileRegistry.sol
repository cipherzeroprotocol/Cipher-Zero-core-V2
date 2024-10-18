// SPDX-License-Identifier: MIT

pragma solidity ^0.8.26;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title FileRegistry
 * @dev Manages metadata for all files in the system and handles access control for file sharing
 */
contract FileRegistry is Ownable, ReentrancyGuard {
    constructor() Ownable(msg.sender) ReentrancyGuard() {}
    struct File {
        string fileName;
        bytes32 fileHash;
        address owner;
        uint256 size;
        uint256 timestamp;
        mapping(address => bool) accessList;
    }

    mapping(bytes32 => File) private files;
    mapping(address => bytes32[]) private userFiles;

    event FileAdded(bytes32 indexed fileHash, string fileName, address indexed owner, uint256 size);
    event FileAccessChanged(bytes32 indexed fileHash, address indexed user, bool canAccess);

    /**
     * @dev Adds a new file to the registry
     * @param _fileHash Hash of the file
     * @param _fileName Name of the file
     * @param _owner Address of the file owner
     * @param _size Size of the file in bytes
     */
    function addFile(bytes32 _fileHash, string memory _fileName, address _owner, uint256 _size) external onlyOwner nonReentrant {
        require(_fileHash != bytes32(0), "Invalid file hash");
        require(_owner != address(0), "Invalid owner address");
        require(_size > 0, "File size must be greater than 0");
        require(files[_fileHash].owner == address(0), "File already exists");

        File storage newFile = files[_fileHash];
        newFile.fileName = _fileName;
        newFile.fileHash = _fileHash;
        newFile.owner = _owner;
        newFile.size = _size;
        newFile.timestamp = block.timestamp;
        newFile.accessList[_owner] = true;

        userFiles[_owner].push(_fileHash);

        emit FileAdded(_fileHash, _fileName, _owner, _size);
    }

    /**
     * @dev Retrieves file metadata
     * @param _fileHash Hash of the file
     * @return fileName The name of the file
     * @return owner The owner of the file
     * @return size The size of the file
     * @return timestamp The timestamp of the file
     */
    function getFileInfo(bytes32 _fileHash) external view returns (string memory fileName, address owner, uint256 size, uint256 timestamp) {
        File storage file = files[_fileHash];
        require(file.owner != address(0), "File does not exist");
        return (file.fileName, file.owner, file.size, file.timestamp);
    }

    /**
     * @dev Sets access permissions for a file
     * @param _fileHash Hash of the file
     * @param _user Address of the user to grant/revoke access
     * @param _canAccess Boolean indicating whether the user can access the file
     */
    function setFileAccess(bytes32 _fileHash, address _user, bool _canAccess) external nonReentrant {
        require(files[_fileHash].owner != address(0), "File does not exist");
        require(files[_fileHash].owner == msg.sender, "Only file owner can set access");
        require(_user != address(0), "Invalid user address");

        files[_fileHash].accessList[_user] = _canAccess;
        emit FileAccessChanged(_fileHash, _user, _canAccess);
    }

    /**
     * @dev Checks if a user has access to a file
     * @param _fileHash Hash of the file
     * @param _user Address of the user to check
     * @return Boolean indicating whether the user has access
     */
    function checkAccess(bytes32 _fileHash, address _user) external view returns (bool) {
        require(files[_fileHash].owner != address(0), "File does not exist");
        return files[_fileHash].accessList[_user];
    }

    /**
     * @dev Retrieves all files owned by a user
     * @param _user Address of the user
     * @return Array of file hashes owned by the user
     */
    function getUserFiles(address _user) external view returns (bytes32[] memory) {
        return userFiles[_user];
    }
}