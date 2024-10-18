// SPDX-License-Identifier: MIT

pragma solidity ^0.8.26;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "./interfaces/IFileRegistry.sol";
import "./interfaces/IMessaging.sol";
import "./interfaces/IStorage.sol";

/**
 * @title CipherZeroCore
 * @dev Main entry point for the Cipher Zero Protocol
 */
contract CipherZeroCore is Ownable, ReentrancyGuard {
    IFileRegistry public fileRegistry;
    IMessaging public messaging;
    IStorage public storage;

    mapping(address => bool) public registeredUsers;

    event UserRegistered(address indexed user);
    event FileUploaded(address indexed user, bytes32 indexed fileHash, uint256 size);
    event FileDownloaded(address indexed user, bytes32 indexed fileHash);
    event MessageSent(address indexed sender, address indexed recipient);

    /**
     * @dev Constructor to set up dependencies
     * @param _fileRegistry Address of the FileRegistry contract
     * @param _messaging Address of the Messaging contract
     * @param _storage Address of the Storage contract
     */
    constructor(address _fileRegistry, address _messaging, address _storage) {
        fileRegistry = IFileRegistry(_fileRegistry);
        messaging = IMessaging(_messaging);
        storage = IStorage(_storage);
    }

    /**
     * @dev Modifier to check if a user is registered
     */
    modifier onlyRegisteredUser() {
        require(registeredUsers[msg.sender], "User not registered");
        _;
    }

    /**
     * @dev Registers a new user in the protocol
     * @param _user Address of the user to register
     */
    function registerUser(address _user) external {
        require(_user != address(0), "Invalid user address");
        require(!registeredUsers[_user], "User already registered");

        registeredUsers[_user] = true;
        emit UserRegistered(_user);
    }

    /**
     * @dev Initiates file upload process
     * @param _fileHash Hash of the file to upload
     * @param _size Size of the file in bytes
     */
    function uploadFile(bytes32 _fileHash, uint256 _size) external onlyRegisteredUser nonReentrant {
        require(_fileHash != bytes32(0), "Invalid file hash");
        require(_size > 0, "File size must be greater than 0");

        fileRegistry.addFile(_fileHash, msg.sender, _size);
        storage.storeData(_fileHash);

        emit FileUploaded(msg.sender, _fileHash, _size);
    }

    /**
     * @dev Initiates file download process
     * @param _fileHash Hash of the file to download
     */
    function downloadFile(bytes32 _fileHash) external onlyRegisteredUser nonReentrant {
        require(fileRegistry.checkAccess(_fileHash, msg.sender), "User does not have access to this file");

        storage.retrieveData(_fileHash);

        emit FileDownloaded(msg.sender, _fileHash);
    }

    /**
     * @dev Sends an encrypted message
     * @param _recipient Address of the message recipient
     * @param _encryptedMessage Encrypted message content
     */
    function sendMessage(address _recipient, bytes calldata _encryptedMessage) external onlyRegisteredUser nonReentrant {
        require(_recipient != address(0), "Invalid recipient address");
        require(_encryptedMessage.length > 0, "Message cannot be empty");

        messaging.sendMessage(_recipient, _encryptedMessage);

        emit MessageSent(msg.sender, _recipient);
    }

    /**
     * @dev Updates the address of the FileRegistry contract
     * @param _newFileRegistry Address of the new FileRegistry contract
     */
    function updateFileRegistry(address _newFileRegistry) external onlyOwner {
        require(_newFileRegistry != address(0), "Invalid FileRegistry address");
        fileRegistry = IFileRegistry(_newFileRegistry);
    }

    /**
     * @dev Updates the address of the Messaging contract
     * @param _newMessaging Address of the new Messaging contract
     */
    function updateMessaging(address _newMessaging) external onlyOwner {
        require(_newMessaging != address(0), "Invalid Messaging address");
        messaging = IMessaging(_newMessaging);
    }

    /**
     * @dev Updates the address of the Storage contract
     * @param _newStorage Address of the new Storage contract
     */
    function updateStorage(address _newStorage) external onlyOwner {
        require(_newStorage != address(0), "Invalid Storage address");
        storage = IStorage(_newStorage);
    }
}