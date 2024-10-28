// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "../interfaces/IVerifier.sol";
import "../interfaces/IMessaging.sol";

contract MessageRegistry is IMessaging, Ownable, ReentrancyGuard, Pausable {
    // State variables
    IVerifier public verifier;
    
    mapping(bytes32 => Message) public messages;
    mapping(bytes32 => bool) public nullifierUsed;
    mapping(address => bytes32[]) public userMessages;
    
    constructor(
        address _verifier,
        address _owner
    ) Ownable(_owner) {
        require(_verifier != address(0), "Invalid verifier address");
        verifier = IVerifier(_verifier);
    }

    function storeMessage(
        bytes32 commitment,
        bytes32 nullifier,
        address recipient,
        bytes calldata encryptedContent,
        bytes calldata proof
    ) external override nonReentrant whenNotPaused {
        require(commitment != bytes32(0), "Invalid commitment");
        require(nullifier != bytes32(0), "Invalid nullifier");
        require(recipient != address(0), "Invalid recipient");
        require(encryptedContent.length > 0, "Empty message");
        require(proof.length > 0, "Empty proof");
        
        require(!nullifierUsed[nullifier], "Nullifier already used");
        
        require(
            verifier.verifyMessageProof(
                commitment,
                nullifier,
                msg.sender,
                recipient,
                encryptedContent,
                proof
            ),
            "Invalid proof"
        );

        messages[commitment] = Message({
            commitment: commitment,
            nullifier: nullifier,
            sender: msg.sender,
            recipient: recipient,
            encryptedContent: encryptedContent,
            timestamp: block.timestamp,
            isRead: false,
            proof: proof
        });

        nullifierUsed[nullifier] = true;
        userMessages[recipient].push(commitment);

        emit MessageStored(commitment, recipient, block.timestamp);
    }

    function sendMessage(
        address recipient,
        bytes calldata encryptedMessage,
        bytes32 messageHash
    ) external override nonReentrant whenNotPaused {
        require(recipient != address(0), "Invalid recipient");
        require(encryptedMessage.length > 0, "Empty message");

        bytes32 commitment = keccak256(
            abi.encodePacked(messageHash, msg.sender, recipient)
        );
        
        messages[commitment] = Message({
            commitment: commitment,
            nullifier: messageHash,
            sender: msg.sender,
            recipient: recipient,
            encryptedContent: encryptedMessage,
            timestamp: block.timestamp,
            isRead: false,
            proof: ""
        });

        userMessages[recipient].push(commitment);
        
        emit MessageStored(commitment, recipient, block.timestamp);
    }

    function markMessageRead(bytes32 commitment) external override {
        require(commitment != bytes32(0), "Invalid commitment");
        
        Message storage message = messages[commitment];
        require(message.commitment != bytes32(0), "Message not found");
        require(message.recipient == msg.sender, "Not message recipient");
        require(!message.isRead, "Message already read");

        message.isRead = true;
        emit MessageRead(commitment, block.timestamp);
    }

    function getUserMessages(
        address user,
        uint256 offset,
        uint256 limit
    ) external view override returns (Message[] memory) {
        require(user != address(0), "Invalid user address");
        require(limit > 0, "Invalid limit");
        
        bytes32[] storage userMsgs = userMessages[user];
        
        uint256 end = offset + limit;
        if (end > userMsgs.length) {
            end = userMsgs.length;
        }
        require(offset < end, "Invalid offset");

        Message[] memory result = new Message[](end - offset);
        for (uint256 i = offset; i < end; i++) {
            result[i - offset] = messages[userMsgs[i]];
        }
        return result;
    }

    function getMessage(bytes32 commitment) 
        external 
        view 
        override 
        returns (Message memory) 
    {
        require(commitment != bytes32(0), "Invalid commitment");
        Message storage message = messages[commitment];
        require(message.commitment != bytes32(0), "Message not found");
        return message;
    }

    // Admin functions
    function setVerifier(address _verifier) external onlyOwner {
        require(_verifier != address(0), "Invalid verifier address");
        verifier = IVerifier(_verifier);
    }

    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }

    // View functions
    function getUserMessageCount(address user) external view returns (uint256) {
        return userMessages[user].length;
    }
}