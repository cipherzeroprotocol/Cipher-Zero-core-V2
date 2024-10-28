// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

interface IMessaging {
    struct Message {
        bytes32 commitment;      // Message commitment
        bytes32 nullifier;       // Uniqueness nullifier
        address sender;          // Sender address
        address recipient;       // Recipient address
        bytes encryptedContent;  // Encrypted message content
        uint256 timestamp;       // Message timestamp
        bool isRead;            // Read status
        bytes proof;            // ZK proof
    }

    function storeMessage(
        bytes32 commitment,
        bytes32 nullifier,
        address recipient,
        bytes calldata encryptedContent,
        bytes calldata proof
    ) external;

    function sendMessage(
        address recipient,
        bytes calldata encryptedMessage,
        bytes32 messageHash
    ) external;

    function markMessageRead(bytes32 commitment) external;

    function getUserMessages(
        address user,
        uint256 offset,
        uint256 limit
    ) external view returns (Message[] memory);

    function getMessage(bytes32 commitment) 
        external 
        view 
        returns (Message memory);

    // Events
    event MessageStored(
        bytes32 indexed commitment,
        address indexed recipient,
        uint256 timestamp
    );

    event MessageRead(
        bytes32 indexed commitment,
        uint256 timestamp
    );
}