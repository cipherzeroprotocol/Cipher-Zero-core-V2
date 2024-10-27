// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

interface IMessaging {
    // Message structure
    struct Message {
        bytes32 commitment;      // Message commitment
        bytes32 nullifier;       // Uniqueness nullifier
        address sender;          // Sender address (encrypted)
        address recipient;       // Recipient address
        bytes encryptedContent;  // Encrypted message content
        uint256 timestamp;       // Message timestamp
        bool isRead;            // Read status
        bytes proof;            // ZK proof
    }

    /**
     * @notice Store encrypted message with ZK proof
     * @param commitment Message commitment
     * @param nullifier Unique nullifier
     * @param recipient Recipient address
     * @param encryptedContent Encrypted message content
     * @param proof ZK proof
     */
    function storeMessage(
        bytes32 commitment,
        bytes32 nullifier,
        address recipient,
        bytes calldata encryptedContent,
        bytes calldata proof
    ) external;

    /**
     * @notice Mark message as read
     * @param commitment Message commitment
     */
    function markMessageRead(bytes32 commitment) external;

    /**
     * @notice Get user's messages with pagination
     * @param user User address
     * @param offset Starting index
     * @param limit Maximum number of messages to return
     * @return Message[] Array of messages
     */
    function getUserMessages(
        address user,
        uint256 offset,
        uint256 limit
    ) external view returns (Message[] memory);

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