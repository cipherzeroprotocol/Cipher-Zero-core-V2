// SPDX-License-Identifier: MIT

pragma solidity ^0.8.26;

/**
 * @title IMessaging
 * @dev Interface for the encrypted messaging functionality in Cipher Zero Protocol
 */
interface IMessaging {

    /// @notice Emitted when a new message is sent
    /// @param sender Address of the message sender
    /// @param receiver Address of the message receiver
    /// @param messageHash Hash of the encrypted message content
    /// @param timestamp Time when the message was sent
    event MessageSent(address indexed sender, address indexed receiver, bytes32 indexed messageHash, uint256 timestamp);

    /// @notice Emitted when a message is received and decrypted
    /// @param receiver Address of the message receiver
    /// @param messageHash Hash of the encrypted message content
    /// @param timestamp Time when the message was decrypted
    event MessageReceived(address indexed receiver, bytes32 indexed messageHash, uint256 timestamp);

    /// @notice Emitted when a message is deleted by the sender or receiver
    /// @param messageHash Hash of the deleted message
    /// @param sender Address that deleted the message
    /// @param timestamp Time when the message was deleted
    event MessageDeleted(bytes32 indexed messageHash, address indexed sender, uint256 timestamp);

    /**
     * @notice Sends an encrypted message to a receiver
     * @dev The message content must be encrypted before calling this function
     * @param receiver Address of the message receiver
     * @param messageHash Hash of the encrypted message content
     */
    function sendMessage(address receiver, bytes32 messageHash) external;

    /**
     * @notice Retrieves the message's encrypted content using its hash
     * @param messageHash Hash of the message content
     * @return Encrypted content of the message
     */
    function retrieveMessage(bytes32 messageHash) external view returns (bytes memory);

    /**
     * @notice Decrypts the message using a decryption key
     * @param messageHash Hash of the encrypted message content
     * @param decryptionKey Key used to decrypt the message
     * @return The decrypted message content
     */
    function decryptMessage(bytes32 messageHash, bytes memory decryptionKey) external returns (string memory);

    /**
     * @notice Deletes a message from the sender's or receiver's view
     * @param messageHash Hash of the message to delete
     */
    function deleteMessage(bytes32 messageHash) external;

    /**
     * @notice Checks if a message exists in the messaging system
     * @param messageHash Hash of the message to check
     * @return True if the message exists, false otherwise
     */
    function messageExists(bytes32 messageHash) external view returns (bool);

    /**
     * @notice Returns the timestamp when the message was sent
     * @param messageHash Hash of the message
     * @return The timestamp when the message was sent
     */
    function getMessageTimestamp(bytes32 messageHash) external view returns (uint256);

    /**
     * @notice Retrieves the address of the sender of the message
     * @param messageHash Hash of the message
     * @return The address of the message sender
     */
    function getMessageSender(bytes32 messageHash) external view returns (address);
}
