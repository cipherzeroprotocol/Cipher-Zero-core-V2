// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

interface IMessageRegistry {
   // Structs
   struct Message {
       bytes32 commitment;    // Message commitment
       bytes32 nullifier;     // Uniqueness nullifier 
       address sender;        // Sender address (encrypted)
       address recipient;     // Recipient address (encrypted)
       bytes encryptedContent;// Encrypted message content
       uint256 timestamp;     // Message timestamp
       bool isRead;          // Read status
       bytes proof;          // ZK proof
   }

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

   event VerifierUpdated(
       address indexed oldVerifier,
       address indexed newVerifier
   );
   
   event EmergencyPaused(
       address indexed operator,
       uint256 timestamp
   );

   event EmergencyUnpaused(
       address indexed operator,
       uint256 timestamp
   );

   /**
    * @notice Store encrypted message with ZK proof
    * @param commitment Message commitment
    * @param nullifier Message nullifier for uniqueness
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
    * @param offset Pagination offset
    * @param limit Pagination limit
    * @return messages Array of messages
    */
   function getUserMessages(
       address user,
       uint256 offset,
       uint256 limit
   ) external view returns (Message[] memory messages);

   /**
    * @notice Update verifier contract address
    * @param verifier New verifier address
    */
   function setVerifier(address verifier) external;

   /**
    * @notice Check if nullifier has been used
    * @param nullifier Nullifier to check
    * @return bool True if nullifier is used
    */
   function nullifierUsed(bytes32 nullifier) external view returns (bool);

   /**
    * @notice Get message details by commitment
    * @param commitment Message commitment
    * @return Message struct
    */
   function messages(bytes32 commitment) external view returns (Message memory);

   /**
    * @notice Get user's message commitments
    * @param user User address
    * @return bytes32[] Array of message commitments
    */
   function userMessages(address user) external view returns (bytes32[] memory);

   /**
    * @notice Pause contract in emergency
    */
   function pause() external;

   /**
    * @notice Unpause contract
    */ 
   function unpause() external;
}
