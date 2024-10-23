// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "../interfaces/IVerifier.sol";
import "../interfaces/IMessaging.sol";

contract MessageRegistry is IMessaging, Ownable, ReentrancyGuard, Pausable {
    // Verifier contract for message proofs
    IVerifier public verifier;
    
    // Events
    event MessageStored(
        bytes32 indexed commitment,
        address indexed recipient,
        uint256 timestamp
    );
    event MessageRead(bytes32 indexed commitment, uint256 timestamp);
    
    // Mappings
    mapping(bytes32 => Message) public messages;
    mapping(bytes32 => bool) public nullifierUsed;
    mapping(address => bytes32[]) public userMessages;
    
    /**
     * @param _verifier Address of the verifier contract
     * @param _owner Address of the contract owner
     */
    constructor(
        address _verifier,
        address _owner
    ) Ownable(_owner) {
        require(_verifier != address(0), "Invalid verifier address");
        verifier = IVerifier(_verifier);
    }

    /**
     * Store encrypted message with ZK proof
     */
    function storeMessage(
        bytes32 commitment,
        bytes32 nullifier,
        address recipient,
        bytes calldata encryptedContent,
        bytes calldata proof
    ) external override nonReentrant whenNotPaused {
        // Input validation
        require(commitment != bytes32(0), "Invalid commitment");
        require(nullifier != bytes32(0), "Invalid nullifier");
        require(recipient != address(0), "Invalid recipient");
        require(encryptedContent.length > 0, "Empty message");
        require(proof.length > 0, "Empty proof");
        
        // Verify nullifier hasn't been used
        require(!nullifierUsed[nullifier], "Nullifier already used");
        
        // Verify ZK proof
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

        // Store message
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

        // Mark nullifier as used
        nullifierUsed[nullifier] = true;

        // Add to user's messages
        userMessages[recipient].push(commitment);

        emit MessageStored(commitment, recipient, block.timestamp);
    }

    /**
     * Mark message as read
     */
    function markMessageRead(bytes32 commitment) external override {
        require(commitment != bytes32(0), "Invalid commitment");
        
        Message storage message = messages[commitment];
        require(message.commitment != bytes32(0), "Message not found");
        require(message.recipient == msg.sender, "Not message recipient");
        require(!message.isRead, "Message already read");

        message.isRead = true;
        emit MessageRead(commitment, block.timestamp);
    }

    /**
     * Get user's messages
     */
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

    /**
     * Update verifier contract
     */
    function setVerifier(address _verifier) external onlyOwner {
        require(_verifier != address(0), "Invalid verifier address");
        verifier = IVerifier(_verifier);
    }

    /**
     * Emergency pause
     */
    function pause() external onlyOwner {
        _pause();
    }

    /**
     * Unpause
     */
    function unpause() external onlyOwner {
        _unpause();
    }

    /**
     * Get total messages for a user
     */
    function getUserMessageCount(address user) external view returns (uint256) {
        return userMessages[user].length;
    }
}