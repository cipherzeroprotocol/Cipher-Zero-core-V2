// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "../interfaces/IVerifier.sol";



contract PrivacyPool is Ownable, ReentrancyGuard, Pausable {
    // State variables
    IVerifier public verifier;
    IERC20 public token;
    
    // Constants
    uint256 public constant MIN_DEPOSIT = 1e6;  // Minimum deposit amount
    uint256 public constant MAX_DEPOSIT = 1e24; // Maximum deposit amount

    // Pool note structure
    struct Note {
        bytes32 commitment;    // Note commitment
        bytes32 nullifier;     // Uniqueness nullifier
        uint256 amount;        // Amount in note
        bool spent;           // Spent status
        uint256 timestamp;    // Creation timestamp
    }

    // Mappings
    mapping(bytes32 => Note) public notes;          // commitment -> Note
    mapping(bytes32 => bool) public nullifierUsed;  // nullifier -> used status
    
    // Events
    event NoteDeposited(
        bytes32 indexed commitment,
        uint256 amount,
        uint256 timestamp
    );
    
    event NoteWithdrawn(
        bytes32 indexed nullifier,
        address indexed recipient,
        uint256 amount,
        uint256 timestamp
    );
    
    event VerifierUpdated(
        address indexed oldVerifier,
        address indexed newVerifier,
        uint256 timestamp
    );
    
    event EmergencyWithdrawal(
        address indexed owner,
        uint256 amount,
        uint256 timestamp
    );
    
    /**
     * @param _token Address of the ERC20 token
     * @param _verifier Address of the verifier contract
     * @param _owner Address of the contract owner
     */
    constructor(
        address _token,
        address _verifier,
        address _owner
    ) Ownable(_owner) {
        require(_token != address(0), "Invalid token address");
        require(_verifier != address(0), "Invalid verifier address");
        
        token = IERC20(_token);
        verifier = IVerifier(_verifier);
    }

    /**
     * @notice Deposit tokens into privacy pool
     * @param commitment The note commitment
     * @param amount The deposit amount
     * @param proof Zero-knowledge proof
     */
    function deposit(
        bytes32 commitment,
        uint256 amount,
        bytes calldata proof
    ) external nonReentrant whenNotPaused {
        // Validate inputs
        require(commitment != bytes32(0), "Invalid commitment");
        require(amount >= MIN_DEPOSIT, "Amount below minimum");
        require(amount <= MAX_DEPOSIT, "Amount above maximum");
        require(notes[commitment].commitment == bytes32(0), "Commitment exists");
        require(proof.length > 0, "Empty proof");

        // Verify deposit proof
        require(
            verifier.verifyDepositProof(
                commitment,
                amount,
                msg.sender,
                proof
            ),
            "Invalid proof"
        );

        // Transfer tokens to pool
        uint256 balanceBefore = token.balanceOf(address(this));
        require(
            token.transferFrom(msg.sender, address(this), amount),
            "Transfer failed"
        );
        require(
            token.balanceOf(address(this)) == balanceBefore + amount,
            "Invalid transfer amount"
        );

        // Store note
        notes[commitment] = Note({
            commitment: commitment,
            nullifier: bytes32(0),
            amount: amount,
            spent: false,
            timestamp: block.timestamp
        });

        emit NoteDeposited(commitment, amount, block.timestamp);
    }

    /**
     * @notice Withdraw tokens from privacy pool
     * @param nullifier The note nullifier
     * @param commitment The note commitment
     * @param recipient The recipient address
     * @param amount The withdrawal amount
     * @param proof Zero-knowledge proof
     */
    function withdraw(
        bytes32 nullifier,
        bytes32 commitment,
        address recipient,
        uint256 amount,
        bytes calldata proof
    ) external nonReentrant whenNotPaused {
        // Validate inputs
        require(nullifier != bytes32(0), "Invalid nullifier");
        require(commitment != bytes32(0), "Invalid commitment");
        require(recipient != address(0), "Invalid recipient");
        require(amount > 0, "Invalid amount");
        require(!nullifierUsed[nullifier], "Nullifier used");
        
        Note storage note = notes[commitment];
        require(note.commitment != bytes32(0), "Note not found");
        require(!note.spent, "Note spent");
        require(amount <= note.amount, "Insufficient balance");
        require(proof.length > 0, "Empty proof");

        // Verify withdrawal proof
        require(
            verifier.verifyWithdrawProof(
                nullifier,
                commitment,
                recipient,
                amount,
                proof
            ),
            "Invalid proof"
        );

        // Mark nullifier as used and note as spent
        nullifierUsed[nullifier] = true;
        note.spent = true;
        note.nullifier = nullifier;

        // Transfer tokens
        uint256 balanceBefore = token.balanceOf(recipient);
        require(
            token.transfer(recipient, amount),
            "Transfer failed"
        );
        require(
            token.balanceOf(recipient) == balanceBefore + amount,
            "Invalid transfer amount"
        );

        emit NoteWithdrawn(nullifier, recipient, amount, block.timestamp);
    }

    /**
     * @notice Get pool balance
     * @return uint256 Current pool balance
     */
    function getBalance() external view returns (uint256) {
        return token.balanceOf(address(this));
    }

    /**
     * @notice Update verifier contract
     * @param _verifier New verifier address
     */
    function setVerifier(address _verifier) external onlyOwner {
        require(_verifier != address(0), "Invalid verifier address");
        address oldVerifier = address(verifier);
        verifier = IVerifier(_verifier);
        emit VerifierUpdated(oldVerifier, _verifier, block.timestamp);
    }

    /**
     * @notice Emergency pause
     */
    function pause() external onlyOwner {
        _pause();
    }

    /**
     * @notice Unpause
     */
    function unpause() external onlyOwner {
        _unpause();
    }

    /**
     * @notice Emergency token withdrawal by owner
     */
    function emergencyWithdraw() external onlyOwner {
        uint256 balance = token.balanceOf(address(this));
        require(balance > 0, "No balance");
        
        require(
            token.transfer(owner(), balance),
            "Transfer failed"
        );
        
        emit EmergencyWithdrawal(owner(), balance, block.timestamp);
    }

    /**
     * @notice Get note details
     * @param commitment Note commitment
     * @return Note structure
     */
    function getNoteDetails(bytes32 commitment) external view returns (Note memory) {
        return notes[commitment];
    }

    /**
     * @notice Check if nullifier has been used
     * @param nullifier The nullifier to check
     * @return bool True if nullifier has been used
     */
    function isNullifierUsed(bytes32 nullifier) external view returns (bool) {
        return nullifierUsed[nullifier];
    }
}