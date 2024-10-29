// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "../../interfaces/IVerifier.sol";
import "../../interfaces/IMixerVerifier.sol";

/**
 * @title TornadoPool
 * @notice Privacy pool for token mixing in Cipher Zero Protocol
 * @dev Implements a zkSNARK-based mixing protocol
 */
contract TornadoPool is Ownable, ReentrancyGuard, Pausable {
    // Pool denomination structure
    struct Denomination {
        uint256 amount;        // Fixed amount for this denomination
        uint256 depositsCount; // Number of deposits
        bool enabled;          // Denomination status
    }

    // Note structure
    struct Note {
        bytes32 commitment;    // Note commitment
        uint32 timestamp;      // Deposit timestamp
        uint256 denomination;  // Note denomination
        bytes encryptedNote;   // Encrypted note data
    }

    // Merkle tree structure
    struct MerkleTree {
        bytes32[] leaves;      // Tree leaves
        uint256 nextIndex;     // Next available index
        bytes32 root;          // Current root
        mapping(uint256 => mapping(uint256 => bytes32)) branches; // Tree branches
    }

    // Events
    event Deposit(
        bytes32 indexed commitment,
        uint256 indexed denomination,
        uint32 leafIndex,
        uint256 timestamp
    );

    event Withdrawal(
        address indexed recipient,
        bytes32 indexed nullifier,
        address indexed relayer,
        uint256 denomination,
        uint256 fee
    );

    event DenominationEnabled(uint256 denomination);
    event DenominationDisabled(uint256 denomination);

    // Constants
    uint256 public constant MERKLE_TREE_HEIGHT = 20;
    uint256 public constant MAX_DEPOSIT_COUNT = 2**MERKLE_TREE_HEIGHT;
    uint256 public constant MAX_FEE_PERCENT = 2; // 2%

    // State variables
    IERC20 public token;
    IMixerVerifier public verifier;
    
    mapping(bytes32 => bool) public nullifierHashes;
    mapping(uint256 => Denomination) public denominations;
    mapping(bytes32 => Note) public notes;
    
    MerkleTree public merkleTree;
    uint256 public denominationCount;
    
    /**
     * @notice Constructor
     * @param _token Token to be mixed
     * @param _verifier Verifier contract
     */
     constructor(
        address initialOwner,
        address _token, 
        address _verifier
    ) Ownable(initialOwner) {
        token = IERC20(_token);
        verifier = IMixerVerifier(_verifier);
        merkleTree.nextIndex = 0;
    }

    /**
     * @notice Deposit tokens into mixing pool
     * @param commitment Note commitment
     * @param denomination Deposit amount denomination
     * @param encryptedNote Encrypted note data
     */
    function deposit(
        bytes32 commitment,
        uint256 denomination,
        bytes calldata encryptedNote
    ) external nonReentrant whenNotPaused {
        // Verify denomination exists and is enabled
        require(denominations[denomination].enabled, "Invalid denomination");
        require(merkleTree.nextIndex < MAX_DEPOSIT_COUNT, "Tree full");

        // Transfer tokens to pool
        token.transferFrom(msg.sender, address(this), denomination);

        // Create note
        notes[commitment] = Note({
            commitment: commitment,
            timestamp: uint32(block.timestamp),
            denomination: denomination,
            encryptedNote: encryptedNote
        });

        // Insert into merkle tree
        uint32 leafIndex = _insert(commitment);
        
        // Update denomination stats
        denominations[denomination].depositsCount++;

        emit Deposit(
            commitment, 
            denomination,
            leafIndex,
            block.timestamp
        );
    }

    /**
     * @notice Withdraw mixed tokens
     * @param proof zkSNARK proof
     * @param nullifierHash Nullifier hash
     * @param recipient Recipient address
     * @param relayer Relayer address
     * @param fee Relayer fee
     * @param denomination Withdrawal denomination
     */
    function withdraw(
    uint256[8] calldata proof,
    bytes32 nullifierHash,
    address recipient,
    address relayer,
    uint256 fee,
    uint256 denomination
) external nonReentrant whenNotPaused {
    // Verify inputs
    require(fee <= denomination * MAX_FEE_PERCENT / 100, "Fee too high");
    require(!nullifierHashes[nullifierHash], "Note already spent");
    require(denominations[denomination].enabled, "Invalid denomination");

    // Prepare inputs for proof verification
    uint256[1] memory inputs;
    inputs[0] = uint256(uint256(nullifierHash)) +
                uint256(uint160(recipient)) * (2 ** 160) +
                uint256(uint160(relayer)) * (2 ** 208) +
                fee * (2 ** 248) +
                denomination;

    // Verify the proof
    require(
        verifier.verifyProof(proof, inputs),
        "Invalid proof"
    );

    // Mark nullifier as spent
    nullifierHashes[nullifierHash] = true;

    // Transfer tokens
    if (fee > 0) {
        token.transfer(relayer, fee);
    }
    token.transfer(recipient, denomination - fee);

    emit Withdrawal(
        recipient,
        nullifierHash,
        relayer,
        denomination,
        fee
    );
}

        
    

    /**
     * @notice Add new denomination
     * @param amount Denomination amount
     */
    function addDenomination(uint256 amount) external onlyOwner {
        require(amount > 0, "Invalid amount");
        require(!denominations[amount].enabled, "Denomination exists");

        denominations[amount] = Denomination({
            amount: amount,
            depositsCount: 0,
            enabled: true
        });

        denominationCount++;
        emit DenominationEnabled(amount);
    }

    /**
     * @notice Disable denomination
     * @param amount Denomination amount
     */
    function disableDenomination(uint256 amount) external onlyOwner {
        require(denominations[amount].enabled, "Denomination not enabled");
        denominations[amount].enabled = false;
        denominationCount--;
        emit DenominationDisabled(amount);
    }

    /**
     * @notice Insert commitment into merkle tree
     * @param commitment Note commitment
     * @return Index in tree
     */
    function _insert(bytes32 commitment) internal returns (uint32) {
        uint32 currentIndex = uint32(merkleTree.nextIndex);
        require(currentIndex < MAX_DEPOSIT_COUNT, "Tree full");

        // Insert leaf
        merkleTree.leaves.push(commitment);
        merkleTree.branches[currentIndex][0] = commitment;

        // Update tree
        uint256 currentLevel = 0;
        uint256 currentLevelIndex = currentIndex;
        bytes32 left;
        bytes32 right;

        while (currentLevel < MERKLE_TREE_HEIGHT) {
            if (currentLevelIndex % 2 == 0) {
                // Right empty
                left = merkleTree.branches[currentLevelIndex][currentLevel];
                right = zeros(currentLevel);
                merkleTree.branches[currentLevelIndex][currentLevel + 1] = 
                    hashLeftRight(left, right);
            } else {
                // Left sibling exists
                left = merkleTree.branches[currentLevelIndex - 1][currentLevel];
                right = merkleTree.branches[currentLevelIndex][currentLevel];
                merkleTree.branches[currentLevelIndex - 1][currentLevel + 1] = 
                    hashLeftRight(left, right);
            }
            
            currentLevelIndex /= 2;
            currentLevel++;
        }

        // Update root
        merkleTree.root = merkleTree.branches[0][MERKLE_TREE_HEIGHT];
        merkleTree.nextIndex++;

        return currentIndex;
    }

    /**
     * @notice Hash left and right nodes
     * @param left Left node
     * @param right Right node
     */
    function hashLeftRight(
        bytes32 left,
        bytes32 right
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(left, right));
    }

    /**
     * @notice Get zero value for level
     * @param level Tree level
     */
    function zeros(uint256 level) internal pure returns (bytes32) {
        if (level == 0) return bytes32(0);
        return hashLeftRight(zeros(level - 1), zeros(level - 1));
    }

    /**
     * @notice Get merkle tree root
     */
    function getRoot() external view returns (bytes32) {
        return merkleTree.root;
    }

    /**
     * @notice Get merkle tree path
     * @param index Leaf index
     */
    function getPath(uint256 index) external view returns (bytes32[] memory) {
        require(index < merkleTree.nextIndex, "Index out of bounds");

        bytes32[] memory path = new bytes32[](MERKLE_TREE_HEIGHT);
        uint256 currentIndex = index;

        for (uint256 i = 0; i < MERKLE_TREE_HEIGHT; i++) {
            uint256 siblingIndex;
            if (currentIndex % 2 == 0) {
                siblingIndex = currentIndex + 1;
            } else {
                siblingIndex = currentIndex - 1;
            }

            path[i] = merkleTree.branches[siblingIndex][i];
            currentIndex /= 2;
        }

        return path;
    }

    // Emergency functions
    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }


}
