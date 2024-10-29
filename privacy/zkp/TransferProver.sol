// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "../../interfaces/IZKVerifier.sol";
import "../../interfaces/IERC20.sol";

contract TransferProver is IZKVerifier, Ownable, ReentrancyGuard, Pausable {
    // Verification key components stored separately
    mapping(uint256 => uint256) public alphaComponents;
    mapping(uint256 => mapping(uint256 => uint256)) public betaComponents;
    mapping(uint256 => uint256) public gammaComponents;
    mapping(uint256 => uint256) public deltaComponents;
    mapping(uint256 => mapping(uint256 => uint256)) public icComponents;
    uint256 public icLength;

    struct Note {
        bytes32 commitment;    
        bytes32 nullifier;     
        uint256 amount;        
        address token;         
        bool spent;           
    }

    // State variables
    mapping(bytes32 => Note) public notes;
    mapping(bytes32 => bool) public nullifierSpent;
    mapping(bytes32 => mapping(uint256 => bytes32)) public merkleTree;
    mapping(address => uint256) public tokenBalances;
    
    uint256 public constant MAX_TRANSFER_AMOUNT = 1000000 * 10**18;
    uint256 public constant MERKLE_TREE_LEVELS = 20;
    uint256 public currentRoot;
    uint256 private nextIndex;

    // Events
    event NoteCreated(
        bytes32 indexed commitment,
        address indexed token,
        uint256 indexed index,
        uint256 timestamp
    );

    event NoteSpent(
        bytes32 indexed nullifier,
        address indexed token,
        uint256 timestamp
    );

    event TransferProofVerified(
        bytes32 indexed inputCommitment,
        bytes32 indexed outputCommitment,
        address indexed token,
        uint256 timestamp
    );

    /**
     * @notice Constructor initializes with owner
     * @param initialOwner Address of the contract owner
     */
    constructor(address initialOwner) Ownable(initialOwner) {
        require(initialOwner != address(0), "Invalid owner address");
    }

    /**
     * @inheritdoc IZKVerifier
     */
    function verifyProof(
        uint256[8] calldata proof,
        uint256[1] calldata input
    ) external view override returns (bool) {
        return _verifyProof(
            [proof[0], proof[1]],  // a
            [[proof[2], proof[3]], [proof[4], proof[5]]], // b
            [proof[6], proof[7]], // c
            input
        );
    }

    /**
     * @notice Internal proof verification
     */
    function _verifyProof(
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[1] memory input
    ) internal view returns (bool) {
        require(input.length + 1 == icLength, "Invalid input length");

        uint256[2] memory vk_x = [icComponents[0][0], icComponents[0][1]];

        for (uint256 i = 0; i < input.length; i++) {
            (uint256 x, uint256 y) = _scalarMul(
                [icComponents[i + 1][0], icComponents[i + 1][1]],
                input[i]
            );
            
            (vk_x[0], vk_x[1]) = _pointAdd(
                vk_x[0],
                vk_x[1],
                x,
                y
            );
        }

        return _verifyPairing(
            a,
            b,
            [alphaComponents[0], alphaComponents[1]],
            [betaComponents[0][0], betaComponents[0][1]],
            vk_x,
            [gammaComponents[0], gammaComponents[1]],
            c,
            [deltaComponents[0], deltaComponents[1]]
        );
    }

    /**
     * @notice Create a new shielded transfer note
     */
    function createNote(
        bytes32 commitment,
        address token,
        uint256 amount,
        uint256[8] calldata proof
    ) external nonReentrant whenNotPaused {
        require(amount <= MAX_TRANSFER_AMOUNT, "Amount exceeds maximum");
        require(notes[commitment].commitment == bytes32(0), "Commitment exists");

        // Verify deposit proof
        uint256[1] memory input = [uint256(uint160(msg.sender))];
        require(
            this.verifyProof(proof, input),
            "Invalid proof"
        );

        // Transfer tokens to contract
        IERC20(token).transferFrom(msg.sender, address(this), amount);

        // Create note
        notes[commitment] = Note({
            commitment: commitment,
            nullifier: bytes32(0),
            amount: amount,
            token: token,
            spent: false
        });

        // Add to merkle tree
        uint256 index = insertIntoMerkleTree(commitment);

        emit NoteCreated(commitment, token, index, block.timestamp);
    }

    /**
     * @notice Spend a note in a private transfer
     */
    function spendNote(
        bytes32 nullifier,
        bytes32 inputCommitment,
        bytes32 outputCommitment,
        uint256[8] calldata proof
    ) external nonReentrant whenNotPaused {
        require(!nullifierSpent[nullifier], "Nullifier already spent");
        
        Note storage spentNote = notes[inputCommitment];
        require(spentNote.commitment == inputCommitment, "Note not found");
        require(!spentNote.spent, "Note already spent");

        // Verify transfer proof
        uint256[1] memory input = [uint256(uint160(msg.sender))];
        require(
            this.verifyProof(proof, input),
            "Invalid proof"
        );

        // Mark nullifier as spent
        nullifierSpent[nullifier] = true;
        spentNote.spent = true;
        spentNote.nullifier = nullifier;

        // Create new note
        notes[outputCommitment] = Note({
            commitment: outputCommitment,
            nullifier: bytes32(0),
            amount: spentNote.amount,
            token: spentNote.token,
            spent: false
        });

        // Add new note to merkle tree
        insertIntoMerkleTree(outputCommitment);

        emit NoteSpent(nullifier, spentNote.token, block.timestamp);
        emit TransferProofVerified(
            inputCommitment,
            outputCommitment,
            spentNote.token,
            block.timestamp
        );
    }

    /**
     * @notice Insert commitment into merkle tree
     */
    function insertIntoMerkleTree(bytes32 commitment) internal returns (uint256) {
        uint256 index = getNextIndex();
        merkleTree[commitment][0] = commitment;

        bytes32 currentHash = commitment;
        for (uint256 i = 0; i < MERKLE_TREE_LEVELS; i++) {
            uint256 siblingIndex = getSiblingIndex(index, i);
            bytes32 sibling = merkleTree[bytes32(0)][siblingIndex];
            
            currentHash = hashPair(currentHash, sibling);
            merkleTree[commitment][i + 1] = currentHash;
        }

        currentRoot = uint256(uint160(bytes20(currentHash)));
        return index;
    }

    /**
 * @notice Get the next available index in merkle tree
 * @return index The next available index
 */
function getNextIndex() internal returns (uint256) {
    uint256 index = nextIndex;
    
    // Ensure we don't exceed max tree capacity
    require(index < 2**MERKLE_TREE_LEVELS, "Merkle tree full");
    
    // Increment index for next use
    nextIndex++;
    
    return index;
}

/**
 * @notice Get current number of elements in the tree
 * @return count Current element count
 */
function getMerkleTreeSize() external view returns (uint256) {
    return nextIndex;
}

/**
 * @notice Check if a commitment exists at given index
 * @param index Position to check
 * @return exists Whether a commitment exists at index
 */
function hasCommitmentAtIndex(uint256 index) public view returns (bool) {
    require(index < 2**MERKLE_TREE_LEVELS, "Index out of bounds");
    
    // Check if there's a non-zero commitment at this index
    bytes32 commitment = merkleTree[bytes32(0)][index];
    return commitment != bytes32(0);
}

/**
 * @notice Get the merkle root
 * @return root Current merkle root
 */
function getMerkleRoot() external view returns (bytes32) {
    return bytes32(currentRoot);
}

/**
 * @notice Get merkle proof for a commitment
 * @param commitment Target commitment
 * @return siblings Array of sibling hashes for proof
 * @return indices Array of indices for proof construction
 */
function getMerkleProof(bytes32 commitment) external view returns (
    bytes32[] memory siblings,
    uint256[] memory indices
) {
    require(notes[commitment].commitment != bytes32(0), "Note not found");

    siblings = new bytes32[](MERKLE_TREE_LEVELS);
    indices = new uint256[](MERKLE_TREE_LEVELS);

    uint256 index = 0;
    // Find index of commitment
    for (uint256 i = 0; i < nextIndex; i++) {
        if (merkleTree[bytes32(0)][i] == commitment) {
            index = i;
            break;
        }
    }

    // Build proof
    for (uint256 i = 0; i < MERKLE_TREE_LEVELS; i++) {
        uint256 siblingIndex = getSiblingIndex(index, i);
        siblings[i] = merkleTree[bytes32(0)][siblingIndex];
        indices[i] = index % 2; // Left or right position
        index = index / 2; // Move up to parent level
    }

    return (siblings, indices);
}

/**
 * @notice Verify a merkle proof
 * @param commitment Target commitment
 * @param siblings Sibling hashes in proof
 * @param indices Position indicators (left/right)
 * @return valid Whether the proof is valid
 */
function verifyMerkleProof(
    bytes32 commitment,
    bytes32[] calldata siblings,
    uint256[] calldata indices
) public view returns (bool) {
    require(siblings.length == MERKLE_TREE_LEVELS, "Invalid proof length");
    require(indices.length == MERKLE_TREE_LEVELS, "Invalid indices length");

    bytes32 currentHash = commitment;
    
    for (uint256 i = 0; i < MERKLE_TREE_LEVELS; i++) {
        bytes32 sibling = siblings[i];
        
        // Order the hashing based on position indicator
        if (indices[i] == 0) {
            currentHash = hashPair(currentHash, sibling);
        } else {
            currentHash = hashPair(sibling, currentHash);
        }
    }

    return bytes32(currentRoot) == currentHash;
}

    /**
     * @notice Get sibling index in merkle tree
     */
    function getSiblingIndex(
        uint256 index,
        uint256 level
    ) internal pure returns (uint256) {
        return index ^ (1 << level);
    }

    /**
     * @notice Hash pair of nodes in merkle tree
     */
    function hashPair(
        bytes32 left,
        bytes32 right
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(left, right));
    }

    function _scalarMul(uint256[2] memory p, uint256 s) internal pure returns (uint256, uint256) {
        // TODO: Implement actual EC scalar multiplication
        return (p[0] * s, p[1] * s);
    }

    function _pointAdd(uint256 x1, uint256 y1, uint256 x2, uint256 y2) internal pure returns (uint256, uint256) {
        // TODO: Implement actual EC point addition
        return (x1 + x2, y1 + y2);
    }

    /**
 * @notice Verify pairing for proof verification
 * @dev Uses bn128 precompiles for efficient pairing checks
 */
function _verifyPairing(
    uint256[2] memory a,
    uint256[2][2] memory b,
    uint256[2] memory alpha,
    uint256[2] memory beta,
    uint256[2] memory vk_x,
    uint256[2] memory gamma,
    uint256[2] memory c,
    uint256[2] memory delta
) internal view returns (bool) {
    // Initialize pairing points array
    uint256[24] memory input;
    
    // Negate a and c for pairing check
    (a[0], a[1]) = _negate(a[0], a[1]);
    (c[0], c[1]) = _negate(c[0], c[1]);

    // First pairing: e(A, B)
    input[0] = a[0];
    input[1] = a[1];
    input[2] = b[0][0];
    input[3] = b[0][1];
    input[4] = b[1][0];
    input[5] = b[1][1];

    // Second pairing: e(alpha, beta)
    input[6] = alpha[0];
    input[7] = alpha[1];
    input[8] = beta[0];
    input[9] = beta[1];
    input[10] = beta[0];
    input[11] = beta[1];

    // Third pairing: e(vk_x, gamma)
    input[12] = vk_x[0];
    input[13] = vk_x[1];
    input[14] = gamma[0];
    input[15] = gamma[1];
    input[16] = gamma[0];
    input[17] = gamma[1];

    // Fourth pairing: e(C, delta)
    input[18] = c[0];
    input[19] = c[1];
    input[20] = delta[0];
    input[21] = delta[1];
    input[22] = delta[0];
    input[23] = delta[1];

    // Perform pairing check using bn128 precompile
    uint256[1] memory out;
    bool success;

    // solium-disable-next-line security/no-inline-assembly
    assembly {
        // Call bn128 pairing precompile at address 0x08
        success := staticcall(gas(), 0x08, input, 0x180, out, 0x20)
    }

    require(success, "Pairing check failed");
    return out[0] == 1;
}

/**
 * @notice Negate a point on the curve
 * @param x X coordinate
 * @param y Y coordinate
 * @return (negX, negY) Negated point
 */
function _negate(uint256 x, uint256 y) internal pure returns (uint256, uint256) {
    // Field modulus
    uint256 q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
    
    if (x == 0 && y == 0) {
        return (0, 0);
    }
    
    // Negate y-coordinate
    return (x, q - (y % q));
}

/**
 * @notice Check if a point is on the curve
 * @param x X coordinate
 * @param y Y coordinate
 * @return valid True if point is on curve
 */
function _isOnCurve(uint256 x, uint256 y) internal pure returns (bool) {
    uint256 p = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
    
    if (x >= p || y >= p) {
        return false;
    }

    // Check y^2 = x^3 + 3 (curve equation for bn128)
    uint256 lhs = mulmod(y, y, p);
    uint256 rhs = addmod(mulmod(mulmod(x, x, p), x, p), 3, p);
    
    return lhs == rhs;
}

    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }
}