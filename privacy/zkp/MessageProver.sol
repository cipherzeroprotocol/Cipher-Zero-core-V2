// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "../../interfaces/IZKVerifier.sol";
import "../../cryptography/ECDSA.sol";

contract MessageProver is IZKVerifier, Ownable, ReentrancyGuard, Pausable {
    // Store verification key components separately to avoid getter issues
    mapping(uint256 => uint256) public alpha1Components;
    mapping(uint256 => uint256) public beta2Components;
    mapping(uint256 => uint256) public gamma2Components;
    mapping(uint256 => uint256) public delta2Components;
    mapping(uint256 => mapping(uint256 => uint256)) public icComponents;
    uint256 public icLength;

    // Message commitment structure
    struct MessageCommitment {
        bytes32 commitment;    // Commitment to the message
        bytes32 nullifier;     // Unique nullifier
        uint256 timestamp;     // Timestamp of the message
        bool verified;         // Whether proof has been verified
    }

    // State variables
    mapping(bytes32 => MessageCommitment) public messages;
    mapping(bytes32 => bool) public nullifierUsed;
    
    // Events
    event ProofVerified(
        bytes32 indexed commitment,
        bytes32 indexed nullifier,
        address indexed sender,
        uint256 timestamp
    );
    
    event VerifyingKeyUpdated(address indexed updater);

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
     * @notice Verify a message proof
     * @param commitment Message commitment
     * @param nullifier Unique nullifier
     * @param sender Message sender
     * @param recipient Message recipient
     * @param proof ZK proof components
     */
    function verifyMessageProof(
        bytes32 commitment,
        bytes32 nullifier,
        address sender,
        address recipient,
        bytes calldata proof
    ) external nonReentrant whenNotPaused returns (bool) {
        require(!nullifierUsed[nullifier], "Nullifier already used");
        
        // Prepare public inputs
        uint256[1] memory input = [uint256(uint160(sender))];
        
        // Verify the proof
        require(
            this.verifyProof(abi.decode(proof, (uint256[8])), input),
            "Invalid proof"
        );

        // Store message commitment
        messages[commitment] = MessageCommitment({
            commitment: commitment,
            nullifier: nullifier,
            timestamp: block.timestamp,
            verified: true
        });

        // Mark nullifier as used
        nullifierUsed[nullifier] = true;

        emit ProofVerified(commitment, nullifier, sender, block.timestamp);

        return true;
    }

    /**
     * @notice Initialize verification key components
     * @param _alpha1 Alpha1 component values
     * @param _beta2 Beta2 component values
     * @param _gamma2 Gamma2 component values
     * @param _delta2 Delta2 component values
     * @param _ic IC component values
     */
    function initializeVerificationKey(
        uint256[2] calldata _alpha1,
        uint256[2] calldata _beta2,
        uint256[2] calldata _gamma2,
        uint256[2] calldata _delta2,
        uint256[2][] calldata _ic
    ) external onlyOwner {
        require(_ic.length > 0, "Invalid IC length");
        
        alpha1Components[0] = _alpha1[0];
        alpha1Components[1] = _alpha1[1];

        beta2Components[0] = _beta2[0];
        beta2Components[1] = _beta2[1];

        gamma2Components[0] = _gamma2[0];
        gamma2Components[1] = _gamma2[1];

        delta2Components[0] = _delta2[0];
        delta2Components[1] = _delta2[1];

        icLength = _ic.length;
        for (uint256 i = 0; i < _ic.length; i++) {
            icComponents[i][0] = _ic[i][0];
            icComponents[i][1] = _ic[i][1];
        }

        emit VerifyingKeyUpdated(msg.sender);
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
            [alpha1Components[0], alpha1Components[1]],
            [beta2Components[0], beta2Components[1]],
            vk_x,
            [gamma2Components[0], gamma2Components[1]],
            c,
            [delta2Components[0], delta2Components[1]]
        );
    }

    // Implement helper functions with _ prefix
    function _scalarMul(uint256[2] memory p, uint256 s) internal pure returns (uint256, uint256) {
        return (p[0] * s, p[1] * s);
    }

    function _pointAdd(uint256 x1, uint256 y1, uint256 x2, uint256 y2) internal pure returns (uint256, uint256) {
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