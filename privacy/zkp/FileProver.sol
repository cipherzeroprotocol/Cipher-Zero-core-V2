// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "../../interfaces/IZKVerifier.sol";
import "../../interfaces/IBitTorrent.sol";

contract FileProver is IZKVerifier, Ownable, ReentrancyGuard, Pausable {
    // Verification key components
    mapping(uint256 => uint256) public alphaComponents;
    mapping(uint256 => mapping(uint256 => uint256)) public betaComponents;
    mapping(uint256 => uint256) public gammaComponents;
    mapping(uint256 => uint256) public deltaComponents;
    mapping(uint256 => mapping(uint256 => uint256)) public icComponents;
    uint256 public icLength;

    struct FileCommitment {
        bytes32 commitment;      
        bytes32 metadataHash;   
        uint256 size;           
        address owner;          
        bool isEncrypted;       
        bytes32 encryptionProof;
        uint256 timestamp;      
    }

    // State variables
    IBitTorrent public immutable bitTorrent;
    mapping(bytes32 => FileCommitment) public files;
    mapping(bytes32 => bool) public nullifierUsed;
    mapping(address => mapping(bytes32 => bool)) public userAccess;
    mapping(bytes32 => mapping(bytes32 => bool)) public fileAccessProofs;

    // Events
    event FileProofVerified(
        bytes32 indexed commitment,
        bytes32 indexed metadataHash,
        address indexed owner,
        uint256 size,
        uint256 timestamp
    );

    event AccessProofVerified(
        bytes32 indexed fileCommitment,
        address indexed user,
        bytes32 accessProof,
        uint256 timestamp
    );

    event EncryptionProofVerified(
        bytes32 indexed fileCommitment,
        bytes32 indexed encryptionProof,
        uint256 timestamp
    );

    constructor(
        address _bitTorrent,
        address _initialOwner
    ) Ownable(_initialOwner) {
        require(_bitTorrent != address(0), "Invalid BitTorrent address");
        bitTorrent = IBitTorrent(_bitTorrent);
    }

    function verifyFileProof(
        bytes32 commitment,
        bytes32 metadataHash,
        uint256 size,
        uint256[8] calldata proof
    ) external nonReentrant whenNotPaused returns (bool) {
        require(commitment != bytes32(0), "Invalid commitment");
        require(files[commitment].commitment == bytes32(0), "File already exists");

        // Convert proof array to expected format and verify
        uint256[1] memory input = [uint256(uint160(msg.sender))];
        
     bool success = bitTorrent.addFile(commitment, metadataHash);
     require(success, "BitTorrent registration failed");
        
        require(
            this.verifyProof(proof, input),
            "Invalid file proof"
        );

        // Store file commitment
        FileCommitment storage newFile = files[commitment];
        newFile.commitment = commitment;
        newFile.metadataHash = metadataHash;
        newFile.size = size;
        newFile.owner = msg.sender;
        newFile.isEncrypted = false;
        newFile.encryptionProof = bytes32(0);
        newFile.timestamp = block.timestamp;

        // Register with BitTorrent integration
        

        emit FileProofVerified(
            commitment,
            metadataHash,
            msg.sender,
            size,
            block.timestamp
        );

        return true;
    }

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

    function initializeVerificationKey(
        uint256[2] calldata _alpha,
        uint256[2][2] calldata _beta,
        uint256[2] calldata _gamma,
        uint256[2] calldata _delta,
        uint256[2][] calldata _ic
    ) external onlyOwner {
        require(_ic.length > 0, "Invalid IC length");
        
        alphaComponents[0] = _alpha[0];
        alphaComponents[1] = _alpha[1];

        for (uint256 i = 0; i < 2; i++) {
            for (uint256 j = 0; j < 2; j++) {
                betaComponents[i][j] = _beta[i][j];
            }
        }

        gammaComponents[0] = _gamma[0];
        gammaComponents[1] = _gamma[1];

        deltaComponents[0] = _delta[0];
        deltaComponents[1] = _delta[1];

        icLength = _ic.length;
        for (uint256 i = 0; i < _ic.length; i++) {
            icComponents[i][0] = _ic[i][0];
            icComponents[i][1] = _ic[i][1];
        }
    }

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