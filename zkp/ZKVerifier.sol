// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";


interface IZKVerifier {
    function verifyProof(uint256[8] calldata proof, uint256[1] calldata input) external view returns (bool);
}

contract ZKVerifier is IZKVerifier, Ownable, Pausable, ReentrancyGuard {
    // Constants
    uint256 private constant FIELD_SIZE = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 private constant SNARK_SCALAR_FIELD = 21888242871839275222246405745257275088597967272855293219849000405095575973152;
    uint256 private constant BN128_CURVE_ORDER = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
    
    // Rate limiting
    uint256 private constant MAX_VERIFICATIONS_PER_BLOCK = 50;
    mapping(uint256 => uint256) private blockVerificationCount;
    
    // State
    mapping(bytes32 => bool) public verifiedProofs;
    mapping(bytes32 => uint256) private verificationTimes;
    
    // Structs
    struct G1Point {
        uint256 X;
        uint256 Y;
    }

    struct G2Point {
        uint256[2] X;
        uint256[2] Y;
    }

    // Events
    event ProofVerified(
        bytes32 indexed proofHash,
        address indexed verifier,
        bool indexed success,
        uint256 timestamp
    );
    
    event VerifierError(
        bytes32 indexed proofHash,
        string reason,
        uint256 timestamp
    );

    constructor(address initialOwner) Ownable(initialOwner) {
        require(initialOwner != address(0), "Invalid owner");
        _pause(); // Start paused for security
    }

    function verifyProof(
        uint256[8] calldata proof,
        uint256[1] calldata input
    ) external view override whenNotPaused returns (bool) {
        require(validateInputs(proof, input), "Invalid inputs");

        G1Point memory a = G1Point(proof[0], proof[1]);
        G2Point memory b = G2Point(
            [proof[2], proof[3]], 
            [proof[4], proof[5]]
        );
        G1Point memory c = G1Point(proof[6], proof[7]);

        return _verifyProofPoints(a, b, c, input[0]);
    }

    function verifyAndRecordProof(
        uint256[8] calldata proof,
        uint256[1] calldata input
    ) external whenNotPaused nonReentrant returns (bool) {
        require(
            blockVerificationCount[block.number] < MAX_VERIFICATIONS_PER_BLOCK,
            "Rate limit exceeded"
        );

        bytes32 proofHash = generateProofHash(proof, input);
        require(!verifiedProofs[proofHash], "Proof already verified");

        bool isValid;
        try this.verifyProof(proof, input) returns (bool result) {
            isValid = result;
        } catch Error(string memory reason) {
            emit VerifierError(proofHash, reason, block.timestamp);
            return false;
        }

        verifiedProofs[proofHash] = isValid;
        verificationTimes[proofHash] = block.timestamp;
        blockVerificationCount[block.number]++;

        emit ProofVerified(
            proofHash,
            msg.sender,
            isValid,
            block.timestamp
        );

        return isValid;
    }

    function _verifyProofPoints(
    G1Point memory a,
    G2Point memory b,
    G1Point memory c,
    uint256 input
) internal view returns (bool) {
    if (!isOnCurveG1(a) || !isOnCurveG2(b) || !isOnCurveG1(c)) {
        return false;
    }

    uint256[24] memory pairingInput;
    bool success; // Variable for the final result after assembly block

    assembly {
        // Load points into pairing input array
        mstore(pairingInput, mload(a))
        mstore(add(pairingInput, 0x20), mload(add(a, 0x20)))
        
        let bPtr := add(b, 0x20)
        mstore(add(pairingInput, 0x40), mload(bPtr))
        mstore(add(pairingInput, 0x60), mload(add(bPtr, 0x20)))
        mstore(add(pairingInput, 0x80), mload(add(bPtr, 0x40)))
        mstore(add(pairingInput, 0xA0), mload(add(bPtr, 0x60)))

        let successInAssembly := staticcall(
            gas(),
            8,  // Call precompile at address 8
            pairingInput,
            768, // 24 * 32 bytes
            pairingInput,
            0x20
        )
        
        if iszero(successInAssembly) {
            revert(0, 0)
        }
        
        success := mload(pairingInput)
    }

        return success;
    }

    function validateInputs(
        uint256[8] calldata proof,
        uint256[1] calldata input
    ) internal pure returns (bool) {
        for(uint256 i = 0; i < 8; i++) {
            if(proof[i] >= FIELD_SIZE) return false;
        }
        if(input[0] >= FIELD_SIZE) return false;
        return true;
    }

    function isOnCurveG1(G1Point memory point) internal pure returns (bool) {
        uint256 p = FIELD_SIZE;
        if (point.X >= p || point.Y >= p) {
            return false;
        }
        
        uint256 lhs = mulmod(point.Y, point.Y, p);
        uint256 rhs = addmod(mulmod(mulmod(point.X, point.X, p), point.X, p), 3, p);
        
        return lhs == rhs;
    }

    function isOnCurveG2(G2Point memory point) internal pure returns (bool) {
        return point.X[0] < FIELD_SIZE && 
               point.X[1] < FIELD_SIZE &&
               point.Y[0] < FIELD_SIZE && 
               point.Y[1] < FIELD_SIZE;
    }

    function generateProofHash(
        uint256[8] calldata proof,
        uint256[1] calldata input
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(proof, input));
    }

    function clearOldBlockCounts(uint256 blocksBack) external onlyOwner {
        require(blocksBack > 0, "Invalid block count");
        uint256 targetBlock = block.number - blocksBack;
        
        for (uint256 i = 0; i < blocksBack; i++) {
            delete blockVerificationCount[targetBlock - i];
        }
    }

    function getVerificationInfo(
        bytes32 proofHash
    ) external view returns (bool verified, uint256 verificationTime) {
        return (verifiedProofs[proofHash], verificationTimes[proofHash]);
    }

    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }
}