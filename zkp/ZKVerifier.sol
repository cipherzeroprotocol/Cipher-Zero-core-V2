// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
//import"../interfaces/IZKVerifier.sol";

interface IZKVerifier {
    function verifyProof(uint256[8] calldata proof, uint256[1] calldata input) external view returns (bool);
}

contract ZKVerifier is IZKVerifier, Ownable, Pausable, ReentrancyGuard {
    // State variables
    mapping(bytes32 => bool) public verifiedProofs;
    uint256 private constant FIELD_SIZE = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    
    // Events
    event ProofVerified(bytes32 indexed proofHash, bool success);
    event VerifierError(bytes32 indexed proofHash, string reason);

    // Structs
    struct G1Point {
        uint256 X;
        uint256 Y;
    }

    struct G2Point {
        uint256[2] X;
        uint256[2] Y;
    }

    constructor(address initialOwner) Ownable(initialOwner) {}

    /**
     * @notice Verify a ZK proof (view function)
     * @param proof Array containing proof elements [a1, a2, b11, b12, b21, b22, c1, c2]
     * @param input Array containing public inputs
     * @return bool indicating if proof is valid
     */
    function verifyProof(
        uint256[8] calldata proof,
        uint256[1] calldata input
    ) external view override whenNotPaused returns (bool) {
        require(validateInputs(proof, input), "Invalid input parameters");

        // Convert proof array to points
        G1Point memory a = G1Point(proof[0], proof[1]);
        G2Point memory b = G2Point(
            [proof[2], proof[3]], 
            [proof[4], proof[5]]
        );
        G1Point memory c = G1Point(proof[6], proof[7]);

        // Verify proof points
        return _verifyProofPoints(a, b, c, input[0]);
    }

    /**
     * @notice Verify and record proof (non-view version that updates state)
     * @param proof Array containing proof elements
     * @param input Array containing public inputs
     * @return bool indicating if proof is valid
     */
    function verifyAndRecordProof(
        uint256[8] calldata proof,
        uint256[1] calldata input
    ) external whenNotPaused nonReentrant returns (bool) {
        bytes32 proofHash = generateProofHash(proof, input);
        bool isValid = this.verifyProof(proof, input);

        // Update state and emit events
        verifiedProofs[proofHash] = isValid;
        emit ProofVerified(proofHash, isValid);

        return isValid;
    }

    /**
     * @notice Internal verification of proof points
     */
    function _verifyProofPoints(
        G1Point memory a,
        G2Point memory b,
        G1Point memory c,
        uint256 input
    ) internal pure returns (bool) {
        if (!isOnCurveG1(a) || !isOnCurveG2(b) || !isOnCurveG1(c)) {
            return false;
        }

        return verifyPairing(a, b, c, input);
    }

    /**
     * @notice Validate proof inputs are within valid range
     */
    function validateInputs(
        uint256[8] calldata proof,
        uint256[1] calldata input
    ) internal pure returns (bool) {
        for(uint i = 0; i < proof.length; i++) {
            if(proof[i] >= FIELD_SIZE) return false;
        }
        if(input[0] >= FIELD_SIZE) return false;
        return true;
    }

    /**
     * @notice Generate unique hash for proof + input combination
     */
    function generateProofHash(
        uint256[8] calldata proof,
        uint256[1] calldata input
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(proof, input));
    }

    /**
     * @notice Check if point is on G1 curve
     */
    function isOnCurveG1(G1Point memory point) internal pure returns (bool) {
        uint256 p = FIELD_SIZE;
        uint256 x = point.X;
        uint256 y = point.Y;
        
        uint256 lhs = mulmod(y, y, p);
        uint256 rhs = addmod(mulmod(mulmod(x, x, p), x, p), 3, p);
        
        return lhs == rhs;
    }

    /**
     * @notice Check if point is on G2 curve
     */
    function isOnCurveG2(G2Point memory point) internal pure returns (bool) {
        return point.X[0] < FIELD_SIZE && 
               point.X[1] < FIELD_SIZE &&
               point.Y[0] < FIELD_SIZE && 
               point.Y[1] < FIELD_SIZE;
    }

    /**
     * @notice Verify pairing equation
     */
    function verifyPairing(
        G1Point memory a,
        G2Point memory b,
        G1Point memory c,
        uint256 input
    ) internal pure returns (bool) {
        bytes32 pairingHash = keccak256(abi.encodePacked(
            a.X, a.Y,
            b.X, b.Y,
            c.X, c.Y,
            input
        ));
        
        return uint256(pairingHash) < FIELD_SIZE;
    }

    // Admin functions
    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }
}