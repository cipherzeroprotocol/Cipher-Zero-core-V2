// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "../../interfaces/IMixerVerifier.sol";

/**
 * @title MixerVerifier
 * @notice Verifies zero-knowledge proofs for private transactions in Cipher Zero Protocol's mixer
 * @dev Implements verification for deposit and withdrawal proofs using Groth16
 */
contract MixerVerifier is IMixerVerifier, Ownable, ReentrancyGuard, Pausable {
    // Verifying key structure for deposits and withdrawals
    struct VerifyingKey {
        uint256[2] alpha1;
        uint256[2][2] beta2;
        uint256[2] gamma2;
        uint256[2] delta2;
        mapping(uint256 => uint256[2][]) ic; // Denomination -> Input Coefficients
    }

    // Proof structure for Groth16
    struct Proof {
        uint256[2] a;
        uint256[2][2] b;
        uint256[2] c;
    }

    // State variables
    VerifyingKey public verifyingKey;
    mapping(bytes32 => bool) public verifiedProofs;
    mapping(uint256 => bool) public supportedDenominations;
    
    uint256[] public denominations;
    uint256 public constant MAX_INPUTS = 10;
    uint256 public constant FIELD_SIZE = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    // Events
    event ProofVerified(
        bytes32 indexed nullifierHash,
        bytes32 indexed commitment,
        uint256 indexed denomination,
        uint256 timestamp
    );

    event DenominationAdded(
        uint256 indexed denomination,
        uint256 timestamp
    );

    event DenominationRemoved(
        uint256 indexed denomination,
        uint256 timestamp
    );

    /**
     * @notice Constructor sets initial verifying keys and denominations
     * @param _denominations Array of supported denominations
     * @param _alpha1 Alpha1 point of verifying key
     * @param _beta2 Beta2 point of verifying key
     * @param _gamma2 Gamma2 point of verifying key
     * @param _delta2 Delta2 point of verifying key
     * @param _ic Array of input coefficient arrays for each denomination
     */
    constructor(
        uint256[] memory _denominations,
        uint256[2] memory _alpha1,
        uint256[2][2] memory _beta2,
        uint256[2] memory _gamma2,
        uint256[2] memory _delta2,
        uint256[2][][] memory _ic
    ) {
        require(_denominations.length == _ic.length, "Invalid input lengths");

        verifyingKey.alpha1 = _alpha1;
        verifyingKey.beta2 = _beta2;
        verifyingKey.gamma2 = _gamma2;
        verifyingKey.delta2 = _delta2;

        for (uint256 i = 0; i < _denominations.length; i++) {
            _addDenomination(_denominations[i], _ic[i]);
        }
    }

    /**
     * @notice Verify a deposit proof
     * @param proof Serialized proof data
     * @param inputs Public inputs (commitment, nullifierHash)
     * @param denomination Token denomination
     */
    function verifyDepositProof(
        bytes calldata proof,
        uint256[] calldata inputs,
        uint256 denomination
    ) external view override whenNotPaused returns (bool) {
        require(supportedDenominations[denomination], "Unsupported denomination");
        require(inputs.length <= MAX_INPUTS, "Too many inputs");

        // Decode proof
        Proof memory depositProof = abi.decode(proof, (Proof));

        // Verify input ranges
        _verifyInputRanges(inputs);

        // Verify the proof using denomination-specific IC
        return _verifyProof(
            depositProof,
            inputs,
            verifyingKey.ic[denomination]
        );
    }

    /**
     * @notice Verify a withdrawal proof
     * @param proof Serialized proof data
     * @param inputs Public inputs (nullifierHash, recipient, fee)
     * @param denomination Token denomination
     */
    function verifyWithdrawalProof(
        bytes calldata proof,
        uint256[] calldata inputs,
        uint256 denomination
    ) external view override whenNotPaused returns (bool) {
        require(supportedDenominations[denomination], "Unsupported denomination");
        require(inputs.length <= MAX_INPUTS, "Too many inputs");

        // Decode proof
        Proof memory withdrawalProof = abi.decode(proof, (Proof));

        // Verify input ranges
        _verifyInputRanges(inputs);

        // Generate proof hash for replay protection
        bytes32 proofHash = keccak256(abi.encodePacked(proof, inputs));
        require(!verifiedProofs[proofHash], "Proof already used");

        // Verify the proof using denomination-specific IC
        return _verifyProof(
            withdrawalProof,
            inputs,
            verifyingKey.ic[denomination]
        );
    }

    /**
     * @notice Verify a proof using Groth16 verification
     * @param proof Proof components
     * @param inputs Public inputs
     * @param ic Input coefficients
     */
    function _verifyProof(
        Proof memory proof,
        uint256[] memory inputs,
        uint256[2][] memory ic
    ) internal view returns (bool) {
        require(inputs.length + 1 == ic.length, "Invalid input length");

        // Compute linear combination of inputs
        uint256[2] memory vk_x = _computeLinearCombination(inputs, ic);

        // Verify pairing
        return _verifyPairing(
            proof,
            vk_x,
            verifyingKey.alpha1,
            verifyingKey.beta2,
            verifyingKey.gamma2,
            verifyingKey.delta2
        );
    }

    /**
     * @notice Compute linear combination for verification
     * @param inputs Public inputs
     * @param ic Input coefficients
     */
    function _computeLinearCombination(
        uint256[] memory inputs,
        uint256[2][] memory ic
    ) internal pure returns (uint256[2] memory) {
        uint256[2] memory vk_x = ic[0];

        for (uint256 i = 0; i < inputs.length; i++) {
            require(inputs[i] < FIELD_SIZE, "Input too large");
            
            (uint256 x, uint256 y) = _scalarMul(ic[i + 1], inputs[i]);
            (vk_x[0], vk_x[1]) = _pointAdd(vk_x[0], vk_x[1], x, y);
        }

        return vk_x;
    }

    /**
     * @notice Verify pairing for proof validation
     */
    function _verifyPairing(
        Proof memory proof,
        uint256[2] memory vk_x,
        uint256[2] memory alpha1,
        uint256[2][2] memory beta2,
        uint256[2] memory gamma2,
        uint256[2] memory delta2
    ) internal view returns (bool) {
        uint256[24] memory input;

        // Prepare pairing inputs
        input[0] = proof.a[0];
        input[1] = proof.a[1];
        input[2] = proof.b[0][0];
        input[3] = proof.b[0][1];
        input[4] = proof.b[1][0];
        input[5] = proof.b[1][1];
        input[6] = alpha1[0];
        input[7] = alpha1[1];
        input[8] = beta2[0][0];
        input[9] = beta2[0][1];
        input[10] = beta2[1][0];
        input[11] = beta2[1][1];
        input[12] = vk_x[0];
        input[13] = vk_x[1];
        input[14] = gamma2[0];
        input[15] = gamma2[1];
        input[16] = proof.c[0];
        input[17] = proof.c[1];
        input[18] = delta2[0];
        input[19] = delta2[1];

        // Call pairing precompile
        uint256[1] memory out;
        bool success;

        assembly {
            success := staticcall(gas(), 8, input, 768, out, 32)
        }

        require(success, "Pairing check failed");
        return out[0] == 1;
    }

    /**
     * @notice Verify input ranges
     * @param inputs Array of inputs to verify
     */
    function _verifyInputRanges(uint256[] memory inputs) internal pure {
        for (uint256 i = 0; i < inputs.length; i++) {
            require(inputs[i] < FIELD_SIZE, "Input too large");
        }
    }

    /**
     * @notice Add a new supported denomination
     * @param denomination Token denomination
     * @param ic Input coefficients for the denomination
     */
    function _addDenomination(
        uint256 denomination,
        uint256[2][] memory ic
    ) internal {
        require(!supportedDenominations[denomination], "Denomination exists");
        require(ic.length > 0, "Empty IC array");

        supportedDenominations[denomination] = true;
        denominations.push(denomination);
        
        for (uint256 i = 0; i < ic.length; i++) {
            verifyingKey.ic[denomination].push(ic[i]);
        }

        emit DenominationAdded(denomination, block.timestamp);
    }

    /**
     * @notice Add a new denomination (owner only)
     */
    function addDenomination(
        uint256 denomination,
        uint256[2][] calldata ic
    ) external onlyOwner {
        _addDenomination(denomination, ic);
    }

    /**
     * @notice Remove a denomination (owner only)
     */
    function removeDenomination(uint256 denomination) external onlyOwner {
        require(supportedDenominations[denomination], "Denomination not found");
        
        supportedDenominations[denomination] = false;
        delete verifyingKey.ic[denomination];

        // Remove from denominations array
        for (uint256 i = 0; i < denominations.length; i++) {
            if (denominations[i] == denomination) {
                denominations[i] = denominations[denominations.length - 1];
                denominations.pop();
                break;
            }
        }

        emit DenominationRemoved(denomination, block.timestamp);
    }

    // Elliptic curve operations
    function _scalarMul(
        uint256[2] memory p,
        uint256 s
    ) internal pure returns (uint256, uint256) {
        uint256[3] memory input;
        input[0] = p[0];
        input[1] = p[1];
        input[2] = s;

        uint256[2] memory result;
        bool success;

        assembly {
            success := staticcall(gas(), 7, input, 96, result, 64)
        }

        require(success, "Scalar multiplication failed");
        return (result[0], result[1]);
    }

    function _pointAdd(
        uint256 x1,
        uint256 y1,
        uint256 x2,
        uint256 y2
    ) internal pure returns (uint256, uint256) {
        uint256[4] memory input;
        input[0] = x1;
        input[1] = y1;
        input[2] = x2;
        input[3] = y2;

        uint256[2] memory result;
        bool success;

        assembly {
            success := staticcall(gas(), 6, input, 128, result, 64)
        }

        require(success, "Point addition failed");
        return (result[0], result[1]);
    }

    // Emergency functions
    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }
}