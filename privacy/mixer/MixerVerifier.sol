// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "../../interfaces/IMixerVerifier.sol";

contract MixerVerifier is IMixerVerifier, Ownable, ReentrancyGuard, Pausable {
    // State variables
    uint256[2] public alpha1;
    uint256[2][2] public beta2;
    uint256[2] public gamma2;
    uint256[2] public delta2;
    mapping(uint256 => uint256[2][]) public inputCoefficients;

    struct Proof {
        uint256[2] a;
        uint256[2][2] b;
        uint256[2] c;
    }

    mapping(bytes32 => bool) public verifiedProofs;
    mapping(uint256 => bool) public supportedDenominations;
    uint256[] public denominations;
    
    uint256 public constant MAX_INPUTS = 10;
    uint256 public constant FIELD_SIZE = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    bytes32 public immutable verifierIdentifier;

    // Events
    event DenominationAdded(uint256 indexed denomination, uint256 timestamp);
    event DenominationRemoved(uint256 indexed denomination, uint256 timestamp);
    event ProofVerified(bytes32 indexed nullifierHash, bytes32 indexed commitment, uint256 indexed denomination);

    constructor(
        address initialOwner,
        uint256[] memory _denominations,
        uint256[2] memory _alpha1,
        uint256[2][2] memory _beta2,
        uint256[2] memory _gamma2,
        uint256[2] memory _delta2,
        uint256[2][][] memory _ic,
        bytes32 _identifier
    ) Ownable(initialOwner) {
        require(_denominations.length == _ic.length, "Invalid input lengths");
        
        alpha1 = _alpha1;
        beta2 = _beta2;
        gamma2 = _gamma2;
        delta2 = _delta2;
        verifierIdentifier = _identifier;

        for (uint256 i = 0; i < _denominations.length; i++) {
            _addDenomination(_denominations[i], _ic[i]);
        }
    }

    function verifyProof(
    uint256[8] calldata proof,
    uint256[1] calldata inputs
) external view override whenNotPaused returns (bool) {
    // Convert inputs to dynamic array
    uint256[] memory inputArray = new uint256[](1);
    inputArray[0] = inputs[0];

    Proof memory grothProof = Proof({
        a: [proof[0], proof[1]],
        b: [[proof[2], proof[3]], [proof[4], proof[5]]],
        c: [proof[6], proof[7]]
    });

    return _verifyProof(
        grothProof, 
        inputArray,  // Pass the converted array
        inputCoefficients[denominations[0]]
    );
}

    function getVerifierID() external view override returns (bytes32) {
        return verifierIdentifier;
    }

    function verifyDepositProof(
        bytes calldata proof,
        uint256[] calldata inputs,
        uint256 denomination
    ) external view override whenNotPaused returns (bool) {
        require(supportedDenominations[denomination], "Unsupported denomination");
        require(inputs.length <= MAX_INPUTS, "Too many inputs");

        Proof memory depositProof = abi.decode(proof, (Proof));
        _verifyInputRanges(inputs);

        return _verifyProof(depositProof, inputs, inputCoefficients[denomination]);
    }

    function verifyWithdrawalProof(
        bytes calldata proof,
        uint256[] calldata inputs,
        uint256 denomination
    ) external view override whenNotPaused returns (bool) {
        require(supportedDenominations[denomination], "Unsupported denomination");
        require(inputs.length <= MAX_INPUTS, "Too many inputs");

        Proof memory withdrawalProof = abi.decode(proof, (Proof));
        _verifyInputRanges(inputs);

        bytes32 proofHash = keccak256(abi.encodePacked(proof, inputs));
        require(!verifiedProofs[proofHash], "Proof already used");

        return _verifyProof(withdrawalProof, inputs, inputCoefficients[denomination]);
    }

    function _verifyProof(
        Proof memory proofData,
        uint256[] memory inputs,
        uint256[2][] memory ic
    ) internal view returns (bool) {
        require(inputs.length + 1 == ic.length, "Invalid input length");

        uint256[2] memory vk_x = _computeLinearCombination(inputs, ic);

        return _verifyPairing(
            proofData,
            vk_x,
            alpha1,
            beta2,
            gamma2,
            delta2
        );
    }

    function _computeLinearCombination(
    uint256[] memory inputs,
    uint256[2][] memory ic
) internal view returns (uint256[2] memory) { // Changed from pure to view
    uint256[2] memory vk_x = ic[0];

    for (uint256 i = 0; i < inputs.length; i++) {
        require(inputs[i] < FIELD_SIZE, "Input too large");
        
        (uint256 x, uint256 y) = _scalarMul(ic[i + 1], inputs[i]);
        (vk_x[0], vk_x[1]) = _pointAdd(vk_x[0], vk_x[1], x, y);
    }

    return vk_x;
}

    function _verifyPairing(
        Proof memory proofData,
        uint256[2] memory vk_x,
        uint256[2] memory alpha1_points,
        uint256[2][2] memory beta2_points,
        uint256[2] memory gamma2_points,
        uint256[2] memory delta2_points
    ) internal view returns (bool) {
        uint256[24] memory input;

        input[0] = proofData.a[0];
        input[1] = proofData.a[1];
        input[2] = proofData.b[0][0];
        input[3] = proofData.b[0][1];
        input[4] = proofData.b[1][0];
        input[5] = proofData.b[1][1];
        input[6] = alpha1_points[0];
        input[7] = alpha1_points[1];
        input[8] = beta2_points[0][0];
        input[9] = beta2_points[0][1];
        input[10] = beta2_points[1][0];
        input[11] = beta2_points[1][1];
        input[12] = vk_x[0];
        input[13] = vk_x[1];
        input[14] = gamma2_points[0];
        input[15] = gamma2_points[1];
        input[16] = proofData.c[0];
        input[17] = proofData.c[1];
        input[18] = delta2_points[0];
        input[19] = delta2_points[1];

        uint256[1] memory out;
        bool success;

        assembly {
            success := staticcall(gas(), 8, input, 768, out, 32)
        }

        require(success, "Pairing check failed");
        return out[0] == 1;
    }

    function _verifyInputRanges(uint256[] memory inputs) internal pure {
        for (uint256 i = 0; i < inputs.length; i++) {
            require(inputs[i] < FIELD_SIZE, "Input too large");
        }
    }

    function _addDenomination(
        uint256 denomination,
        uint256[2][] memory ic
    ) internal {
        require(!supportedDenominations[denomination], "Denomination exists");
        require(ic.length > 0, "Empty IC array");

        supportedDenominations[denomination] = true;
        denominations.push(denomination);
        
        for (uint256 i = 0; i < ic.length; i++) {
            inputCoefficients[denomination].push(ic[i]);
        }

        emit DenominationAdded(denomination, block.timestamp);
    }

    function addDenomination(
        uint256 denomination,
        uint256[2][] calldata ic
    ) external onlyOwner {
        _addDenomination(denomination, ic);
    }

    function removeDenomination(uint256 denomination) external onlyOwner {
        require(supportedDenominations[denomination], "Denomination not found");
        
        supportedDenominations[denomination] = false;
        delete inputCoefficients[denomination];

        for (uint256 i = 0; i < denominations.length; i++) {
            if (denominations[i] == denomination) {
                denominations[i] = denominations[denominations.length - 1];
                denominations.pop();
                break;
            }
        }

        emit DenominationRemoved(denomination, block.timestamp);
    }

    function _scalarMul(
    uint256[2] memory p,
    uint256 s
) internal view returns (uint256, uint256) {  // Changed from pure to view
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
) internal view returns (uint256, uint256) {  // Changed from pure to view
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


}
