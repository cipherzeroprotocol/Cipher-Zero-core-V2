// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;


import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/utils/math/Math.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

interface IProofVerifier {
    function verifyProof(
        bytes calldata proof,
        uint256[] calldata inputs
    ) external view returns (bool);
}

/**
 * @title ProofGeneration
 * @dev This contract is responsible for generating zk-SNARKs proofs for transactions and data validation.
 */
contract ProofGeneration is AccessControl, EIP712 {
    using Math for uint256;
    using Strings for string;

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");

    IProofVerifier public proofVerifier;

    event ProofGenerated(address indexed user, string proofId);

    constructor(string memory name, string memory version, address _proofVerifier) EIP712(name, version) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        proofVerifier = IProofVerifier(_proofVerifier);
    }

    /**
     * @dev Generate zk-SNARK proof for a transaction or data.
     * @param proof The zk-SNARK proof.
     * @param inputs The inputs used for the proof.
     * @param proofId Unique identifier for the proof.
     */
    function generateProof(bytes calldata proof, uint256[] calldata inputs, string calldata proofId) external onlyRole(VERIFIER_ROLE) {
        require(proofVerifier.verifyProof(proof, inputs), "ProofGeneration: Invalid proof");

        emit ProofGenerated(msg.sender, proofId);
    }

    /**
     * @dev Set a new proof verifier contract address.
     * @param _proofVerifier The address of the new proof verifier contract.
     */
    function setProofVerifier(address _proofVerifier) external onlyRole(ADMIN_ROLE) {
        proofVerifier = IProofVerifier(_proofVerifier);
    }

    /**
     * @dev Grant the verifier role to an account.
     * @param account The account to grant the verifier role to.
     */
    function grantVerifierRole(address account) external onlyRole(DEFAULT_ADMIN_ROLE) {
        grantRole(VERIFIER_ROLE, account);
    }

    /**
     * @dev Revoke the verifier role from an account.
     * @param account The account to revoke the verifier role from.
     */
    function revokeVerifierRole(address account) external onlyRole(DEFAULT_ADMIN_ROLE) {
        revokeRole(VERIFIER_ROLE, account);
    }

    /**
     * @dev Check if an account has the verifier role.
     * @param account The account to check.
     * @return True if the account has the verifier role, false otherwise.
     */
    function hasVerifierRole(address account) external view returns (bool) {
        return hasRole(VERIFIER_ROLE, account);
    }
}