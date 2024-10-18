// SPDX-License-Identifier: MIT

pragma solidity ^0.8.26;

import "@openzeppelin/contracts/access/Ownable.sol";
import "../interfaces/IZKVerifier.sol";

/**
 * @title IPAnonymizer
 * @dev This contract enables the registration and verification of anonymized IP addresses
 *      using zk-SNARKs for privacy-preserving proof. The contract owner can update
 *      the zk-SNARK verifier if needed.
 */
contract IPAnonymizer is Ownable {
    // The zk-SNARK verifier contract
    IZKVerifier public verifier;

    // Mapping to track anonymized IP hashes
    mapping(bytes32 => bool) private anonymizedIPs;

    // Event emitted when a new IP hash is anonymized
    event AnonymizedIPRegistered(bytes32 indexed ipHash);

    // Event emitted when the zk-SNARK verifier is updated
    event VerifierUpdated(address indexed newVerifier);

    /**
     * @dev Constructor that initializes the zk-SNARK verifier.
     * @param _verifier Address of the zk-SNARK verifier contract
     */
    constructor(address _verifier) Ownable(msg.sender) {
        require(_verifier != address(0), "Invalid verifier address");
        verifier = IZKVerifier(_verifier);
    }

    /**
     * @dev Registers an anonymized IP by verifying the zk-SNARK proof.
     * @param ipHash The hash of the IP address to be anonymized
     * @param proof The zk-SNARK proof for anonymization
     * @param publicInputs The public inputs for the proof verification
     */
    function registerAnonymizedIP(
        bytes32 ipHash,
        uint256[8] calldata proof,
        uint256[1] calldata publicInputs
    ) external {
        require(!anonymizedIPs[ipHash], "IP address already anonymized");
        require(verifier.verifyProof(proof, publicInputs), "Invalid zk-SNARK proof");

        anonymizedIPs[ipHash] = true;
        emit AnonymizedIPRegistered(ipHash);
    }

    /**
     * @dev Returns whether an IP address has been anonymized.
     * @param ipHash The hash of the IP address to check
     * @return True if the IP has been anonymized, false otherwise
     */
    function isIPAnonymized(bytes32 ipHash) external view returns (bool) {
        return anonymizedIPs[ipHash];
    }

    /**
     * @dev Updates the zk-SNARK verifier contract address. Restricted to the contract owner.
     * @param _newVerifier The address of the new zk-SNARK verifier contract
     */
    function updateVerifier(address _newVerifier) external onlyOwner {
        require(_newVerifier != address(0), "Invalid verifier address");
        verifier = IZKVerifier(_newVerifier);
        emit VerifierUpdated(_newVerifier);
    }

    /**
     * @dev Revokes the anonymization of an IP, if necessary. Restricted to the contract owner.
     * @param ipHash The hash of the IP address to be de-anonymized
     */
    function revokeAnonymizedIP(bytes32 ipHash) external onlyOwner {
        require(anonymizedIPs[ipHash], "IP not anonymized");
        anonymizedIPs[ipHash] = false;
    }
}
