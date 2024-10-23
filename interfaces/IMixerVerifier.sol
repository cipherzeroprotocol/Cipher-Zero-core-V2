// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IMixerVerifier {
    /**
     * @dev Verifies a zk-SNARK proof for a given transaction.
     * @param proof Array containing the zk-SNARK proof (proof.A, proof.B, proof.C).
     * @param input Array containing the public inputs required for the zk-SNARK verification.
     * @return success Boolean indicating whether the proof is valid.
     */
    function verifyProof(
        uint256[8] calldata proof,
        uint256[1] calldata input
    ) external view returns (bool success);
    
    /**
     * @dev Returns the verifier's unique identifier (could be a version or type identifier).
     * @return identifier Bytes32 representing the verifier's ID.
     */
    function getVerifierID() external view returns (bytes32 identifier);
}
