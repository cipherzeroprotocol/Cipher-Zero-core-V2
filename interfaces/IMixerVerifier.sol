
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

interface IMixerVerifier {
    function verifyProof(
        uint256[8] calldata proof,
        uint256[1] calldata inputs
    ) external view returns (bool);

    function getVerifierID() external view returns (bytes32 identifier);

    function verifyDepositProof(
        bytes calldata proof,
        uint256[] calldata inputs,
        uint256 denomination
    ) external view returns (bool);

    function verifyWithdrawalProof(
        bytes calldata proof,
        uint256[] calldata inputs,
        uint256 denomination
    ) external view returns (bool);
}