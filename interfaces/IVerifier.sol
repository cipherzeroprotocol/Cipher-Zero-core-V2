// IVerifier.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

interface IVerifier {
    /**
     * Verify a message proof
     */
    function verifyMessageProof(
        bytes32 commitment,
        bytes32 nullifier,
        address sender,
        address recipient,
        bytes calldata encryptedContent,
        bytes calldata proof
    ) external view returns (bool);



    function verifyDepositProof(

        bytes32 commitment,

        uint256 amount,

        address sender,

        bytes calldata proof

    ) external view returns (bool);



    function verifyWithdrawProof(

        bytes32 nullifier,

        bytes32 commitment,

        address recipient,

        uint256 amount,

        bytes calldata proof

    ) external view returns (bool);

}

