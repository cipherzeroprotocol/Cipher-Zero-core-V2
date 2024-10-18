// SPDX-License-Identifier: MIT

pragma solidity ^0.8.26;

interface IZKVerifier {
    function verifyProof(uint256[8] calldata proof, uint256[1] calldata input) external view returns (bool);
}