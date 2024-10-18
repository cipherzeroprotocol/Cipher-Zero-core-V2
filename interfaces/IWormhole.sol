// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;


interface IWormhole {
    function transferTokens(address token, uint256 amount, uint16 recipientChain, bytes32 recipient, uint32 nonce) external returns (uint64 sequence);
    function completeTransfer(bytes calldata encodedVm) external;
    function sendMessage(bytes memory message, uint32 nonce) external returns (uint64);
    function getNonce() external view returns (uint32);
    function getFees() external view returns (uint256);
    function getChainId() external view returns (uint16);
    function getBridgeAddress() external view returns (address);
    function getWrappedAssetAddress(address token) external view returns (address);
    function getWrappedAssetOwner(address token) external view returns (address);
    function getWrappedAssetEvmScriptHash(address token) external view returns (bytes32);
    function getWrappedAssetChainId(address token) external view returns (uint16);
    function getWrappedAssetName(address token) external view returns (string memory);
    function getWrappedAssetSymbol(address token) external view returns (string memory);
    function getWrappedAssetDecimals(address token) external view returns (uint8);
    function getWrappedAssetMetadata(address token) external view returns (address, address, bytes32, uint16, string memory, string memory, uint8);
    function getWrappedAssetNonce(address token) external view returns (uint32);
    function getWrappedAssetTotalSupply(address token) external view returns (uint256);
    function getWrappedAssetBalance(address token, address account) external view returns (uint256);
    function getWrappedAssetAllowance(address token, address owner, address spender) external view returns (uint256);
    function getWrappedAssetTransferAllowance(address token, address spender) external view returns (uint256);
    function getWrappedAssetApproveAllowance(address token, address spender) external view returns (uint256);
}