// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;


import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/math/Math.sol";
import "../interfaces/IWormhole.sol";

contract WormholeBridge is AccessControl, Pausable {
    using Math for uint256;

    // Constants
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    uint8 public constant CONSISTENCY_LEVEL = 1;

    // Wormhole integration
    IWormhole public immutable wormhole;

    // Message structure
    struct Message {
        address token;
        uint256 amount;
        uint16 destinationChainId;
        address destinationAddress;
    }

    // Events
    event TokensBridged(
        address indexed token,
        address indexed from,
        uint256 amount,
        uint16 destinationChainId,
        address destinationAddress,
        uint64 sequence
    );

    event TokensReceived(
        address indexed token,
        address indexed recipient,
        uint256 amount,
        uint16 sourceChainId
    );

    constructor(address _wormhole) {
        require(_wormhole != address(0), "Invalid Wormhole address");
        wormhole = IWormhole(_wormhole);
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);
    }

    /**
     * @notice Bridge tokens to another chain
     * @dev Must send enough ETH to cover Wormhole fee
     * @param token Token address to bridge
     * @param amount Amount of tokens to bridge 
     * @param destinationChainId Target chain ID
     * @param destinationAddress Recipient address on target chain
     */
    function bridgeTokens(
        address token,
        uint256 amount,
        uint16 destinationChainId,
        address destinationAddress
    ) external payable whenNotPaused {
        require(amount > 0, "Amount must be greater than 0");
        require(destinationAddress != address(0), "Invalid destination address");
        require(IERC20(token).balanceOf(msg.sender) >= amount, "Insufficient balance");

        // Get required Wormhole fee
        uint256 fee = wormhole.messageFee();
        require(msg.value >= fee, "Insufficient Wormhole fee");

        // Transfer tokens from sender to this contract
        require(
            IERC20(token).transferFrom(msg.sender, address(this), amount),
            "Transfer failed"
        );

        // Prepare message
        Message memory message = Message({
            token: token,
            amount: amount,
            destinationChainId: destinationChainId,
            destinationAddress: destinationAddress
        });

        // Publish message to Wormhole
        uint64 sequence = wormhole.publishMessage{value: fee}(
            0, // nonce
            abi.encode(message),
            CONSISTENCY_LEVEL
        );

        // Refund excess fee if any
        uint256 excess = msg.value - fee;
        if (excess > 0) {
            (bool success, ) = msg.sender.call{value: excess}("");
            require(success, "Fee refund failed");
        }

        emit TokensBridged(
            token,
            msg.sender,
            amount,
            destinationChainId,
            destinationAddress,
            sequence
        );
    }

    function receiveTokens(
        bytes calldata encodedVM
    ) external whenNotPaused {
        // Parse and verify the VAA
        (
            IWormhole.VM memory vm,
            bool valid,
            string memory reason
        ) = wormhole.parseAndVerifyVM(encodedVM);

        require(valid, reason);

        // Decode the message
        Message memory message = abi.decode(vm.payload, (Message));
        
        require(
            IERC20(message.token).transfer(message.destinationAddress, message.amount),
            "Token transfer failed"
        );

        emit TokensReceived(
            message.token,
            message.destinationAddress,
            message.amount,
            vm.emitterChainId
        );
    }

    /**
     * @notice Withdraw accidentally sent tokens
     * @param token Token address to withdraw
     * @param to Address to send tokens to
     * @param amount Amount to withdraw
     */
    function withdrawTokens(
        address token,
        address to,
        uint256 amount
    ) external onlyRole(ADMIN_ROLE) {
        require(to != address(0), "Invalid address");
        require(
            IERC20(token).transfer(to, amount),
            "Transfer failed"
        );
    }

    /**
     * @notice Withdraw accidentally sent ETH
     * @param to Address to send ETH to
     * @param amount Amount to withdraw
     */
    function withdrawETH(
        address payable to,
        uint256 amount
    ) external onlyRole(ADMIN_ROLE) {
        require(to != address(0), "Invalid address");
        (bool success, ) = to.call{value: amount}("");
        require(success, "ETH transfer failed");
    }

    function pause() external onlyRole(ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(ADMIN_ROLE) {
        _unpause();
    }

    /**
     * @dev Allow receiving ETH for Wormhole fees
     */
    receive() external payable {}
}