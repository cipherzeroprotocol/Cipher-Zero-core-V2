// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;


import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/math/Math.sol";
import "../interfaces/IWormhole.sol";
// Remove the duplicate declaration of the interface

// Correctly declare the contract once and fix the constructor visibility
contract WormholeBridge is AccessControl, Pausable {
    IWormhole public wormhole;

    // Remove the duplicate constructor
    constructor(address _wormholeAddress) {
        wormhole = IWormhole(_wormholeAddress);
    }

    // This function is correctly placed inside your contract that interacts with IWormhole
    function sendMessageToWormhole(bytes memory message, uint32 nonce) public returns (uint64) {
        // Assuming sendMessage is a method in IWormhole
        return wormhole.sendMessage(message, nonce);
    }
    using Math for uint256;

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    
    IWormhole public wormholeTokenBridge;

    struct Message {
        address token;
        uint256 amount;
        uint16 destinationChainId;
        address destinationAddress;
    }

    event TokensBridged(address indexed token, address indexed from, uint256 amount, uint16 destinationChainId, address destinationAddress);

    // This constructor initialization has been removed because it is a duplicate.

    function bridgeTokens(address token, uint256 amount, uint16 destinationChainId, address destinationAddress) external whenNotPaused {
        require(IERC20(token).balanceOf(msg.sender) >= amount, "Insufficient balance");
        
        // Transfer tokens from the sender to this contract
        IERC20(token).transferFrom(msg.sender, address(this), amount);

        // Prepare Wormhole message
        Message memory message = Message({
            token: token,
            amount: amount,
            destinationChainId: destinationChainId,
            destinationAddress: destinationAddress
        });

        // Call the sendMessageToWormhole function of the WormholeBridge contract
        // This function should return a sequence number for the message
        uint64 nonce = 0; // Declare the nonce variable
        uint32 sequence = uint32(sendMessageToWormhole(abi.encode(message), uint32(nonce))); // Explicitly convert uint64 to uint32
        (sequence);

        emit TokensBridged(token, msg.sender, amount, destinationChainId, destinationAddress);
    }

    function receiveTokens(address token, uint256 amount, address recipient) external onlyRole(ADMIN_ROLE) {
        // Mint or release tokens to the recipient
        IERC20(token).transfer(recipient, amount);
    }

    function pause() external onlyRole(ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(ADMIN_ROLE) {
        _unpause();
    }
}
