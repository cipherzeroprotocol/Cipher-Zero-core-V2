// /utils/Address.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/**
 * @dev Collection of functions related to the address type
 */
library Address {
    /**
     * @dev Sends value ETH or tokens to an address
     * @param recipient The address to transfer to
     * @param amount The amount to be transferred
     */
    function sendValue(address payable recipient, uint256 amount) internal {
        require(address(this).balance >= amount, "Address: insufficient balance");

        // solhint-disable-next-line avoid-low-level-calls, avoid-call-value
        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Address: unable to send value, recipient may have reverted");
    }

    /**
     * @dev Returns true if `account` is a contract.
     * @param account The address to query
     */
    function isContract(address account) internal view returns (bool) {
        // This method relies on extcodesize, which returns 0 for contracts in
        // construction, since the code is only stored at the end of the
        // constructor execution.
        uint256 size;
        assembly {
            size := extcodesize(account)
        }
        return size > 0;
    }
}