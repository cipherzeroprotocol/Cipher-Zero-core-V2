// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;
interface ICipherDividendTracker {
    function processAccountDividends(address account) external returns (bool);
    function excludeFromDividends(address account, bool value) external;
    function trackerRescueETH20Tokens(address recipient, address tokenAddress) external;
    function trackerForceSend(address recipient) external;
    function updateLP_Token(address _lpToken) external;
}