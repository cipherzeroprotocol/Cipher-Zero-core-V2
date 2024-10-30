// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "../interfaces/IERC20.sol";
import "../interfaces/DividendPayingTokenInterface.sol";
//import "../interfaces/DividendPayingTokenInterface.sol";
import "../interfaces/ERC20.sol";
import "../interfaces/SafeMath.sol";

/**
 * @title TokenDividendPayingToken
 * @dev Base contract for dividend payments with privacy features
 */
abstract contract TokenDividendPayingToken is ERC20, DividendPayingTokenInterface {
    using SafeMath for uint256;

    // State variables
    uint256 internal constant MAGNITUDE = 2**128;
    uint256 internal magnifiedDividendPerShare;
    uint256 public totalDividendsDistributed;
    
    // Dividend tracking
    mapping(address => int256) internal magnifiedDividendCorrections;
    mapping(address => uint256) internal withdrawnDividends;

    /**
     * @notice View the amount of dividend in wei that an address can withdraw
     * @param account The address of a token holder
     * @return The amount of dividend in wei that `account` can withdraw
     */
    function dividendOf(address account) public view override returns(uint256) {
        return withdrawableDividendOf(account);
    }

    /**
     * @notice View the amount of dividend in wei that an address can withdraw
     * @param account The address of a token holder
     * @return The amount of dividend in wei that `account` can withdraw
     */
    function withdrawableDividendOf(address account) public view override returns(uint256) {
        return accumulativeDividendOf(account).sub(withdrawnDividends[account]);
    }

    /**
     * @notice View the amount of dividend in wei that an address has withdrawn
     * @param account The address of a token holder
     * @return The amount of dividend in wei that `account` has withdrawn
     */
    function withdrawnDividendOf(address account) public view override returns(uint256) {
        return withdrawnDividends[account];
    }

    /**
     * @notice View the amount of dividend in wei that an address has earned in total
     * @param account The address of a token holder
     * @return The amount of dividend in wei that `account` has earned in total
     */
    function accumulativeDividendOf(address account) public view override returns(uint256) {
        return uint256(int256(magnifiedDividendPerShare.mul(balanceOf(account))) + 
            magnifiedDividendCorrections[account]) / MAGNITUDE;
    }

    /**
     * @dev Internal function to distribute dividends
     * @param amount The amount of dividends to distribute
     */
    function _distributeDividends(uint256 amount) internal {
        require(totalSupply() > 0, "No supply");

        if (amount > 0) {
            magnifiedDividendPerShare = magnifiedDividendPerShare.add(
                amount.mul(MAGNITUDE) / totalSupply()
            );
            totalDividendsDistributed = totalDividendsDistributed.add(amount);

            emit DividendsDistributed(msg.sender, amount);
        }
    }

    /**
     * @dev Internal function to withdraw dividends for a user
     * @param user Address of user to withdraw dividends for
     */
    function _withdrawDividendOfUser(address payable user) internal returns (uint256) {
        uint256 withdrawableDividend = withdrawableDividendOf(user);
        if (withdrawableDividend > 0) {
            withdrawnDividends[user] = withdrawnDividends[user].add(withdrawableDividend);
            emit DividendWithdrawn(user, withdrawableDividend);
            user.transfer(withdrawableDividend);
            return withdrawableDividend;
        }
        return 0;
    }

    /**
     * @dev Internal function to set account balance
     * @param account Account to update
     * @param newBalance New balance amount
     */
    function _setBalance(address account, uint256 newBalance) internal {
        uint256 currentBalance = balanceOf(account);
        
        if (newBalance > currentBalance) {
            uint256 addAmount = newBalance.sub(currentBalance);
            _mint(account, addAmount);
        } else if (newBalance < currentBalance) {
            uint256 subAmount = currentBalance.sub(newBalance);
            _burn(account, subAmount);
        }

        int256 correction = int256(magnifiedDividendPerShare.mul(newBalance));
        magnifiedDividendCorrections[account] = correction;
    }
}