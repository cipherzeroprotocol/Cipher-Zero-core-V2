// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "../interfaces/DividendPayingToken.sol";
import "../interfaces/Ownable.sol";
import "../interfaces/IDex.sol";
import "../interfaces/IERC20.sol";
import "../interfaces/IZKVerifier.sol";
import "./CipherDividendTracker.sol";
import "./Address.sol";
import "../interfaces/IZKVerifier.sol";
import "../interfaces/ICipherDividendTracker.sol";

/**
 * @title CipherZeroToken
 * @dev Token for Cipher Zero Protocol with privacy features and zk-SNARK integration
 */
contract CipherZeroToken is ERC20, Ownable {
    using Address for address payable;

    IRouter public router;
    address public pair;
    IZKVerifier public zkVerifier;
    CipherDividendTracker public dividendTracker;
    bool private swapping;
    bool public swapEnabled = true;
    bool public privacyEnabled;
    bool public tradingEnabled;

    
    //CipherDividendTracker public dividendTracker;

    address public treasuryWallet;
    address public devWallet;
    address public lpToken;

    uint256 public constant PRIVACY_POOL_MIN = 1000 * 10**18;
    uint256 public swapTokensAtAmount = 500_000 * 10**18;
    uint256 public maxBuyAmount = 1_000_000 * 10**18;
    uint256 public maxSellAmount = 1_000_000 * 10**18;

    struct Taxes {
    uint256 rewards;
    uint256 treasury;
    uint256 privacy;
    uint256 dev;
    uint256 liquidity;  // Added liquidity field
}
    
    struct ExcludeMultipleAccountsFromFeesData{
        address[] accounts;
        bool excluded;
    }
    
    struct PrivacyPool {
    uint256 balance;
    uint256 lastMixTime;
    uint256 participantCount;
    bytes32 merkleRoot;
    }

    Taxes public buyTaxes = Taxes(2,2,2,2,2);  // Added liquidity value
Taxes public sellTaxes = Taxes(3,3,3,1,3);  // Added liquidity value

    uint256 public totalBuyTax = 8;
    uint256 public totalSellTax = 10;

    // Privacy mappings
    mapping(bytes32 => bool) public usedNullifiers;
    mapping(address => bool) public isPrivacyPool;
    mapping(address => bool) private _isExcludedFromFees;
    mapping(address => bool) public automatedMarketMakerPairs;
    mapping(uint256 => PrivacyPool) public privacyPools;
mapping(uint256 => mapping(bytes32 => bool)) public poolCommitments; // denomination => commitment => exists
mapping(uint256 => mapping(bytes32 => bool)) public poolNullifiers; // denomination => nullifier => used
mapping(uint256 => bytes32[]) private poolCommitmentsList; // denomination => list of commitments
  uint256[] public supportedDenominations; // Valid pool sizes (e.g., 100, 1000, 10000)
uint256 public constant MIN_PARTICIPANTS = 3; // Minimum participants for mixing
uint256 public constant MIX_COOLDOWN = 1 hours; // Time between mixes
event SetAutomatedMarketMakerPair(address indexed pair, bool indexed value);
event SendDividends(uint256 tokensSwapped, uint256 amount);
event ExcludeMultipleAccountsFromFees(address[] accounts, bool excluded);
event LPTokenUpdated(address indexed oldLPToken, address indexed newLPToken);

// Add with other state variables
bool public claimEnabled;
mapping(address => bool) public _isBot;
event PrivacyPoolDeposit(uint256 indexed denomination, bytes32 commitment);
event PrivacyPoolMix(uint256 indexed denomination, bytes32 merkleRoot);
event PrivacyPoolWithdraw(uint256 indexed denomination, bytes32 nullifier);
    // Events
    event PrivateTransfer(bytes32 indexed nullifier, bytes32 indexed commitment);
    event PrivacyPoolCreated(address indexed creator, uint256 amount);
    event PrivacyPoolClosed(address indexed pool);
    event ExcludeFromFees(address indexed account, bool isExcluded);

    struct PrivateTransferData {
        bytes32 nullifier;
        bytes32 commitment;
        bytes proof;
        address recipient;
        uint256 amount;
    }

    constructor(
        address _zkVerifier,
        address _router,
        address _treasury,
        address _dev
    ) ERC20("CipherZero", "CZT") {
        zkVerifier = IZKVerifier(_zkVerifier);
        treasuryWallet = _treasury;
        devWallet = _dev;

        dividendTracker = new CipherDividendTracker();

        IRouter router_ = IRouter(_router);
        address pair_ = IFactory(router_.factory()).createPair(address(this), router_.WETH());

        router = router_;
        pair = pair_;

        _setAutomatedMarketMakerPair(pair_, true);
        
        // Setup exclusions
        excludeFromFees(owner(), true);
        excludeFromFees(address(this), true);
        excludeFromFees(treasuryWallet, true);
        excludeFromFees(devWallet, true);

        _mint(owner(), 1_000_000_000 * (10**18));
    }

    address public LP_Token;  // Add with other state variables

    /**
 * @dev Implementation for distributing dividends for Cipher Zero Protocol
 * Add this to your CipherZeroToken contract
 */

uint256 private constant MAGNITUDE = 2**128;
uint256 private magnifiedDividendPerShare;
mapping(address => int256) private magnifiedDividendCorrections;
mapping(address => uint256) private withdrawnDividends;
uint256 public totalDividendsDistributed;


  mapping(address => bool) public excludedFromDividends;
    mapping(address => uint256) public lastClaimTimes;
    mapping(bytes32 => bool) public usedProofs;

    event ExcludeFromDividends(address indexed account, bool value);
    event Claim(address indexed account, uint256 amount);
    event DividendProcessed(address indexed account, uint256 amount);

    // Events
    event DividendDistributed(address indexed from, uint256 amount);
    event PrivacyPoolCreated(uint256 denomination);
  // Added liquidity value to Taxes struct for zk-SNARK integration of privacy features.


 /**
     * @notice Process account for dividend distribution
     * @param account The account to process
     * @return bool True if processing was successful
     */
    function processAccount(address payable account) external onlyOwner returns (bool) {
        require(account != address(0), "Invalid address");
        require(!excludedFromDividends[account], "Account excluded from dividends");
        
        uint256 amount = _withdrawDividendOfUser(account);
        
        if (amount > 0) {
            lastClaimTimes[account] = block.timestamp;
            emit Claim(account, amount);
            emit DividendProcessed(account, amount);
            return true;
        }
        
        return false;
    }


/**
 * @notice Update merkle tree with new commitment
 */
function updateMerkleTree(
    uint256 denomination,
    bytes32 commitment
) private {
    // Add commitment to list
    poolCommitmentsList[denomination].push(commitment);
    
    // Get current tree elements
    bytes32[] memory elements = poolCommitmentsList[denomination];
    
    // Recalculate merkle root
    bytes32 newRoot = calculateMerkleRoot(elements);
    
    // Update pool's merkle root
    privacyPools[denomination].merkleRoot = newRoot;
}



/**
 * @dev Internal function to distribute dividends
 * @param amount Amount of dividends to distribute
 */
function _distributeDividends(uint256 amount) internal {
    require(totalSupply() > 0, "No supply for dividend distribution");

    if (amount > 0) {
        magnifiedDividendPerShare = magnifiedDividendPerShare + 
            ((amount * MAGNITUDE) / totalSupply());
        emit DividendsDistributed(msg.sender, amount);

        totalDividendsDistributed = totalDividendsDistributed + amount;
    }
}

/**
 * @notice View the amount of dividend in wei that an address can withdraw
 * @param account The address of a token holder
 * @return The amount of dividend in wei that `account` can withdraw
 */


/**
 * @notice View the amount of dividend in wei that an address has withdrawn
 * @param account The address of a token holder
 * @return The amount of dividend in wei that `account` has withdrawn
 */
function withdrawnDividendOf(address account) public view returns(uint256) {
    return withdrawnDividends[account];
}

/**
 * @notice View the amount of dividend in wei that an address has earned in total
 * @param account The address of a token holder
 * @return The amount of dividend in wei that `account` has earned in total
 */
function accumulativeDividendOf(address account) public view returns(uint256) {
    return uint256(int256(magnifiedDividendPerShare * balanceOf(account)) + 
        magnifiedDividendCorrections[account]) / MAGNITUDE;
}

/**
 * @dev Internal function to withdraw accumulated dividends
 */
function _withdrawDividendOfUser(address payable user) internal returns (uint256) {
    uint256 _withdrawableDividend = withdrawableDividendOf(user);
    if (_withdrawableDividend > 0) {
        withdrawnDividends[user] = withdrawnDividends[user] + _withdrawableDividend;
        emit DividendWithdrawn(user, _withdrawableDividend);
        (bool success,) = user.call{value: _withdrawableDividend}("");
        if(!success) {
            withdrawnDividends[user] = withdrawnDividends[user] - _withdrawableDividend;
            return 0;
        }
        return _withdrawableDividend;
    }
    return 0;
}

/**
 * @dev Internal function to update dividend corrections when transferring tokens
 */
function _updateDividendCorrections(
    address from,
    address to,
    uint256 amount
) internal {
    if (amount == 0) return;

    int256 correctionAmount = int256(magnifiedDividendPerShare * amount);
    magnifiedDividendCorrections[from] = magnifiedDividendCorrections[from] + correctionAmount;
    magnifiedDividendCorrections[to] = magnifiedDividendCorrections[to] - correctionAmount;
}

// Add this event if not already defined
event DividendsDistributed(
    address indexed from,
    uint256 amount
);

event DividendWithdrawn(
    address indexed to,
    uint256 amount
);

function updateLP_Token(address _lpToken) external onlyOwner {
    LP_Token = _lpToken;
}

function distributeLPDividends(uint256 amount) external {
    require(msg.sender == owner(), "Only owner");
    _distributeDividends(amount);
}

    // Private transfer functionality
    function privateTransfer(PrivateTransferData calldata data) external {
        require(privacyEnabled, "Privacy features not enabled");
        require(!usedNullifiers[data.nullifier], "Nullifier already used");
        
        // Verify ZK proof
        require(
            zkVerifier.verifyTransferProof(
                data.nullifier,
                data.commitment, 
                data.amount,
                msg.sender,
                data.recipient,
                data.proof
            ),
            "Invalid ZK proof"
        );

        usedNullifiers[data.nullifier] = true;
        
        _transfer(msg.sender, data.recipient, data.amount);
        
        emit PrivateTransfer(data.nullifier, data.commitment);
    }

    // Privacy pool functionality 
    function createPrivacyPool(uint256 amount, bytes calldata proof) external {
        require(amount >= PRIVACY_POOL_MIN, "Below minimum pool amount");
        require(!isPrivacyPool[msg.sender], "Already a privacy pool");

        // Verify pool creation proof
        require(
            zkVerifier.verifyPoolCreationProof(
                amount,
                msg.sender,
                proof
            ),
            "Invalid pool proof"
        );

        isPrivacyPool[msg.sender] = true;
        _transfer(msg.sender, address(this), amount);
        
        emit PrivacyPoolCreated(msg.sender, amount);
    }

    

    // Fee distribution with privacy pool support
    function swapAndDistribute(uint256 amount) private {
        Taxes memory taxes = automatedMarketMakerPairs[address(0)] ? sellTaxes : buyTaxes;
        
        uint256 privacyAmount = amount * taxes.privacy / 100;
        uint256 treasuryAmount = amount * taxes.treasury / 100;
        uint256 devAmount = amount * taxes.dev / 100;
        uint256 rewardsAmount = amount * taxes.rewards / 100;

        // Handle privacy pool funds
        if(privacyAmount > 0) {
            addToPrivacyPool(privacyAmount);
        }

        // Convert and distribute other fees
        swapTokensForETH(treasuryAmount + devAmount + rewardsAmount);
        
        uint256 ethBalance = address(this).balance;
        uint256 totalTax = taxes.treasury + taxes.dev + taxes.rewards;
        
        if(ethBalance > 0) {
            payable(treasuryWallet).sendValue(ethBalance * taxes.treasury / totalTax);
            payable(devWallet).sendValue(ethBalance * taxes.dev / totalTax);
            dividendTracker.distributeDividends{value: address(this).balance}();
        }
    }

    /**
 * @notice Add tokens to privacy pool with ZK commitment
 * @param amount The amount of tokens to add to privacy pool
 * @dev Manages deposit into appropriate denomination pool with privacy protections
 */
/**
 * @notice Add tokens to privacy pool with ZK commitment
 * @param amount The amount of tokens to add to privacy pool
 * @dev Manages deposit into appropriate denomination pool with privacy protections
 */
function addToPrivacyPool(uint256 amount) private {
    require(amount > 0, "Invalid amount");
    
    // Find appropriate denomination pool
    uint256 denomination = findPoolDenomination(amount);
    require(denomination > 0, "Invalid denomination");

    PrivacyPool storage pool = privacyPools[denomination];

    // Generate commitment using ZK proof
    bytes32 commitment = generateCommitment(
        amount,
        msg.sender,
        block.timestamp
    );
    
    // Use separate mapping instead of struct mapping
    require(!poolCommitments[denomination][commitment], "Commitment exists");

    // Update pool state
    pool.balance += amount;
    pool.participantCount++;
    
    // Store commitment in separate mapping
    poolCommitments[denomination][commitment] = true;
    poolCommitmentsList[denomination].push(commitment);

    // Update merkle tree
    updateMerkleTree(denomination, commitment);

    // Check if pool is ready for mixing
    if (shouldMixPool(pool)) {
        mixPool(denomination);
    }

    emit PrivacyPoolDeposit(denomination, commitment);
}

/**
 * @notice Generate commitment for privacy pool deposit
 */
function generateCommitment(
    uint256 amount,
    address depositor,
    uint256 timestamp
) private view returns (bytes32) {
    return keccak256(
        abi.encodePacked(
            amount,
            depositor,
            timestamp,
            blockhash(block.number - 1)
        )
    );
}

/**
 * @notice Find appropriate denomination pool for amount
 */
function findPoolDenomination(uint256 amount) private view returns (uint256) {
    for (uint256 i = 0; i < supportedDenominations.length; i++) {
        if (amount >= supportedDenominations[i]) {
            return supportedDenominations[i];
        }
    }
    return 0; // No valid denomination found
}
/**
 * @notice Get merkle tree elements from pool
 */
function getMerkleElements(PrivacyPool storage pool) private view returns (bytes32[] memory) {
    bytes32[] memory elements = new bytes32[](pool.participantCount);
    uint256 index = 0;
    
    // Note: This is a simplified implementation - you'll need to add actual logic
    // to retrieve elements from your storage structure
    return elements;
}

/**
 * @notice Append element to array
 */
function appendElement(bytes32[] memory elements, bytes32 element) private pure returns (bytes32[] memory) {
    bytes32[] memory newElements = new bytes32[](elements.length + 1);
    for (uint256 i = 0; i < elements.length; i++) {
        newElements[i] = elements[i];
    }
    newElements[elements.length] = element;
    return newElements;
}

/**
 * @notice Calculate merkle root from elements
 */
function calculateMerkleRoot(bytes32[] memory elements) private pure returns (bytes32) {
    require(elements.length > 0, "Empty elements");
    
    while (elements.length > 1) {
        bytes32[] memory newElements = new bytes32[]((elements.length + 1) / 2);
        
        for (uint256 i = 0; i < elements.length; i += 2) {
            if (i + 1 < elements.length) {
                newElements[i / 2] = keccak256(abi.encodePacked(elements[i], elements[i + 1]));
            } else {
                newElements[i / 2] = elements[i];
            }
        }
        
        elements = newElements;
    }
    
    return elements[0];
}
/**
 * @notice Update merkle tree with new commitment
 */
function updateMerkleTree(
    PrivacyPool storage pool,
    bytes32 commitment
) private {
    // Get current tree elements
    bytes32[] memory elements = getMerkleElements(pool);
    
    // Add new commitment
    elements = appendElement(elements, commitment);
    
    // Recalculate merkle root
    pool.merkleRoot = calculateMerkleRoot(elements);
}

/**
 * @notice Check if pool should be mixed
 */
function shouldMixPool(PrivacyPool storage pool) private view returns (bool) {
    return (
        pool.participantCount >= MIN_PARTICIPANTS &&
        block.timestamp >= pool.lastMixTime + MIX_COOLDOWN
    );
}

/**
 * @notice Mix privacy pool funds
 */
function mixPool(uint256 denomination) private {
    PrivacyPool storage pool = privacyPools[denomination];
    require(pool.balance > 0, "Empty pool");

    // Generate ZK proof for mixing
    bytes memory mixProof = zkVerifier.generateMixProof(
        pool.merkleRoot,
        pool.participantCount,
        denomination
    );

    require(
        zkVerifier.verifyMixProof(
            mixProof,
            pool.merkleRoot,
            pool.participantCount,
            denomination
        ),
        "Invalid mix proof"
    );

    // Reset pool state while maintaining privacy
    bytes32 oldMerkleRoot = pool.merkleRoot;
    pool.merkleRoot = bytes32(0);
    pool.lastMixTime = block.timestamp;
    pool.participantCount = 0;

    emit PrivacyPoolMix(denomination, oldMerkleRoot);
}

/**
 * @notice Withdraw from privacy pool using ZK proof
 * @param denomination Pool denomination
 * @param nullifier Unique nullifier to prevent double spending
 * @param proof ZK proof of valid withdrawal
 */
/**
 * @notice Withdraw from privacy pool using ZK proof
 * @param denomination Pool denomination
 * @param nullifier Unique nullifier to prevent double spending
 * @param proof ZK proof of valid withdrawal
 */
function withdrawFromPrivacyPool(
    uint256 denomination,
    bytes32 nullifier,
    bytes calldata proof
) external {
    PrivacyPool storage pool = privacyPools[denomination];
    
    // Check if pool has commitments
    require(poolCommitmentsList[denomination].length > 0, "Empty pool");
    
    // Check if nullifier has been used
    require(!poolNullifiers[denomination][nullifier], "Nullifier used");

    // Verify withdrawal proof
    require(
        zkVerifier.verifyWithdrawalProof(
            proof,
            nullifier,
            pool.merkleRoot,
            denomination,
            msg.sender
        ),
        "Invalid withdrawal proof"
    );

    // Mark nullifier as used in separate mapping
    poolNullifiers[denomination][nullifier] = true;
    
    // Process withdrawal
    pool.balance -= denomination;
    _transfer(address(this), msg.sender, denomination);

    emit PrivacyPoolWithdraw(denomination, nullifier);
}

/**
 * @notice Initialize supported pool denominations
 * @dev Called by owner to set up initial denomination pools
 */
function initializePrivacyPools(uint256[] calldata denominations) external onlyOwner {
    require(supportedDenominations.length == 0, "Already initialized");
    
    for (uint256 i = 0; i < denominations.length; i++) {
        require(denominations[i] > 0, "Invalid denomination");
        supportedDenominations.push(denominations[i]);
        
        privacyPools[denominations[i]] = PrivacyPool({
            balance: 0,
            lastMixTime: 0,
            participantCount: 0,
            merkleRoot: bytes32(0)
        });
    }
}

    // Standard utility functions...
    //receive() external payable {}

    // Admin functions
    function setPrivacyEnabled(bool enabled) external onlyOwner {
        privacyEnabled = enabled;
    }

    function updateZKVerifier(address newVerifier) external onlyOwner {
        require(newVerifier != address(0), "Invalid verifier");
        zkVerifier = IZKVerifier(newVerifier);
    }


    receive() external payable {}
    // Change VIRALDividendTracker to CipherDividendTracker
    /**
 * @notice Update dividend tracker contract
 * @param newAddress Address of new dividend tracker
 */
function updateDividendTracker(address newAddress) public onlyOwner {
    require(newAddress != address(0), "Zero address");
    require(newAddress != address(dividendTracker), "Same address");
    
    CipherDividendTracker newDividendTracker = CipherDividendTracker(payable(newAddress));
    
    // Setup exclusions
    newDividendTracker.excludeFromDividends(address(newDividendTracker), true);
    newDividendTracker.excludeFromDividends(address(this), true);
    newDividendTracker.excludeFromDividends(owner(), true);
    newDividendTracker.excludeFromDividends(address(router), true);

    // Store old tracker to enable migration if needed
    address oldTracker = address(dividendTracker);
    
    // Update tracker
    dividendTracker = newDividendTracker;
    
    emit DividendTrackerUpdated(oldTracker, newAddress);
}

// In CipherDividendTracker contract
function processAccountDividends(address account) external  onlyOwner returns (bool) {
        uint256 amount = _withdrawDividendOfUser(payable(account));
        if(amount > 0) {
            lastClaimTimes[account] = block.timestamp;
            emit Claim(account, amount);
            return true;
        }
        return false;
    }

/**
     * @notice Withdraw dividends
     */
    function withdrawDividend() external  {
        uint256 amount = _withdrawDividendOfUser(payable(msg.sender));
        if(amount > 0) {
            lastClaimTimes[msg.sender] = block.timestamp;
            emit Claim(msg.sender, amount);
        }
    }


// In CipherZeroToken.sol
function claim() external {
    require(claimEnabled, "Claims not enabled");
    require(!swapping, "Swapping in progress");
    require(automatedMarketMakerPairs[address(pair)], "Invalid pair");
    require(!_isExcludedFromFees[msg.sender], "Excluded from dividends");

    // Use withdrawDividend instead of processAccount
    dividendTracker.withdrawDividend();
}
/**
 * @notice Emergency rescue of tokens sent by mistake
 * @param tokenAddress Address of token to rescue
 */
function rescueETH20Tokens(address tokenAddress) external onlyOwner {
    require(tokenAddress != address(this), "Cannot rescue core token");
    require(tokenAddress != address(dividendTracker), "Cannot rescue tracker token");
    
    IERC20 token = IERC20(tokenAddress);
    uint256 balance = token.balanceOf(address(this));
    require(balance > 0, "Nothing to rescue");

    require(token.transfer(owner(), balance), "Transfer failed");
    emit TokensRescued(tokenAddress, balance);
}

/**
 * @notice Emergency ETH recovery to treasury
 * @dev Only callable by owner or in emergency
 */
function forceSend() external {
    require(msg.sender == owner() || msg.sender == treasuryWallet, "Unauthorized");
    require(address(this).balance > 0, "No ETH to send");

    uint256 ethBalance = address(this).balance;
    payable(treasuryWallet).sendValue(ethBalance);
    
    emit ETHRecovered(treasuryWallet, ethBalance);
}

/**
 * @notice Rescue tokens from dividend tracker
 * @param tokenAddress Address of token to rescue
 */
function trackerRescueETH20Tokens(address tokenAddress) external onlyOwner {
    require(tokenAddress != address(dividendTracker), "Cannot rescue tracker token");
    dividendTracker.trackerRescueETH20Tokens(owner(), tokenAddress);
}

/**
 * @notice Force send ETH from dividend tracker
 * @dev Emergency recovery function
 */
function trackerForceSend() external onlyOwner {
    dividendTracker.trackerForceSend(owner());
}

/**
 * @notice Update router address
 * @param newRouter Address of new router
 */
function updateRouter(address newRouter) external onlyOwner {
    require(newRouter != address(0), "Zero address");
    require(newRouter != address(router), "Same address");
    
    router = IRouter(newRouter);
    emit RouterUpdated(newRouter);
}

// Events
event DividendTrackerUpdated(address indexed oldTracker, address indexed newTracker);
event TokensRescued(address indexed token, uint256 amount);
event ETHRecovered(address indexed recipient, uint256 amount);
event RouterUpdated(address indexed newRouter);

// Helper function
function isContract(address account) internal view returns (bool) {
    uint256 size;
    assembly {
        size := extcodesize(account)
    }
    return size > 0;
}
     /////////////////////////////////
    // Exclude / Include functions //
   /////////////////////////////////

    function excludeFromFees(address account, bool excluded) public onlyOwner {
        require(_isExcludedFromFees[account] != excluded, "VIRAL: Account is already the value of 'excluded'");
        _isExcludedFromFees[account] = excluded;

        emit ExcludeFromFees(account, excluded);
    }

    function excludeMultipleAccountsFromFees(address[] calldata accounts, bool excluded) public onlyOwner {
        for(uint256 i = 0; i < accounts.length; i++) {
            _isExcludedFromFees[accounts[i]] = excluded;
        }
        emit ExcludeMultipleAccountsFromFees(accounts, excluded);
    }

    /// @dev "true" to exlcude, "false" to include
    function excludeFromDividends(address account, bool value) external onlyOwner{
        dividendTracker.excludeFromDividends(account, value);
    }

     ///////////////////////
    //  Setter Functions //
   ///////////////////////

    function setTreasuryWallet(address newWallet) external onlyOwner{
        treasuryWallet = newWallet;
    }

    function setDevWallet(address newWallet) external onlyOwner{
        devWallet = newWallet;
    }

    /// @notice Update the threshold to swap tokens for liquidity,
    ///   treasury and dividends.
    function setSwapTokensAtAmount(uint256 amount) external onlyOwner{
        swapTokensAtAmount = amount * 10**18;
    }

    function setBuyTaxes(
    uint256 _rewards, 
    uint256 _treasury, 
    uint256 _privacy, 
    uint256 _dev,
    uint256 _liquidity
) external onlyOwner {
    require(_rewards + _treasury + _privacy + _dev + _liquidity <= 20, "Fee must be <= 20%");
    buyTaxes = Taxes(_rewards, _treasury, _privacy, _dev, _liquidity);
    totalBuyTax = _rewards + _treasury + _privacy + _dev + _liquidity;
}

function setSellTaxes(
    uint256 _rewards, 
    uint256 _treasury, 
    uint256 _privacy, 
    uint256 _dev,
    uint256 _liquidity
) external onlyOwner {
    require(_rewards + _treasury + _privacy + _dev + _liquidity <= 20, "Fee must be <= 20%");
    sellTaxes = Taxes(_rewards, _treasury, _privacy, _dev, _liquidity);
    totalSellTax = _rewards + _treasury + _privacy + _dev + _liquidity;
}

    function setMaxBuyAndSell(uint256 maxBuy, uint256 maxSell) external onlyOwner{
        maxBuyAmount = maxBuy * 10**18;
        maxSellAmount = maxSell * 10**18;
    }

    /// @notice Enable or disable internal swaps
    /// @dev Set "true" to enable internal swaps for liquidity, treasury and dividends
    function setSwapEnabled(bool _enabled) external onlyOwner{
        swapEnabled = _enabled;
    }
    
    
    function activateTrading() external onlyOwner{
        require(!tradingEnabled, "Trading already enabled");
        tradingEnabled = true;
    }

    function setClaimEnabled(bool state) external onlyOwner{
        claimEnabled = state;
    }

    /// @param bot The bot address
    /// @param value "true" to blacklist, "false" to unblacklist
    function setBot(address bot, bool value) external onlyOwner{
        require(_isBot[bot] != value);
        _isBot[bot] = value;
    }
    
    function setBulkBot(address[] memory bots, bool value) external onlyOwner{
        for(uint256 i; i<bots.length; i++){
            _isBot[bots[i]] = value;
        }
    }

    /**
     * @notice Update LP token address
     * @param newLPToken Address of new LP token
     */
    function setLPToken(address newLPToken) external onlyOwner {
        require(newLPToken != address(0), "Zero address");
        address oldLPToken = lpToken;
        lpToken = newLPToken;
        emit LPTokenUpdated(oldLPToken, newLPToken);
    }


    /// @dev Set new pairs created due to listing in new DEX
    function setAutomatedMarketMakerPair(address newPair, bool value) external onlyOwner {
        _setAutomatedMarketMakerPair(newPair, value);
    }
    
    
    function _setAutomatedMarketMakerPair(address newPair, bool value) private {
        require(automatedMarketMakerPairs[newPair] != value, "VIRAL: Automated market maker pair is already set to that value");
        automatedMarketMakerPairs[newPair] = value;

        if(value) {
            dividendTracker.excludeFromDividends(newPair, true);
        }

        emit SetAutomatedMarketMakerPair(newPair, value);
    }

     //////////////////////
    // Getter Functions //
   //////////////////////

    function getTotalDividendsDistributed() external view returns (uint256) {
        return dividendTracker.totalDividendsDistributed();
    }

    function isExcludedFromFees(address account) public view returns(bool) {
        return _isExcludedFromFees[account];
    }

    function withdrawableDividendOf(address account) public view returns(uint256) {
        return dividendTracker.withdrawableDividendOf(account);
    }

    function dividendTokenBalanceOf(address account) public view returns (uint256) {
        return dividendTracker.balanceOf(account);
    }

      

     ////////////////////////
    // Transfer Functions //
   ////////////////////////
   
    // Airdrop tokens to users. This won't update the dividend balance in order to avoid a gas issue.
    // Users will get dividend balance updated as soon as their balance change.
    function airdropTokens(address[] memory accounts, uint256[] memory amounts) external onlyOwner{
        require(accounts.length == amounts.length, "Arrays must have same size");
        for(uint256 i; i< accounts.length; i++){
            super._transfer(msg.sender, accounts[i], amounts[i]);
        }
    }

    function _transfer(address from, address to, uint256 amount) internal override {
        require(from != address(0), "ERC20: transfer from the zero address");
        require(to != address(0), "ERC20: transfer to the zero address");
        

        if(!_isExcludedFromFees[from] && !_isExcludedFromFees[to] && !swapping){
            require(tradingEnabled, "Trading not active");
            require(!_isBot[from] && !_isBot[to], "Bye Bye Bot");
            if(automatedMarketMakerPairs[to]) require(amount <= maxSellAmount, "You are exceeding maxSellAmount");
            else if(automatedMarketMakerPairs[from]) require(amount <= maxBuyAmount, "You are exceeding maxBuyAmount");
        }

        if(amount == 0) {
            super._transfer(from, to, 0);
            return;
        }
        
        uint256 contractTokenBalance = balanceOf(address(this));
        bool canSwap = contractTokenBalance >= swapTokensAtAmount;

        if( canSwap && !swapping && swapEnabled && automatedMarketMakerPairs[to] && !_isExcludedFromFees[from] && !_isExcludedFromFees[to]) {
            swapping = true;

            if(totalSellTax> 0){
                swapAndLiquify(swapTokensAtAmount);
            }

            swapping = false;
        }

        bool takeFee = !swapping;

        // if any account belongs to _isExcludedFromFee account then remove the fee
        if(_isExcludedFromFees[from] || _isExcludedFromFees[to]) {
            takeFee = false;
        }

        if(!automatedMarketMakerPairs[to] && !automatedMarketMakerPairs[from]) takeFee = false;

        if(takeFee) {
            uint256 feeAmt;
            if(automatedMarketMakerPairs[to]) feeAmt = amount * totalSellTax / 100;
            else if(automatedMarketMakerPairs[from]) feeAmt = amount * totalBuyTax / 100;

            amount = amount - feeAmt;
            super._transfer(from, address(this), feeAmt);
        }
        super._transfer(from, to, amount);

        try dividendTracker.setBalance(from, balanceOf(from)) {} catch {}
        try dividendTracker.setBalance(to, balanceOf(to)) {} catch {}

    }

    function swapAndLiquify(uint256 tokens) private {
    // Split the contract balance into halves
    uint256 tokensToAddLiquidityWith = tokens / 2;
    uint256 toSwap = tokens - tokensToAddLiquidityWith;

    uint256 initialBalance = address(this).balance;

    swapTokensForETH(toSwap);

    uint256 ETHToAddLiquidityWith = address(this).balance - initialBalance;

    if(ETHToAddLiquidityWith > 0){
        // Add liquidity to pancake
        addLiquidity(tokensToAddLiquidityWith, ETHToAddLiquidityWith);
    }

    uint256 lpBalance = IERC20(pair).balanceOf(address(this));
    uint256 totalTax = (totalSellTax - sellTaxes.liquidity);

    // Send LP to treasuryWallet
    uint256 treasuryAmt = lpBalance * sellTaxes.treasury / totalTax;
    if(treasuryAmt > 0){
        IERC20(pair).transfer(treasuryWallet, treasuryAmt);
    }

    // Send LP to dev
    uint256 devAmt = lpBalance * sellTaxes.dev / totalTax;
    if(devAmt > 0){
        IERC20(pair).transfer(devWallet, devAmt);
    }

    // Send LP to dividends
    uint256 dividends = lpBalance * sellTaxes.rewards / totalTax;
    if(dividends > 0) {
        bool success = IERC20(pair).transfer(address(dividendTracker), dividends);
        if (success) {
            dividendTracker.withdrawDividend();  // Updated to use correct function
            emit SendDividends(tokens, dividends);
        }
    }
}

    function swapTokensForETH(uint256 tokenAmount) private {
        address[] memory path = new address[](2);
        path[0] = address(this);
        path[1] = router.WETH();

        _approve(address(this), address(router), tokenAmount);

        // make the swap
        router.swapExactTokensForETHSupportingFeeOnTransferTokens(
            tokenAmount,
            0, // accept any amount of ETH
            path,
            address(this),
            block.timestamp
        );

    }

    function addLiquidity(uint256 tokenAmount, uint256 ethAmount) private {

        // approve token transfer to cover all possible scenarios
        _approve(address(this), address(router), tokenAmount);

        // add the liquidity
        router.addLiquidityETH{value: ethAmount}(
            address(this),
            tokenAmount,
            0, // slippage is unavoidable
            0, // slippage is unavoidable
            address(this),
            block.timestamp
        );

    
}
}


