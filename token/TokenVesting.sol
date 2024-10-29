// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/math/Math.sol";

/**
 * @title TokenVesting
 * @notice Manages token vesting schedules for CipherZeroToken
 * @dev Supports multiple beneficiaries with different vesting schedules
 */
contract TokenVesting is Ownable, ReentrancyGuard, Pausable {
    using Math for uint256;

    // Vesting schedule structure
    struct VestingSchedule {
        uint256 totalAmount;     // Total amount of tokens to vest
        uint256 releasedAmount;  // Amount of tokens released so far
        uint256 startTime;       // Start time of the vesting period
        uint256 duration;        // Duration of the vesting period
        uint256 cliffDuration;   // Cliff period duration
        uint256 slicePeriod;     // Period between vesting releases
        bool revocable;         // Whether the schedule can be revoked
        bool revoked;           // Whether the schedule has been revoked
    }

    // Schedule types
    enum ScheduleType {
        TEAM,           // Team and advisors
        ECOSYSTEM,      // Ecosystem development
        COMMUNITY,      // Community rewards
        PRIVATE_SALE,   // Private sale participants
        PUBLIC_SALE     // Public sale participants
    }

    // State variables
    IERC20 public token;
    
    mapping(address => VestingSchedule[]) public vestingSchedules;
    mapping(address => uint256) public vestingScheduleCount;
    mapping(ScheduleType => uint256) public totalVestedByType;
    mapping(ScheduleType => uint256) public maxVestingByType;
    
    uint256 public vestingSchedulesCount;
    address public treasury;

    // Events
    event VestingScheduleCreated(
        address indexed beneficiary,
        uint256 indexed scheduleId,
        ScheduleType scheduleType,
        uint256 amount
    );

    event VestingScheduleRevoked(
        address indexed beneficiary,
        uint256 indexed scheduleId,
        uint256 refundAmount
    );

    event TokensReleased(
        address indexed beneficiary,
        uint256 indexed scheduleId,
        uint256 amount
    );

    event TreasuryUpdated(
        address indexed oldTreasury,
        address indexed newTreasury
    );

    /**
     * @notice Constructor
     * @param initialOwner Initial owner address
     * @param _token CipherZeroToken address
     * @param _treasury Treasury address
     */
    constructor(
        address initialOwner,
        address _token,
        address _treasury
    ) Ownable(initialOwner) {
        require(_token != address(0), "Invalid token address");
        require(_treasury != address(0), "Invalid treasury address");
        
        token = IERC20(_token);
        treasury = _treasury;

        // Initialize max vesting amounts by type
        maxVestingByType[ScheduleType.TEAM] = 150_000_000 * 10**18;        // 15%
        maxVestingByType[ScheduleType.ECOSYSTEM] = 250_000_000 * 10**18;   // 25%
        maxVestingByType[ScheduleType.COMMUNITY] = 50_000_000 * 10**18;    // 5%
        maxVestingByType[ScheduleType.PRIVATE_SALE] = 200_000_000 * 10**18; // 20%
        maxVestingByType[ScheduleType.PUBLIC_SALE] = 200_000_000 * 10**18;  // 20%
    }

    /**
     * @notice Create a new vesting schedule
     */
    function createVestingSchedule(
        address beneficiary,
        ScheduleType scheduleType,
        uint256 amount,
        uint256 startTime,
        uint256 duration,
        uint256 cliffDuration,
        uint256 slicePeriod,
        bool revocable
    ) external onlyOwner {
        require(beneficiary != address(0), "Invalid beneficiary");
        require(amount > 0, "Amount must be > 0");
        require(duration > 0, "Duration must be > 0");
        require(slicePeriod > 0, "Slice period must be > 0");
        require(duration >= cliffDuration, "Invalid cliff");
        require(startTime >= block.timestamp, "Start time < now");
        
        // Check vesting cap for schedule type
        require(
            totalVestedByType[scheduleType] + amount <= maxVestingByType[scheduleType],
            "Exceeds max vesting"
        );

        // Transfer tokens to contract
        require(
            token.transferFrom(msg.sender, address(this), amount),
            "Transfer failed"
        );

        // Create schedule
        vestingSchedules[beneficiary].push(VestingSchedule({
            totalAmount: amount,
            releasedAmount: 0,
            startTime: startTime,
            duration: duration,
            cliffDuration: cliffDuration,
            slicePeriod: slicePeriod,
            revocable: revocable,
            revoked: false
        }));

        // Update counters
        vestingScheduleCount[beneficiary]++;
        vestingSchedulesCount++;
        totalVestedByType[scheduleType] = totalVestedByType[scheduleType] + amount;

        emit VestingScheduleCreated(
            beneficiary,
            vestingScheduleCount[beneficiary] - 1,
            scheduleType,
            amount
        );
    }

    /**
     * @notice Release vested tokens for a schedule
     */
    function release(uint256 scheduleId) external nonReentrant {
        VestingSchedule storage schedule = vestingSchedules[msg.sender][scheduleId];
        require(schedule.totalAmount > 0, "No such schedule");
        require(!schedule.revoked, "Schedule revoked");

        uint256 vestedAmount = _computeVestedAmount(schedule);
        uint256 releasableAmount = vestedAmount - schedule.releasedAmount;
        require(releasableAmount > 0, "No tokens to release");

        // Update released amount
        schedule.releasedAmount = schedule.releasedAmount + releasableAmount;

        // Transfer tokens
        require(
            token.transfer(msg.sender, releasableAmount),
            "Transfer failed"
        );

        emit TokensReleased(msg.sender, scheduleId, releasableAmount);
    }

    /**
     * @notice Revoke a vesting schedule
     */
    function revoke(
        address beneficiary,
        uint256 scheduleId
    ) external onlyOwner {
        VestingSchedule storage schedule = vestingSchedules[beneficiary][scheduleId];
        require(schedule.totalAmount > 0, "No such schedule");
        require(schedule.revocable, "Not revocable");
        require(!schedule.revoked, "Already revoked");

        // Calculate vested amount before revocation
        uint256 vestedAmount = _computeVestedAmount(schedule);
        uint256 refundAmount = schedule.totalAmount - vestedAmount;

        // Mark as revoked
        schedule.revoked = true;

        // Transfer remaining tokens to treasury
        if (refundAmount > 0) {
            require(
                token.transfer(treasury, refundAmount),
                "Transfer failed"
            );
        }

        emit VestingScheduleRevoked(beneficiary, scheduleId, refundAmount);
    }

    /**
     * @notice Compute vested amount for a schedule
     */
    function _computeVestedAmount(
        VestingSchedule memory schedule
    ) internal view returns (uint256) {
        if (block.timestamp < schedule.startTime) {
            return 0;
        }

        if (block.timestamp < schedule.startTime + schedule.cliffDuration) {
            return 0;
        }

        if (block.timestamp >= schedule.startTime + schedule.duration) {
            return schedule.totalAmount;
        }

        uint256 timeFromStart = block.timestamp - schedule.startTime;
        uint256 secondsPerSlice = schedule.slicePeriod;
        uint256 vestedSlices = timeFromStart / secondsPerSlice;
        uint256 vestedSeconds = vestedSlices * secondsPerSlice;

        uint256 vestedAmount = (schedule.totalAmount * vestedSeconds) / schedule.duration;

        return vestedAmount;
    }

    // View functions remain unchanged...
    function getVestingSchedule(
        address beneficiary,
        uint256 scheduleId
    ) external view returns (
        uint256 totalAmount,
        uint256 releasedAmount,
        uint256 startTime,
        uint256 duration,
        uint256 cliffDuration,
        uint256 slicePeriod,
        bool revocable,
        bool revoked
    ) {
        VestingSchedule memory schedule = vestingSchedules[beneficiary][scheduleId];
        return (
            schedule.totalAmount,
            schedule.releasedAmount,
            schedule.startTime,
            schedule.duration,
            schedule.cliffDuration,
            schedule.slicePeriod,
            schedule.revocable,
            schedule.revoked
        );
    }

    function computeReleasableAmount(
        address beneficiary,
        uint256 scheduleId
    ) external view returns (uint256) {
        VestingSchedule memory schedule = vestingSchedules[beneficiary][scheduleId];
        return _computeVestedAmount(schedule) - schedule.releasedAmount;
    }

    /**
     * @notice Update treasury address
     */
    function updateTreasury(address newTreasury) external onlyOwner {
        require(newTreasury != address(0), "Invalid address");
        address oldTreasury = treasury;
        treasury = newTreasury;
        emit TreasuryUpdated(oldTreasury, newTreasury);
    }

    // Emergency functions
    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }
}