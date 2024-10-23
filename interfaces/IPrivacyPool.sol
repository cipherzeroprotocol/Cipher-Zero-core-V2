// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

interface IPrivacyPool {
   // Structs
   struct Note {
       bytes32 commitment;    // Note commitment
       bytes32 nullifier;     // Uniqueness nullifier
       uint256 amount;        // Amount in note
       bool spent;           // Spent status
   }

   // Events
   event NoteDeposited(
       bytes32 indexed commitment,
       uint256 amount,
       uint256 timestamp
   );

   event NoteWithdrawn(
       bytes32 indexed nullifier,
       address recipient,
       uint256 amount,
       uint256 timestamp
   );
   
   event VerifierUpdated(
       address indexed oldVerifier,
       address indexed newVerifier
   );

   event EmergencyWithdrawal(
       address indexed operator,
       uint256 amount,
       uint256 timestamp
   );

   event EmergencyPaused(
       address indexed operator,
       uint256 timestamp
   );

   event EmergencyUnpaused(
       address indexed operator, 
       uint256 timestamp
   );

   /**
    * @notice Deposit tokens into privacy pool
    * @param commitment Note commitment
    * @param amount Token amount
    * @param proof ZK proof
    */
   function deposit(
       bytes32 commitment,
       uint256 amount,
       bytes calldata proof
   ) external;

   /**
    * @notice Withdraw tokens from privacy pool
    * @param nullifier Note nullifier
    * @param commitment Note commitment
    * @param recipient Recipient address
    * @param amount Token amount
    * @param proof ZK proof
    */
   function withdraw(
       bytes32 nullifier,
       bytes32 commitment,
       address recipient,
       uint256 amount,
       bytes calldata proof
   ) external;

   /**
    * @notice Get pool token balance
    * @return uint256 Token balance
    */
   function getBalance() external view returns (uint256);

   /**
    * @notice Get note details by commitment
    * @param commitment Note commitment
    * @return Note struct
    */
   function notes(bytes32 commitment) external view returns (Note memory);

   /**
    * @notice Check if nullifier has been used
    * @param nullifier Nullifier to check
    * @return bool True if nullifier is used
    */
   function nullifierUsed(bytes32 nullifier) external view returns (bool);

   /**
    * @notice Update verifier contract address
    * @param verifier New verifier address
    */
   function setVerifier(address verifier) external;

   /**
    * @notice Get token contract address
    * @return address Token contract address
    */
   function token() external view returns (address);

   /**
    * @notice Get verifier contract address
    * @return address Verifier contract address
    */
   function verifier() external view returns (address);

   /**
    * @notice Emergency token withdrawal
    */
   function emergencyWithdraw() external;

   /**
    * @notice Pause contract in emergency
    */
   function pause() external;

   /**
    * @notice Unpause contract
    */
   function unpause() external;

   /**
    * @notice Check if contract is paused
    * @return bool True if paused
    */
   function paused() external view returns (bool);
}