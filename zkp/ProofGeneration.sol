// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

/**
 * @title IProofVerifier
 * @dev Interface for the proof verifier contract
 */
interface IProofVerifier {
    function verifyProof(
        bytes calldata proof,
        uint256[] calldata inputs
    ) external view returns (bool);
}

/**
 * @title ProofGeneration
 * @dev Enhanced zk-SNARKs proof generation with security features
 */
contract ProofGeneration is AccessControl, ReentrancyGuard, Pausable, EIP712 {
    // Roles
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    // Proof verifier interface
    IProofVerifier public proofVerifier;
    
    // Proof tracking
    mapping(bytes32 => bool) public usedProofs;
    mapping(string => bytes32) public proofHashes;
    mapping(address => uint256) public userProofCount;
    
    // Rate limiting
    uint256 public constant MAX_PROOFS_PER_BLOCK = 50;
    mapping(uint256 => uint256) private blockProofCount;

    // Events
    event ProofGenerated(
        address indexed user,
        string indexed proofId,
        bytes32 indexed proofHash,
        uint256 timestamp
    );
    
    event ProofVerifierUpdated(
        address indexed oldVerifier,
        address indexed newVerifier,
        address indexed updater
    );
    
    event ProofRevoked(
        string indexed proofId,
        address indexed revokedBy,
        uint256 timestamp
    );

    /**
     * @dev Constructor with enhanced initialization
     */
    constructor(
        string memory name,
        string memory version,
        address _proofVerifier,
        address admin
    ) EIP712(name, version) {
        require(_proofVerifier != address(0), "Invalid verifier");
        require(admin != address(0), "Invalid admin");

        proofVerifier = IProofVerifier(_proofVerifier);
        
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ADMIN_ROLE, admin);
        _grantRole(PAUSER_ROLE, admin);
        
        _pause(); // Start paused for security
    }

    /**
     * @dev Generate and verify zk-SNARK proof
     */
    function generateProof(
        bytes calldata proof,
        uint256[] calldata inputs,
        string calldata proofId
    ) external nonReentrant whenNotPaused onlyRole(VERIFIER_ROLE) {
        require(bytes(proofId).length > 0, "Invalid proofId");
        require(proofHashes[proofId] == bytes32(0), "ProofId used");
        require(
            blockProofCount[block.number] < MAX_PROOFS_PER_BLOCK,
            "Rate limit exceeded"
        );

        // Verify the proof using assembly for gas optimization
        bool isValid;
        assembly {
            // Get free memory pointer
            let ptr := mload(0x40)
            
            // Copy proof to memory
            let proofLen := proof.length
            calldatacopy(ptr, proof.offset, proofLen)
            
            // Copy inputs to memory
            let inputsPtr := add(ptr, proofLen)
            let inputsLen := mul(inputs.length, 0x20)
            calldatacopy(inputsPtr, inputs.offset, inputsLen)
            
            // Call verifier
            isValid := staticcall(
                gas(),
                sload(proofVerifier.slot),
                ptr,
                add(proofLen, inputsLen),
                ptr,
                0x20
            )
            
            if iszero(isValid) {
                revert(0, 0)
            }
            
            isValid := mload(ptr)
            
            // Update free memory pointer
            mstore(0x40, add(ptr, 0x40))
        }
        
        require(isValid, "Invalid proof");

        // Generate and store proof hash
        bytes32 proofHash = keccak256(abi.encode(proof, inputs, proofId));
        require(!usedProofs[proofHash], "Duplicate proof");
        
        usedProofs[proofHash] = true;
        proofHashes[proofId] = proofHash;
        userProofCount[msg.sender]++;
        blockProofCount[block.number]++;

        emit ProofGenerated(
            msg.sender,
            proofId,
            proofHash,
            block.timestamp
        );
    }

    /**
     * @dev Revoke a previously generated proof
     */
    function revokeProof(
        string calldata proofId
    ) external onlyRole(ADMIN_ROLE) {
        bytes32 proofHash = proofHashes[proofId];
        require(proofHash != bytes32(0), "Proof not found");
        
        delete usedProofs[proofHash];
        delete proofHashes[proofId];
        
        emit ProofRevoked(
            proofId,
            msg.sender,
            block.timestamp
        );
    }

    /**
     * @dev Update proof verifier with security checks
     */
    function setProofVerifier(
        address _proofVerifier
    ) external onlyRole(ADMIN_ROLE) whenPaused {
        require(_proofVerifier != address(0), "Invalid verifier");
        require(_proofVerifier != address(proofVerifier), "Same verifier");
        
        address oldVerifier = address(proofVerifier);
        proofVerifier = IProofVerifier(_proofVerifier);
        
        emit ProofVerifierUpdated(
            oldVerifier,
            _proofVerifier,
            msg.sender
        );
    }

    /**
     * @dev Clear old block proof counts
     */
    function clearOldBlockCounts(
        uint256 blocksBack
    ) external onlyRole(ADMIN_ROLE) {
        require(blocksBack > 0, "Invalid block count");
        uint256 targetBlock = block.number - blocksBack;
        
        for (uint256 i = 0; i < blocksBack; i++) {
            delete blockProofCount[targetBlock - i];
        }
    }

    // Role management functions
    function grantVerifierRole(address account) external onlyRole(ADMIN_ROLE) {
        grantRole(VERIFIER_ROLE, account);
    }

    function revokeVerifierRole(address account) external onlyRole(ADMIN_ROLE) {
        revokeRole(VERIFIER_ROLE, account);
    }

    // Emergency functions
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }
}