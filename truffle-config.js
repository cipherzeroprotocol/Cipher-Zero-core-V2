const Web3 = require("web3");
const HDWalletProvider = require("@truffle/hdwallet-provider");

Web3.providers.HttpProvider.prototype.sendAsync = Web3.providers.HttpProvider.prototype.send

// Configure provider URL based on network
const NEON_DEVNET_URL = "https://devnet.neonevm.org";
const NEON_TESTNET_URL = "https://testnet.neonevm.org";
const NEON_MAINNET_URL = "https://neon-proxy-mainnet.solana.p2p.org";

// Private keys for test accounts (REPLACE WITH YOUR OWN)
const privateKeys = [
  "0x7efe7d68906dd6fb3487f411aafb8e558863bf1d2f60372a47186d151eae625a",
  "0x09fb68d632c2b227cc6da77696de362fa38cb94e1c62d8a07db82e7d5e754f10"
];

module.exports = {
  networks: {
    // Neon Devnet
    neondev: {
      provider: () => {
        return new HDWalletProvider(
          privateKeys,
          NEON_DEVNET_URL
        );
      },
      network_id: "*",
      gas: 3000000000,
      gasPrice: 1000000000,
    },
    
    // Neon Testnet
    neontest: {
      provider: () => {
        return new HDWalletProvider(
          privateKeys,
          NEON_TESTNET_URL
        );
      },
      network_id: "*",
      gas: 3000000000,
      gasPrice: 1000000000,
    },

    // Neon Mainnet
    neonmain: {
      provider: () => {
        return new HDWalletProvider(
          privateKeys,
          NEON_MAINNET_URL
        );
      },
      network_id: "*",
      gas: 3000000000,
      gasPrice: 1000000000,
    }
  },

  // Configure compilers
  compilers: {
    solc: {
      version: "0.8.26",
      settings: {
        optimizer: {
          enabled: true,
          runs: 200,
          details: {
            yul: true,
            yulDetails: {
              stackAllocation: true,
              optimizerSteps: "dhfoDgvulfnTUtnIf"
            }
          }
        },
        viaIR: true,
        outputSelection: {
          "*": {
            "*": ["evm.bytecode", "evm.deployedBytecode", "abi"]
          }
        }
      }
    }
  },

  // Plugin configurations
  plugins: [
    'truffle-plugin-verify',
    'truffle-contract-size'
  ],

  // Mocha configurations for testing
  mocha: {
    timeout: 100000,
    useColors: true
  },

  // API keys for verification (if needed)
  api_keys: {
    etherscan: process.env.ETHERSCAN_API_KEY
  }
};