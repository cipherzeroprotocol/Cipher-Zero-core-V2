const HDWalletProvider = require("@truffle/hdwallet-provider");
require('dotenv').config();

console.log("MNEMONIC:", process.env.MNEMONIC); // Debugging: output mnemonic

module.exports = {
  networks: {
    neonEVM: {
      provider: () => {
        const mnemonic = process.env.MNEMONIC;
        if (!mnemonic) {
          throw new Error("MNEMONIC not found in environment variables");
        }
        console.log("Creating HDWalletProvider with MNEMONIC:", mnemonic); // Debugging
        return new HDWalletProvider(
          mnemonic,
          "https://devnet.neonevm.org"
        );
      },
      network_id: 245022926,
      gas: 3000000,
      gasPrice: 10000000000, // 10 gwei
    },
  },
  compilers: {
    solc: {
      version: "0.8.26",
    }
  },
};