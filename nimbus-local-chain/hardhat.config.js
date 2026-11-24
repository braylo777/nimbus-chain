// Local chain only: `npx hardhat node` serves JSON-RPC on http://127.0.0.1:8545 (chainId 31337, 20 funded test accounts).
module.exports = { networks: { hardhat: { chainId: 31337, mining: { auto: true } } } };
