# NIMBUS local chain (Hardhat)

A local Ethereum-compatible chain on your own CPU, with a test token contract, deploy script and test suite.
For local development only — nothing here has real value.

## Requirements
- Node.js 18+ (https://nodejs.org). Check with `node -v`.

## Install
    npm install

## Build (compile the contract with the bundled Solidity compiler)
    npm run compile

## Run the chain (terminal 1 — leave it running)
    npm run chain
JSON-RPC at http://127.0.0.1:8545, chainId 31337, 20 pre-funded test accounts (printed at start-up).

## Deploy (terminal 2)
    npm run deploy
Writes the contract address to `deployments.json`.

## Test (terminal 2)
    npm test
Six end-to-end tests against the running chain, including a 200-transfer latency measurement.

## Notes
- Restarting `npm run chain` resets the chain; re-run `npm run deploy` afterwards.
- The pre-funded accounts' private keys are public Hardhat defaults. Never use them outside this local chain.
