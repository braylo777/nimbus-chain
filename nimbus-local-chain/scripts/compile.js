// Compile contracts/NimbusToken.sol with solc-js (bundled in the npm package; no compiler download needed).
const fs = require("fs"), path = require("path"), solc = require("solc");
const src = fs.readFileSync(path.join(__dirname, "..", "contracts", "NimbusToken.sol"), "utf8");
const input = { language: "Solidity", sources: { "NimbusToken.sol": { content: src } },
  settings: { optimizer: { enabled: true, runs: 200 }, outputSelection: { "*": { "*": ["abi", "evm.bytecode.object"] } } } };
const out = JSON.parse(solc.compile(JSON.stringify(input)));
const errors = (out.errors || []).filter(e => e.severity === "error");
if (errors.length) { errors.forEach(e => console.error(e.formattedMessage)); process.exit(1); }
const c = out.contracts["NimbusToken.sol"].NimbusToken;
fs.mkdirSync(path.join(__dirname, "..", "build"), { recursive: true });
fs.writeFileSync(path.join(__dirname, "..", "build", "NimbusToken.json"), JSON.stringify({ abi: c.abi, bytecode: "0x" + c.evm.bytecode.object }, null, 1));
console.log(`compiled NimbusToken with solc ${solc.version()} — bytecode ${c.evm.bytecode.object.length / 2} bytes, ${c.abi.length} ABI entries`);
