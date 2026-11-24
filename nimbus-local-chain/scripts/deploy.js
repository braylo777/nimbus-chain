// Deploy NimbusToken to the local chain and record the address in deployments.json.
const fs = require("fs"), path = require("path"), { ethers } = require("ethers");
(async () => {
  const provider = new ethers.JsonRpcProvider(process.env.RPC_URL || "http://127.0.0.1:8545");
  const signer = await provider.getSigner(0);
  const art = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "build", "NimbusToken.json")));
  const factory = new ethers.ContractFactory(art.abi, art.bytecode, signer);
  const t0 = Date.now();
  const token = await factory.deploy(ethers.parseUnits("1000000", 18));
  const receipt = await token.deploymentTransaction().wait();
  const addr = await token.getAddress();
  const net = await provider.getNetwork();
  fs.writeFileSync(path.join(__dirname, "..", "deployments.json"),
    JSON.stringify({ chainId: Number(net.chainId), NimbusToken: addr, block: receipt.blockNumber, deployer: await signer.getAddress() }, null, 1));
  console.log(`deployed NimbusToken at ${addr} (chainId ${net.chainId}, block ${receipt.blockNumber}, gas ${receipt.gasUsed}, ${Date.now() - t0} ms)`);
})().catch(e => { console.error(e.message); process.exit(1); });
