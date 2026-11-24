// End-to-end tests against the running local chain and the deployed contract (node --test).
const { test, before } = require("node:test"), assert = require("node:assert/strict");
const fs = require("fs"), path = require("path"), { ethers } = require("ethers");
const root = path.join(__dirname, "..");
let provider, owner, alice, bob, token;
const U = (x) => ethers.parseUnits(String(x), 18);

before(async () => {
  provider = new ethers.JsonRpcProvider(process.env.RPC_URL || "http://127.0.0.1:8545");
  [owner, alice, bob] = await Promise.all([0, 1, 2].map(i => provider.getSigner(i)));
  const dep = JSON.parse(fs.readFileSync(path.join(root, "deployments.json")));
  const art = JSON.parse(fs.readFileSync(path.join(root, "build", "NimbusToken.json")));
  token = new ethers.Contract(dep.NimbusToken, art.abi, owner);
});

test("chain is live and the contract is deployed", async () => {
  const net = await provider.getNetwork();
  assert.equal(Number(net.chainId), 31337);
  assert.ok((await provider.getCode(await token.getAddress())).length > 2);
});

test("metadata and initial supply", async () => {
  assert.equal(await token.symbol(), "NIMT");
  assert.equal(await token.decimals(), 18n);
  assert.equal(await token.totalSupply(), U(1000000));
});

test("transfer moves balance and emits Transfer", async () => {
  const before = await token.balanceOf(await alice.getAddress());
  const rc = await (await token.transfer(await alice.getAddress(), U(250))).wait();
  assert.equal(await token.balanceOf(await alice.getAddress()), before + U(250));
  const ev = rc.logs.map(l => token.interface.parseLog(l)).find(e => e && e.name === "Transfer");
  assert.equal(ev.args.value, U(250));
});

test("transfer above balance is rejected and state is unchanged", async () => {
  const b = await token.balanceOf(await bob.getAddress());
  await assert.rejects(token.connect(bob).transfer(await alice.getAddress(), b + 1n), /insufficient balance/);
  assert.equal(await token.balanceOf(await bob.getAddress()), b);
});

test("approve + transferFrom respects the allowance", async () => {
  const a = await alice.getAddress(), b = await bob.getAddress();
  await (await token.connect(alice).approve(b, U(100))).wait();
  await (await token.connect(bob).transferFrom(a, b, U(60))).wait();
  assert.equal(await token.allowance(a, b), U(40));
  await assert.rejects(token.connect(bob).transferFrom(a, b, U(41)), /allowance exceeded/);
});

test("200 sequential transfers: confirmation latency", async () => {
  const to = await bob.getAddress(), times = [];
  const start = await token.balanceOf(to);
  for (let i = 0; i < 200; i++) {
    const t0 = performance.now();
    await (await token.transfer(to, 1n)).wait();
    times.push(performance.now() - t0);
  }
  times.sort((x, y) => x - y);
  assert.equal(await token.balanceOf(to), start + 200n);
  console.log(`    200 transfers confirmed: p50 ${times[100].toFixed(1)} ms, p99 ${times[197].toFixed(1)} ms, max ${times[199].toFixed(1)} ms`);
});
