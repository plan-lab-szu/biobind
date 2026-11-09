// PrivateAuthGateway evaluation: on-chain Poseidon credential and device trees,
// atomic issuance (receipt consumption + leaf insertion, idc under the station
// link signature), immediate revocation by leaf zeroing, and unlinkable
// authentication with real auth_private_128 Groth16 proofs; gas for each step.
// Requires build/auth_private_128 from scripts/auth-private-benchmark.mjs.
// Local Ganache, synthetic vectors, software keys, benchmark-only setup.
// Usage (from prototype/): .toolchain/node-v24.19.0-win-x64/node.exe scripts/private-gateway-evaluation.mjs
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { buildEddsa, buildPoseidon, poseidonContract } from "circomlibjs";
import ganache from "ganache";
import solc from "solc";
import { ethers } from "ethers";
import { groth16 } from "snarkjs";
import { DST_PROBE, poseidonCommitment } from "./commitment.mjs";
import { encodeFinalizedSession } from "./lib/finalized-record.mjs";

const root = resolve(import.meta.dirname, "..");
const out = resolve(root, process.env.BIOBIND_OUT ?? "build/private-gateway");
const wasm = resolve(root, "build", "auth_private_128", "auth_private_128_js", "auth_private_128.wasm");
const zkey = resolve(root, "build", "auth_private_128", "auth_private_128_final.zkey");
const R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const CRED_DEPTH = 20, DEV_DEPTH = 10, ROOT_HISTORY = 64;
const DST = { ID: 3n, LEAF: 4n, DEV: 5n, CAPTURE: 6n, NULLIFIER: 7n };
const { id, keccak256, joinSignature } = ethers.utils;

const poseidon = await buildPoseidon();
const eddsa = await buildEddsa();
const F = poseidon.F;
const H = (xs) => F.toObject(poseidon(xs.map(BigInt)));
const field = (label) => BigInt(`0x${createHash("sha256").update(label).digest("hex")}`) % R;
const str = (o) => JSON.parse(JSON.stringify(o, (_, v) => (typeof v === "bigint" ? v.toString() : v)));
const confirmed = async (tx) => (await tx).wait();
const gasOf = (r) => r.gasUsed.toNumber();

async function compile() {
  const paths = ["PrivateAuthGateway.sol", "PoseidonMerkleTree.sol", "PoseidonT3.sol", "BioZKFHEFinalizationAdapter.sol",
    "interfaces/IBioZKFHEUniquenessAdapter.sol", "interfaces/IBioZKFHEFinalizationSource.sol",
    "test/LocalBioZKFHEFinalizationSource.sol", "generated/Groth16VerifierPrivate128.sol"];
  const sources = Object.fromEntries(await Promise.all(paths.map(async (p) =>
    [p, { content: await readFile(resolve(root, "contracts", p), "utf8") }])));
  const r = JSON.parse(solc.compile(JSON.stringify({ language: "Solidity", sources,
    settings: { optimizer: { enabled: true, runs: 200 }, evmVersion: "shanghai",
      outputSelection: { "*": { "*": ["abi", "evm.bytecode.object", "evm.deployedBytecode.object"] } } } })));
  const errors = (r.errors ?? []).filter((e) => e.severity === "error");
  assert.equal(errors.length, 0, errors.map((e) => e.formattedMessage).join("\n"));
  return r.contracts;
}

/// Mirror of the on-chain tree (zero subtrees, zeroed leaves stay 0).
function merklePath(leaves, depth, index) {
  const zeros = [0n];
  for (let i = 0; i < depth; i++) zeros.push(H([zeros[i], zeros[i]]));
  let level = new Map(leaves.map((v, i) => [i, v]));
  const pathElements = [], pathIndices = [];
  let idx = index;
  for (let d = 0; d < depth; d++) {
    const sib = idx ^ 1;
    pathElements.push(level.has(sib) ? level.get(sib) : zeros[d]);
    pathIndices.push(idx & 1);
    const next = new Map();
    for (const k of new Set([...level.keys()].map((x) => x >> 1))) {
      next.set(k, H([level.has(2 * k) ? level.get(2 * k) : zeros[d], level.has(2 * k + 1) ? level.get(2 * k + 1) : zeros[d]]));
    }
    level = next;
    idx >>= 1;
  }
  return { root: level.size ? level.get(0) : zeros[depth], pathElements, pathIndices };
}

async function reverts(promise, errorName, contract) {
  try { await promise; } catch (error) {
    const selector = contract.interface.getSighash(errorName);
    const found = [];
    const walk = (x, d) => {
      if (d > 5 || x == null) return;
      if (typeof x === "string") { if (x.startsWith("0x")) found.push(x); return; }
      if (typeof x === "object") for (const k of ["data", "error", "body"]) walk(x[k], d + 1);
    };
    walk(error, 0);
    if (typeof error.body === "string") { try { walk(JSON.parse(error.body), 0); } catch { /* ignore */ } }
    return found.some((v) => v.startsWith(selector)) ? errorName : `other:${String(error.message).slice(0, 60)}`;
  }
  return "NOT_REVERTED";
}

const contracts = await compile();
const base = JSON.parse(await readFile(resolve(root, "inputs", "generated", "auth_distance_128.json"), "utf8"));
const policyDigest = BigInt(base.policyDigest);
const EPSILON = BigInt(base.epsilon);

const chain = ganache.provider({ chain: { chainId: 31337, hardfork: "shanghai" }, logging: { quiet: true },
  miner: { blockGasLimit: 30_000_000 }, wallet: { deterministic: true, totalAccounts: 6 } });
const provider = new ethers.providers.Web3Provider(chain);
const [owner, relayer] = Object.values(chain.getInitialAccounts()).map(({ secretKey }) => new ethers.Wallet(secretKey, provider));
const deployFrom = async (abi, bytecode, ...args) => {
  const c = await new ethers.ContractFactory(abi, bytecode, owner).deploy(...args, { gasLimit: 29_000_000 });
  const r = await c.deployTransaction.wait();
  c.deployGas = gasOf(r);
  return c;
};
const deploy = (path, name, ...args) => {
  const c = contracts[path][name];
  return deployFrom(c.abi, `0x${c.evm.bytecode.object}`, ...args);
};

const result = { gas: {}, checks: {} };
try {
  // Poseidon contracts (circomlibjs generator) and agreement with circomlibjs hashing.
  const p2 = await deployFrom(poseidonContract.generateABI(2), poseidonContract.createCode(2));
  const p5 = await deployFrom(poseidonContract.generateABI(5), poseidonContract.createCode(5));
  const sample = [field("a"), field("b")];
  result.checks.poseidonMatchesCircomlibjs =
    (await p2["poseidon(uint256[2])"](sample)).toString() === H(sample).toString();
  assert.equal(result.checks.poseidonMatchesCircomlibjs, true);
  const hashTx = await confirmed(owner.sendTransaction({ to: p2.address,
    data: p2.interface.encodeFunctionData("poseidon(uint256[2])", [sample]) }));
  result.gas.poseidon2CallTx = gasOf(hashTx);

  const source = await deploy("test/LocalBioZKFHEFinalizationSource.sol", "LocalBioZKFHEFinalizationSource");
  const adapter = await deploy("BioZKFHEFinalizationAdapter.sol", "BioZKFHEFinalizationAdapter", source.address);
  const verifier = await deploy("generated/Groth16VerifierPrivate128.sol", "Groth16Verifier");
  const gateway = await deploy("PrivateAuthGateway.sol", "PrivateAuthGateway", adapter.address, verifier.address,
    p5.address, CRED_DEPTH, DEV_DEPTH, ROOT_HISTORY);
  result.gas.gatewayDeployment = gateway.deployGas;
  const treeAbi = contracts["PoseidonMerkleTree.sol"].PoseidonMerkleTree.abi;
  const credTree = new ethers.Contract(await gateway.credentialTree(), treeAbi, owner);
  const devTree = new ethers.Contract(await gateway.deviceTree(), treeAbi, owner);
  await confirmed(adapter.configureAuthorizedConsumer(gateway.address));
  await confirmed(gateway.registerPolicy(policyDigest, EPSILON));
  const station = ethers.Wallet.createRandom();
  await confirmed(gateway.registerEnrollmentStation(station.address));

  // Devices: the AFE under test plus two others.
  const prv = createHash("sha256").update("device-key/AFE-1").digest();
  const [ax, ay] = eddsa.prv2pub(prv).map((p) => F.toObject(p));
  const fw = field("fw/1.0"), model = field("model/synthetic-128"), quant = field("quant/u16-offset");
  const devLeaves = [];
  const deviceGas = [];
  for (const [kx, ky] of [[field("dev-x-0"), field("dev-y-0")], [ax, ay], [field("dev-x-2"), field("dev-y-2")]]) {
    const leaf = H([DST.DEV, kx, ky, fw, model, quant, policyDigest]);
    const r = await confirmed(gateway.registerDevice(leaf, kx, ky, fw, model, quant, policyDigest));
    deviceGas.push(gasOf(r));
    devLeaves.push(leaf);
  }
  result.gas.registerDevice = deviceGas;
  result.checks.deviceRootMatchesMirror = (await devTree.currentRoot()).toString() === merklePath(devLeaves, DEV_DEPTH, 0).root.toString();
  assert.equal(result.checks.deviceRootMatchesMirror, true);

  // Issue 8 credentials; holder A (base vectors) is index 5.
  const sA = field("identity-secret/holder-A");
  const credLeaves = [];
  const issueGas = [];
  const receiptIds = [];
  for (let i = 0; i < 8; i++) {
    const isA = i === 5;
    const cEnroll = isA ? BigInt(base.cEnroll) : field(`cEnroll-${i}`);
    const idc = H([DST.ID, isA ? sA : field(`secret-${i}`)]);
    const sid = id(`private/source-session/${i}`);
    const record = { operation: 1, finalized: true, uniquenessAccepted: true, expectedBlockCount: 1,
      verifiedBlockCount: 1, confirmationThreshold: 3, confirmationCount: 3,
      sourceContextHash: id(`ctx/${i}`), gallerySnapshotHash: id(`snap/${i}`), queryCiphertextDigest: id(`q/${i}`),
      enrollmentCiphertextDigest: id(`e/${i}`), verifiedOutputCollectionDigest: id(`o/${i}`),
      modelHash: id("model"), quantizationHash: id("quant"), finalizedAtBlock: await provider.getBlockNumber() };
    await confirmed(source.recordImmutableSession(sid, record));
    const enc = encodeFinalizedSession(record);
    const receipt = await adapter.previewFinalizedUniqueEnrollment(sid, enc);
    const digest = await gateway.linkDigest(receipt.receiptId, receipt.uniqueInputDigest, cEnroll, idc, policyDigest, 1);
    const sig = joinSignature(station._signingKey().signDigest(digest));
    if (i === 0) {
      // idc is covered by the station signature: a substituted idc is rejected.
      result.checks.substitutedIdcRejected = await reverts(gateway.callStatic.issue(sid, enc, cEnroll, idc + 1n, policyDigest, sig), "InvalidLink", gateway);
    }
    const r = await confirmed(gateway.issue(sid, enc, cEnroll, idc, policyDigest, sig));
    issueGas.push(gasOf(r));
    receiptIds.push(receipt.receiptId);
    credLeaves.push(H([DST.LEAF, cEnroll, idc, policyDigest, 1n]));
    if (i === 0) {
      result.checks.receiptConsumedOnce = await reverts(gateway.callStatic.issue(sid, enc, cEnroll, idc, policyDigest, sig), "InvalidSourceSession", adapter);
    }
  }
  result.gas.issue = issueGas;
  result.checks.credentialRootMatchesMirror = (await credTree.currentRoot()).toString() === merklePath(credLeaves, CRED_DEPTH, 0).root.toString();
  assert.equal(result.checks.credentialRootMatchesMirror, true);

  // Authentication helpers.
  const appId = id("app/voting"), action = id("action/ballot-1");
  const fresh = async () => {
    const w = ethers.Wallet.createRandom().connect(provider);
    await confirmed(owner.sendTransaction({ to: w.address, value: ethers.utils.parseEther("1") }));
    return w;
  };
  async function challenge(beneficiary, { oneTime = true, act = action } = {}) {
    const deadline = (await provider.getBlock("latest")).timestamp + 3600;
    const r = await confirmed(gateway.issueChallenge(beneficiary.address, policyDigest, appId, act, oneTime, deadline));
    const ev = r.events.find((e) => e.event === "ChallengeIssued").args;
    return { nonce: ev.nonce, scope: BigInt(ev.scope.toString()), deadline: BigInt(deadline), gas: gasOf(r) };
  }
  async function prove(ch, { leaves = credLeaves, devs = devLeaves, index = 5, secret = sA } = {}) {
    const ctxHash = BigInt((await gateway.ctxHashOf(ch.nonce)).toString());
    const cProbe = await poseidonCommitment({ roleTag: DST_PROBE, policyDigest, contextDigest: ctxHash, dimension: 128,
      salt: BigInt(base.rProbe), values: base.probe.map(BigInt) });
    const notAfter = ch.deadline;
    const msg = H([DST.CAPTURE, cProbe, ctxHash, policyDigest, model, quant, fw, notAfter]);
    const sig = eddsa.signPoseidon(prv, F.e(msg));
    const cred = merklePath(leaves, CRED_DEPTH, index), dev = merklePath(devs, DEV_DEPTH, 1);
    const input = { credRoot: cred.root, devRoot: dev.root, cProbe, policyDigest, ctxHash, epsilon: EPSILON, notAfter,
      scope: ch.scope, nullifier: H([DST.NULLIFIER, secret, ch.scope]), identitySecret: secret, templateVersion: 1n,
      cEnroll: base.cEnroll, rEnroll: base.rEnroll, rProbe: base.rProbe, enrollment: base.enrollment, probe: base.probe,
      credPathElements: cred.pathElements, credPathIndices: cred.pathIndices, devAx: ax, devAy: ay, devFirmware: fw,
      devModel: model, devQuantization: quant, devPathElements: dev.pathElements, devPathIndices: dev.pathIndices,
      sigR8x: F.toObject(sig.R8[0]), sigR8y: F.toObject(sig.R8[1]), sigS: sig.S };
    const t0 = performance.now();
    const { proof, publicSignals } = await groth16.fullProve(str(input), wasm, zkey);
    const ms = performance.now() - t0;
    const [pA, pB, pC, pub] = JSON.parse(`[${await groth16.exportSolidityCallData(proof, publicSignals)}]`);
    return { args: [ch.nonce, pA, pB, pC, pub], ms, nullifier: input.nullifier };
  }
  const authGas = [], proveMs = [];

  // 1. Honest one-time authentication; replay of the same scope under a new challenge is rejected.
  const b1 = await fresh();
  const c1 = await challenge(b1);
  const p1 = await prove(c1);
  proveMs.push(p1.ms);
  result.checks.nonBeneficiarySenderRejected = await reverts(gateway.connect(relayer).callStatic.authenticate(...p1.args), "InvalidChallenge", gateway);
  const r1 = await confirmed(gateway.connect(b1).authenticate(...p1.args));
  authGas.push({ case: "oneTime", gas: gasOf(r1) });
  const b2 = await fresh();
  const c2 = await challenge(b2);
  const p2proof = await prove(c2);
  proveMs.push(p2proof.ms);
  result.checks.sameScopeReplayRejected = await reverts(gateway.connect(b2).callStatic.authenticate(...p2proof.args), "NullifierUsed", gateway);

  // 2. App-scoped (reusable) pseudonym: same nullifier for the same app, accepted twice.
  const b3 = await fresh();
  const c3 = await challenge(b3, { oneTime: false });
  const p3 = await prove(c3);
  proveMs.push(p3.ms);
  const r3 = await confirmed(gateway.connect(b3).authenticate(...p3.args));
  authGas.push({ case: "appScoped", gas: gasOf(r3) });
  const b4 = await fresh();
  const c4 = await challenge(b4, { oneTime: false });
  const p4 = await prove(c4);
  proveMs.push(p4.ms);
  await confirmed(gateway.connect(b4).authenticate(...p4.args));
  result.checks.appPseudonymStable = p3.nullifier === p4.nullifier;
  result.checks.oneTimeAndAppNullifiersDiffer = p1.nullifier !== p3.nullifier;

  // 3. Insertion does not invalidate an earlier root (history window).
  const b5 = await fresh();
  const c5 = await challenge(b5, { oneTime: false });
  const p5proof = await prove(c5);
  proveMs.push(p5proof.ms);
  {
    const sid = id("private/source-session/late");
    const rec = { operation: 1, finalized: true, uniquenessAccepted: true, expectedBlockCount: 1, verifiedBlockCount: 1,
      confirmationThreshold: 3, confirmationCount: 3, sourceContextHash: id("ctx/late"), gallerySnapshotHash: id("snap/late"),
      queryCiphertextDigest: id("q/late"), enrollmentCiphertextDigest: id("e/late"), verifiedOutputCollectionDigest: id("o/late"),
      modelHash: id("model"), quantizationHash: id("quant"), finalizedAtBlock: await provider.getBlockNumber() };
    await confirmed(source.recordImmutableSession(sid, rec));
    const enc = encodeFinalizedSession(rec);
    const rc = await adapter.previewFinalizedUniqueEnrollment(sid, enc);
    const cE = field("cEnroll-late"), idc = H([DST.ID, field("secret-late")]);
    const sig = joinSignature(station._signingKey().signDigest(await gateway.linkDigest(rc.receiptId, rc.uniqueInputDigest, cE, idc, policyDigest, 1)));
    issueGas.push(gasOf(await confirmed(gateway.issue(sid, enc, cE, idc, policyDigest, sig))));
    credLeaves.push(H([DST.LEAF, cE, idc, policyDigest, 1n]));
  }
  const r5 = await confirmed(gateway.connect(b5).authenticate(...p5proof.args));
  result.checks.proofOnPreInsertionRootAccepted = r5.status === 1;

  // 4. Revocation of another credential invalidates every earlier root immediately.
  const b6 = await fresh();
  const c6 = await challenge(b6, { oneTime: false });
  const p6 = await prove(c6);
  proveMs.push(p6.ms);
  const revokeOther = await confirmed(gateway.revokeCredential(receiptIds[2], merklePath(credLeaves, CRED_DEPTH, 2).pathElements));
  result.gas.revokeCredential = [gasOf(revokeOther)];
  credLeaves[2] = 0n;
  result.checks.preRevocationRootRejected = await reverts(gateway.connect(b6).callStatic.authenticate(...p6.args), "InvalidRoot", gateway);
  const p6b = await prove(c6);
  proveMs.push(p6b.ms);
  const r6 = await confirmed(gateway.connect(b6).authenticate(...p6b.args));
  authGas.push({ case: "appScopedAfterRevocation", gas: gasOf(r6) });
  result.checks.unaffectedHolderReprovesOnNewRoot = r6.status === 1;
  result.checks.credentialRootMatchesMirrorAfterRevocation =
    (await credTree.currentRoot()).toString() === merklePath(credLeaves, CRED_DEPTH, 0).root.toString();

  // 5. Revoking holder A: old proofs fail by root, and no witness exists for the new root.
  const b7 = await fresh();
  const c7 = await challenge(b7, { oneTime: false });
  const p7proof = await prove(c7);
  proveMs.push(p7proof.ms);
  const revokeA = await confirmed(gateway.revokeCredential(receiptIds[5], merklePath(credLeaves, CRED_DEPTH, 5).pathElements));
  result.gas.revokeCredential.push(gasOf(revokeA));
  const leavesBefore = [...credLeaves];
  credLeaves[5] = 0n;
  result.checks.revokedHolderOldProofRejected = await reverts(gateway.connect(b7).callStatic.authenticate(...p7proof.args), "InvalidRoot", gateway);
  try {
    // The prover still has its old leaf; recompute the path against the live tree state.
    const live = merklePath(credLeaves, CRED_DEPTH, 5);
    assert.notEqual(merklePath(leavesBefore, CRED_DEPTH, 5).root, live.root);
    await prove(c7);
    result.checks.revokedHolderCannotProveOnNewRoot = false;
  } catch {
    result.checks.revokedHolderCannotProveOnNewRoot = true;
  }

  // 6. Device revocation invalidates proofs made with the old device root.
  const b8 = await fresh();
  // Holder A is revoked; use a fresh honest holder for this check: re-issue A under a new receipt.
  {
    const sid = id("private/source-session/A-reissue");
    const rec = { operation: 1, finalized: true, uniquenessAccepted: true, expectedBlockCount: 1, verifiedBlockCount: 1,
      confirmationThreshold: 3, confirmationCount: 3, sourceContextHash: id("ctx/A2"), gallerySnapshotHash: id("snap/A2"),
      queryCiphertextDigest: id("q/A2"), enrollmentCiphertextDigest: id("e/A2"), verifiedOutputCollectionDigest: id("o/A2"),
      modelHash: id("model"), quantizationHash: id("quant"), finalizedAtBlock: await provider.getBlockNumber() };
    await confirmed(source.recordImmutableSession(sid, rec));
    const enc = encodeFinalizedSession(rec);
    const rc = await adapter.previewFinalizedUniqueEnrollment(sid, enc);
    const idc = H([DST.ID, sA]);
    const sig = joinSignature(station._signingKey().signDigest(await gateway.linkDigest(rc.receiptId, rc.uniqueInputDigest, BigInt(base.cEnroll), idc, policyDigest, 1)));
    await confirmed(gateway.issue(sid, enc, BigInt(base.cEnroll), idc, policyDigest, sig));
    credLeaves.push(H([DST.LEAF, BigInt(base.cEnroll), idc, policyDigest, 1n]));
  }
  const reissuedIndex = credLeaves.length - 1;
  const c8 = await challenge(b8, { oneTime: false });
  const p8 = await prove(c8, { index: reissuedIndex });
  proveMs.push(p8.ms);
  const revokeDev = await confirmed(gateway.revokeDevice(0, merklePath(devLeaves, DEV_DEPTH, 0).pathElements));
  result.gas.revokeDevice = gasOf(revokeDev);
  devLeaves[0] = 0n;
  result.checks.preDeviceRevocationRootRejected = await reverts(gateway.connect(b8).callStatic.authenticate(...p8.args), "InvalidRoot", gateway);
  const p8b = await prove(c8, { index: reissuedIndex });
  proveMs.push(p8b.ms);
  const r8 = await confirmed(gateway.connect(b8).authenticate(...p8b.args));
  authGas.push({ case: "appScopedAfterDeviceRevocation", gas: gasOf(r8) });
  result.checks.reissueKeepsAppPseudonym = p8b.nullifier === p3.nullifier;

  // 7. Statement checks.
  const b9 = await fresh();
  const c9 = await challenge(b9, { oneTime: false });
  const p9 = await prove(c9, { index: reissuedIndex });
  proveMs.push(p9.ms);
  const wrongScope = [...p9.args];
  wrongScope[4] = [...p9.args[4]];
  wrongScope[4][7] = "0x" + (BigInt(wrongScope[4][7]) + 1n).toString(16);
  result.checks.mismatchedScopeRejected = await reverts(gateway.connect(b9).callStatic.authenticate(...wrongScope), "InvalidStatement", gateway);
  const forged = [...p9.args];
  forged[4] = [...p9.args[4]];
  forged[4][8] = "0x" + (BigInt(forged[4][8]) + 1n).toString(16);
  result.checks.alteredNullifierRejected = await reverts(gateway.connect(b9).callStatic.authenticate(...forged), "ProofRejected", gateway);

  result.gas.authenticate = authGas;
  result.gas.issueChallenge = c1.gas;
  result.proveMs = proveMs.map(Math.round);
  result.runtimeBytes = {
    gateway: contracts["PrivateAuthGateway.sol"].PrivateAuthGateway.evm.deployedBytecode.object.length / 2,
    tree: contracts["PoseidonMerkleTree.sol"].PoseidonMerkleTree.evm.deployedBytecode.object.length / 2,
  };
} finally {
  await chain.disconnect();
}

const expected = {
  poseidonMatchesCircomlibjs: true, deviceRootMatchesMirror: true, substitutedIdcRejected: "InvalidLink",
  receiptConsumedOnce: "InvalidSourceSession", credentialRootMatchesMirror: true, nonBeneficiarySenderRejected: "InvalidChallenge",
  sameScopeReplayRejected: "NullifierUsed", appPseudonymStable: true, oneTimeAndAppNullifiersDiffer: true,
  proofOnPreInsertionRootAccepted: true, preRevocationRootRejected: "InvalidRoot", unaffectedHolderReprovesOnNewRoot: true,
  credentialRootMatchesMirrorAfterRevocation: true, revokedHolderOldProofRejected: "InvalidRoot",
  revokedHolderCannotProveOnNewRoot: true, preDeviceRevocationRootRejected: "InvalidRoot", reissueKeepsAppPseudonym: true,
  mismatchedScopeRejected: "InvalidStatement", alteredNullifierRejected: "ProofRejected",
};
const record = {
  generatedAt: new Date().toISOString(),
  scope: "PrivateAuthGateway on local Ganache 7.9.2 (Shanghai), solc " + solc.version() + "; credential tree depth 20, device tree depth 10, root history 64; trees hash with the internal PoseidonT3 library (generated assembly), credential leaf with the circomlibjs 5-input Poseidon contract; real auth_private_128 Groth16 proofs",
  securityWarning: "Benchmark-only single-contributor Groth16 setup; software EdDSA and station keys; local fixture finalization source; synthetic vectors; never deploy.",
  ...result,
};
await mkdir(out, { recursive: true });
await writeFile(resolve(out, "result.json"), `${JSON.stringify(record, null, 2)}\n`, "utf8");
process.stdout.write(`${JSON.stringify({ checks: result.checks, gas: result.gas, proveMs: result.proveMs, runtimeBytes: result.runtimeBytes }, null, 2)}\n`);
for (const [k, v] of Object.entries(expected)) assert.equal(result.checks[k], v, k);
if (globalThis.curve_bn128) await globalThis.curve_bn128.terminate();
process.exit(0);
