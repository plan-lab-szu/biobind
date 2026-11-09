// End-to-end BioBind private profile on one local chain:
//   MCU capture packet -> R1 enrollment bridge -> BioZKFHEEnrollmentSourceCompact
//   (bound request, snapshot verdict, stale abort, root migration) -> simulated
//   committee finalization -> BioZKFHEFinalizationAdapter (calldata record) ->
//   PrivateAuthGateway.issue (credential leaf, idc under the bridge signature)
//   -> unlinkable authentication with a real auth_private_128 proof.
// The committee is simulated (SCMV plaintext semantics); PVSC, coverage, and
// threshold decryption are not executed. Software MCU, bridge, and AFE keys;
// benchmark-only Groth16 setup; synthetic vectors. Never deploy.
// Requires build/auth_private_128 (scripts/auth-private-benchmark.mjs).
// Usage (from prototype/): .toolchain/node-v24.19.0-win-x64/node.exe scripts/private-e2e-evaluation.mjs
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { buildEddsa, buildPoseidon, poseidonContract } from "circomlibjs";
import ganache from "ganache";
import solc from "solc";
import { ethers } from "ethers";
import { groth16 } from "snarkjs";
import { DST_PROBE, poseidonCommitment, squaredDistance } from "./commitment.mjs";
import { MESSAGE_ENROLL, computeSessionBinding, createP256ECDHKeyPair, createTrustedCapturePacket,
  deriveChannelKey, deriveP256SharedSecret } from "./trusted-capture-wire.mjs";
import { ScmvGallery, prepare, scmvBase, syntheticPeople } from "./lib/scmv-model.mjs";
import { ciphertextDigest } from "./lib/biozkfhe-source-model.mjs";
import { BridgeError, EnrollmentBridge, toU16 } from "./lib/enrollment-bridge.mjs";
import { encodeFinalizedSession } from "./lib/finalized-record.mjs";

const root = resolve(import.meta.dirname, "..");
const out = resolve(root, "build", "private-e2e");
const wasm = resolve(root, "build", "auth_private_128", "auth_private_128_js", "auth_private_128.wasm");
const zkey = resolve(root, "build", "auth_private_128", "auth_private_128_final.zkey");
const R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const GAMMA = 128, L = 128;
const PARAMS = { L, d: 4, n: 3, gamma: GAMMA, T: scmvBase(GAMMA, L) };
const CAP = PARAMS.n * PARAMS.d;
const TAU = BigInt(GAMMA * GAMMA / 2);
const EPSILON = 2000n; // squared u16 distance for synthetic recapture noise
const CRED_DEPTH = 20, DEV_DEPTH = 10, ROOT_HISTORY = 64;
const DST = { ID: 3n, LEAF: 4n, DEV: 5n, CAPTURE: 6n, NULLIFIER: 7n };
const STATUS = ["None", "Created", "Bound", "Finalized", "AbortedStaleSlot", "Duplicate"];
const RECORD_FIELDS = ["sid", "status", "galleryCount", "blockCount", "gallerySnapshotHash",
  "snapshotLastCommitment", "contextHash", "queryDigest", "enrollDigest"];
const { id, keccak256, defaultAbiCoder: abi, joinSignature } = ethers.utils;

const poseidon = await buildPoseidon();
const eddsa = await buildEddsa();
const F = poseidon.F;
const H = (xs) => F.toObject(poseidon(xs.map(BigInt)));
const field = (label) => BigInt(`0x${createHash("sha256").update(label).digest("hex")}`) % R;
const str = (o) => JSON.parse(JSON.stringify(o, (_, v) => (typeof v === "bigint" ? v.toString() : v)));
const confirmed = async (tx) => (await tx).wait();
const gasOf = (r) => r.gasUsed.toNumber();
const sortByAddress = (ws) => [...ws].sort((a, b) => (BigInt(a.address) < BigInt(b.address) ? -1 : 1));
const plainRecord = (r) => Object.fromEntries(RECORD_FIELDS.map((f) => [f, r[f]]));

async function compile() {
  const paths = ["PrivateAuthGateway.sol", "PoseidonMerkleTree.sol", "PoseidonT3.sol", "BioZKFHEFinalizationAdapter.sol",
    "BioZKFHEEnrollmentSourceCompact.sol", "interfaces/IBioZKFHEUniquenessAdapter.sol",
    "interfaces/IBioZKFHEFinalizationSource.sol", "generated/Groth16VerifierPrivate128.sol"];
  const sources = Object.fromEntries(await Promise.all(paths.map(async (p) =>
    [p, { content: await readFile(resolve(root, "contracts", p), "utf8") }])));
  const r = JSON.parse(solc.compile(JSON.stringify({ language: "Solidity", sources,
    settings: { optimizer: { enabled: true, runs: 200 }, evmVersion: "shanghai",
      outputSelection: { "*": { "*": ["abi", "evm.bytecode.object"] } } } })));
  const errors = (r.errors ?? []).filter((e) => e.severity === "error");
  assert.equal(errors.length, 0, errors.map((e) => e.formattedMessage).join("\n"));
  return r.contracts;
}

/// Simulated committee: identify on the session snapshot, recompute the merged block.
class Committee {
  constructor(wallets) {
    this.wallets = sortByAddress(wallets);
    this.gallery = new ScmvGallery(PARAMS);
    this.blockCts = [];
    this.snapshots = new Map();
  }
  snapshot(sid) {
    const g = new ScmvGallery(PARAMS);
    g.blocks = this.gallery.blocks.map((W) => W.map((r) => [...r]));
    g.N = this.gallery.N;
    this.snapshots.set(sid, { g, cts: [...this.blockCts] });
  }
  propose(sid, cIdentify, cEnroll) {
    const { g, cts } = this.snapshots.get(sid);
    const unique = g.identify(cIdentify.rows).every((s) => s < TAU);
    const append = g.N % CAP === 0;
    const blockIndex = append ? cts.length : cts.length - 1;
    const uOld = append ? ethers.constants.HashZero : cts.at(-1).digest;
    let next = cEnroll;
    if (!append) {
      const last = cts.at(-1);
      next = { role: "block", rows: last.rows.map((row, i) => row.map((x, j) => x + cEnroll.rows[i][j])),
        randomness: keccak256(abi.encode(["bytes32", "bytes32"], [last.randomness, cEnroll.randomness])) };
      next.digest = ciphertextDigest(next);
    }
    const outputDigest = keccak256(abi.encode(["string", "bytes32", "bool"], ["outputs", sid, unique]));
    return { unique, append, blockIndex, uOld, uNew: unique ? next.digest : ethers.constants.HashZero, outputDigest, next,
      Venroll: cEnroll.rows };
  }
  async sign(source, rec, p) {
    const digest = await source.confirmationDigest(rec, p.unique, p.outputDigest, p.blockIndex, p.uOld, p.uNew);
    return this.wallets.map((w) => joinSignature(w._signingKey().signDigest(digest)));
  }
  commit(p) {
    if (p.append) this.blockCts.push(p.next); else this.blockCts[this.blockCts.length - 1] = p.next;
    this.gallery.update(p.Venroll);
  }
}

function merklePath(leaves, depth, index) {
  const zeros = [0n];
  for (let i = 0; i < depth; i++) zeros.push(H([zeros[i], zeros[i]]));
  let level = new Map(leaves.map((v, i) => [i, v]));
  const pathElements = [], pathIndices = [];
  let idx = index;
  for (let d = 0; d < depth; d++) {
    pathElements.push(level.has(idx ^ 1) ? level.get(idx ^ 1) : zeros[d]);
    pathIndices.push(idx & 1);
    const next = new Map();
    for (const k of new Set([...level.keys()].map((x) => x >> 1))) {
      next.set(k, H([level.has(2 * k) ? level.get(2 * k) : zeros[d], level.has(2 * k + 1) ? level.get(2 * k + 1) : zeros[d]]));
    }
    level = next;
    idx >>= 1;
  }
  return { root: level.get(0), pathElements, pathIndices };
}

const contracts = await compile();
const chain = ganache.provider({ chain: { chainId: 31337, hardfork: "shanghai" }, logging: { quiet: true },
  miner: { blockGasLimit: 30_000_000 }, wallet: { deterministic: true, totalAccounts: 4 } });
const provider = new ethers.providers.Web3Provider(chain);
const [owner, holderA, holderB, holderC] = Object.values(chain.getInitialAccounts())
  .map(({ secretKey }) => new ethers.Wallet(secretKey, provider));
const deployFrom = async (abiDef, bytecode, ...args) => {
  const c = await new ethers.ContractFactory(abiDef, bytecode, owner).deploy(...args, { gasLimit: 29_000_000 });
  await c.deployTransaction.wait();
  return c;
};
const deploy = (path, name, ...args) => deployFrom(contracts[path][name].abi, `0x${contracts[path][name].evm.bytecode.object}`, ...args);

const result = { enrollments: [], checks: {} };
try {
  // Profile identifiers. The policy field digest is what the circuit and commitments use.
  const policyDigest = field("bioBind/policy/sqdist-2000/u16-offset/128/v1");
  const policyHash = id("bioBind/policy/sqdist-2000/u16-offset/128/v1");
  const modelHash = id("bridge/model/synthetic-FaceNet-shaped-128");
  const quantizationHash = id("bridge/quant/L2-gamma128-round/u16-offset32768/v1");

  const committeeKeys = Array.from({ length: 5 }, (_, i) => new ethers.Wallet(id(`e2e-private-committee-${i}`)));
  const committee = new Committee(committeeKeys);
  const source = await deploy("BioZKFHEEnrollmentSourceCompact.sol", "BioZKFHEEnrollmentSourceCompact",
    committeeKeys.map((w) => w.address), 3, PARAMS.n, PARAMS.d, modelHash, quantizationHash);
  const adapter = await deploy("BioZKFHEFinalizationAdapter.sol", "BioZKFHEFinalizationAdapter", source.address);
  const verifier = await deploy("generated/Groth16VerifierPrivate128.sol", "Groth16Verifier");
  const p5 = await deployFrom(poseidonContract.generateABI(5), poseidonContract.createCode(5));
  const gateway = await deploy("PrivateAuthGateway.sol", "PrivateAuthGateway", adapter.address, verifier.address,
    p5.address, CRED_DEPTH, DEV_DEPTH, ROOT_HISTORY);
  await confirmed(adapter.configureAuthorizedConsumer(gateway.address));
  await confirmed(gateway.registerPolicy(policyDigest, EPSILON));

  // R1 enrollment bridge = enrollment station: one derivation key registered at both contracts.
  const derivationKey = ethers.Wallet.createRandom();
  await confirmed(source.registerBridge(derivationKey.address));
  await confirmed(gateway.registerEnrollmentStation(derivationKey.address));
  const mcuKeys = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const mcu = { deviceVersionId: id("bridge/mcu-version"), firmwareMeasurement: id("bridge/mcu-fw"), channelId: id("bridge/attested-channel") };
  const shared = deriveP256SharedSecret(createP256ECDHKeyPair().privateKey, createP256ECDHKeyPair().publicKey);
  const keyFor = (binding) => deriveChannelKey(shared, mcu.channelId, computeSessionBinding(binding));
  const bridge = new EnrollmentBridge({ derivationKey, deviceVersionId: id("bridge/unused-in-private-profile"), modelHash,
    quantizationHash, policyHash, policyDigest: policyDigest.toString(), scmv: PARAMS, mcu: { ...mcu, publicKey: mcuKeys.publicKey } });
  let sealed = bridge.initialize();
  let mcuCounter = 0n;
  const people = syntheticPeople(23, L);
  const now = async () => (await provider.getBlock("latest")).timestamp;
  const destination = { chainId: 31337, gateway: gateway.address };

  // Authentication capture module (AFE), registered in the device tree.
  const afePrv = createHash("sha256").update("device-key/AFE-e2e").digest();
  const [ax, ay] = eddsa.prv2pub(afePrv).map((p) => F.toObject(p));
  const fw = field("fw/1.0"), model = field("model/synthetic-128"), quant = field("quant/u16-offset");
  const devLeaf = H([DST.DEV, ax, ay, fw, model, quant, policyDigest]);
  await confirmed(gateway.registerDevice(devLeaf, ax, ay, fw, model, quant, policyDigest));
  const devLeaves = [devLeaf];
  const credLeaves = [];

  async function enroll(person, holder, secret) {
    const row = { person };
    const r0 = await confirmed(source.createSession());
    const a = r0.events.find((e) => e.event === "SessionCreated").args;
    let rec = plainRecord(a.record);
    committee.snapshot(a.sid);
    const ctx = { chainId: 31337, sourceContract: source.address, sid: a.sid, op: 1, galleryCount: Number(rec.galleryCount),
      gallerySnapshotHash: rec.gallerySnapshotHash, ledgerMetaHash: a.ledgerMetaHash };
    const binding = { sourceChainId: 31337, sourceContract: source.address, sourceSessionId: a.sid,
      sourceContextHash: rec.contextHash, destinationChainId: 31337, destinationGateway: gateway.address,
      holder: holder.address, lineageId: id(`lineage/${person}`), enrollmentContext: id(`lineage/${person}/ctx`),
      policyHash, modelHash, quantizationHash };
    const packet = createTrustedCapturePacket({ messageType: MESSAGE_ENROLL, vector: toU16(people.capture(person, GAMMA)),
      metadata: { ...mcu, modelHash, quantizationHash, policyHash, sessionBinding: computeSessionBinding(binding),
        counter: ++mcuCounter, notAfter: 4_000_000_000n, coordinateBits: 16 },
      channelKey: keyFor(binding), signingPrivateKey: mcuKeys.privateKey });
    bridge.config.mcu.channelKey = keyFor(binding);
    const prep = await bridge.prepareEnrollment(sealed, { packet, binding, sourceContext: ctx, now: await now() });
    sealed = prep.sealed;
    const at = prep.attestation;
    const r1 = await confirmed(source.bindRequest(rec, prep.cIdentify.digest, prep.cEnroll.digest, at.galleryCount, at.h, at.k, at.signature));
    rec = plainRecord(r1.events.find((e) => e.event === "RequestBound").args.record);
    const p = committee.propose(a.sid, prep.cIdentify, prep.cEnroll);
    const r2 = await confirmed(source.finalize(rec, p.unique, p.outputDigest, p.uNew, await committee.sign(source, rec, p)));
    row.status = STATUS[r2.events.find((e) => e.event === "SessionClosed").args.status];
    Object.assign(row, { createSession: gasOf(r0), bindRequest: gasOf(r1), finalize: gasOf(r2), merge: !p.append });
    if (row.status !== "Finalized") return { row };
    committee.commit(p);
    const sourceRecord = encodeFinalizedSession(r2.events.find((e) => e.event === "SessionFinalized").args.record);
    const receipt = await adapter.previewFinalizedUniqueEnrollment(a.sid, sourceRecord);
    const plain = Object.fromEntries(["receiptId", "sourceChainId", "sourceContract", "sourceSessionId", "sourceContextHash",
      "gallerySnapshotHash", "queryCiphertextDigest", "enrollmentCiphertextDigest", "verifiedOutputCollectionDigest",
      "finalizationDigest", "uniqueInputDigest", "modelHash", "quantizationHash", "finalizedAtBlock"].map((f) => [f, receipt[f].toString()]));
    const idc = H([DST.ID, secret]);
    const link = bridge.signPrivateEnrollmentLink(sealed, { receipt: plain, idc, policyDigest: policyDigest.toString(), destination });
    sealed = link.sealed;
    if (credLeaves.length === 0) {
      result.checks.idcSubstitutionRejected = await gateway.callStatic.issue(a.sid, sourceRecord, link.cEnroll, idc + 1n,
        policyDigest, link.signature).then(() => "NOT_REVERTED", () => "rejected");
      result.checks.hostChosenCommitmentRejected = await gateway.callStatic.issue(a.sid, sourceRecord, BigInt(link.cEnroll) + 1n,
        idc, policyDigest, link.signature).then(() => "NOT_REVERTED", () => "rejected");
    }
    const r3 = await confirmed(gateway.connect(holder).issue(a.sid, sourceRecord, link.cEnroll, idc, policyDigest, link.signature));
    const ev = r3.events.find((e) => e.event === "CredentialIssued").args;
    credLeaves.push(BigInt(ev.leaf.toString()));
    assert.equal(BigInt(ev.leaf.toString()), H([DST.LEAF, BigInt(link.cEnroll), idc, policyDigest, 1n]));
    row.issue = gasOf(r3);
    row.total = row.createSession + row.bindRequest + row.finalize + row.issue;
    return { row, index: Number(ev.index), cEnroll: BigInt(link.cEnroll), opening: prep.opening, secret };
  }

  const A = await enroll("P1", holderA, field("secret/P1"));
  const B = await enroll("P2", holderB, field("secret/P2"));
  const Again = await enroll("P1", holderC, field("secret/P1-second-identity"));
  result.enrollments = [A.row, B.row, Again.row];
  result.checks.sameIdentityDuplicateNotIssued = Again.row.status === "Duplicate";
  result.checks.credentialRootMatchesMirror =
    (await (new ethers.Contract(await gateway.credentialTree(), contracts["PoseidonMerkleTree.sol"].PoseidonMerkleTree.abi, owner)).currentRoot()).toString()
    === merklePath(credLeaves, CRED_DEPTH, 0).root.toString();

  // Authentication: holder A, fresh one-time beneficiary, app-scoped pseudonym.
  async function authenticate(holder, livePerson, { oneTime = false } = {}) {
    const beneficiary = ethers.Wallet.createRandom().connect(provider);
    await confirmed(owner.sendTransaction({ to: beneficiary.address, value: ethers.utils.parseEther("1") }));
    const deadline = (await now()) + 3600;
    const rc = await confirmed(gateway.issueChallenge(beneficiary.address, policyDigest, id("app/e2e"), id("action/1"), oneTime, deadline));
    const ch = rc.events.find((e) => e.event === "ChallengeIssued").args;
    const ctxHash = BigInt((await gateway.ctxHashOf(ch.nonce)).toString());
    const probe = toU16(people.capture(livePerson, GAMMA));
    const rProbe = BigInt(`0x${randomBytes(31).toString("hex")}`);
    const cProbe = await poseidonCommitment({ roleTag: DST_PROBE, policyDigest, contextDigest: ctxHash, dimension: L,
      salt: rProbe, values: probe });
    const notAfter = BigInt(deadline);
    const sig = eddsa.signPoseidon(afePrv, F.e(H([DST.CAPTURE, cProbe, ctxHash, policyDigest, model, quant, fw, notAfter])));
    const scope = BigInt(ch.scope.toString());
    const cred = merklePath(credLeaves, CRED_DEPTH, holder.index), dev = merklePath(devLeaves, DEV_DEPTH, 0);
    const input = { credRoot: cred.root, devRoot: dev.root, cProbe, policyDigest, ctxHash, epsilon: EPSILON, notAfter, scope,
      nullifier: H([DST.NULLIFIER, holder.secret, scope]), identitySecret: holder.secret, templateVersion: 1n,
      cEnroll: holder.cEnroll, rEnroll: holder.opening.salt, rProbe, enrollment: holder.opening.values, probe,
      credPathElements: cred.pathElements, credPathIndices: cred.pathIndices, devAx: ax, devAy: ay, devFirmware: fw,
      devModel: model, devQuantization: quant, devPathElements: dev.pathElements, devPathIndices: dev.pathIndices,
      sigR8x: F.toObject(sig.R8[0]), sigR8y: F.toObject(sig.R8[1]), sigS: sig.S };
    const distance = squaredDistance(holder.opening.values.map(BigInt), probe.map(BigInt));
    let proof, publicSignals;
    const t0 = performance.now();
    try {
      ({ proof, publicSignals } = await groth16.fullProve(str(input), wasm, zkey));
    } catch {
      return { accepted: false, witness: "rejected", distance: distance.toString() };
    }
    const ms = performance.now() - t0;
    const [pA, pB, pC, pub] = JSON.parse(`[${await groth16.exportSolidityCallData(proof, publicSignals)}]`);
    const r = await confirmed(gateway.connect(beneficiary).authenticate(ch.nonce, pA, pB, pC, pub));
    return { accepted: r.status === 1, gas: gasOf(r), challengeGas: gasOf(rc), proveMs: Math.round(ms),
      distance: distance.toString(), nullifier: input.nullifier.toString() };
  }
  const authA1 = await authenticate(A, "P1");
  const authA2 = await authenticate(A, "P1");
  const authB = await authenticate(B, "P2");
  const impostor = await authenticate(A, "P2"); // P2 presents at the AFE against A's credential
  result.authentications = { A1: authA1, A2: authA2, B: authB, impostorOnA: impostor };
  result.checks.genuineAccepted = authA1.accepted && authA2.accepted && authB.accepted;
  result.checks.appPseudonymStableForA = authA1.nullifier === authA2.nullifier;
  result.checks.pseudonymsDifferAcrossHolders = authA1.nullifier !== authB.nullifier;
  result.checks.impostorRejectedAtWitness = impostor.witness === "rejected";
} finally {
  await chain.disconnect();
}

const expected = { idcSubstitutionRejected: "rejected", hostChosenCommitmentRejected: "rejected",
  sameIdentityDuplicateNotIssued: true, credentialRootMatchesMirror: true, genuineAccepted: true,
  appPseudonymStableForA: true, pseudonymsDifferAcrossHolders: true, impostorRejectedAtWitness: true };
const record = {
  generatedAt: new Date().toISOString(),
  scope: "BioBind private profile end to end on local Ganache 7.9.2 (Shanghai), solc " + solc.version() + ": MCU packet, R1 bridge, BioZKFHEEnrollmentSourceCompact (t=3 of 5 simulated committee), adapter, PrivateAuthGateway (PoseidonT3 trees), auth_private_128 proofs; epsilon " + EPSILON,
  securityWarning: "Simulated committee (PVSC, coverage, threshold decryption not executed and not in gas); software MCU/bridge/AFE keys; benchmark-only Groth16 setup; synthetic vectors; never deploy.",
  ...result,
};
await mkdir(out, { recursive: true });
await writeFile(resolve(out, "result.json"), `${JSON.stringify(record, (_, v) => (typeof v === "bigint" ? v.toString() : v), 2)}\n`, "utf8");
process.stdout.write(`${JSON.stringify({ checks: result.checks, enrollments: result.enrollments, authentications: result.authentications }, null, 2)}\n`);
for (const [k, v] of Object.entries(expected)) assert.equal(result.checks[k], v, k);
if (globalThis.curve_bn128) await globalThis.curve_bn128.terminate();
process.exit(0);
