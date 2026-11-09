// End-to-end BioBind private profile with REAL LFW features in the recommended
// configuration: 512-D, 12-bit coordinates (Gamma = 2047, offset 2048), commitment
// format v2 (auth_private_v2), device tree depth 20. Derived from private-e2e-lfw512.mjs.
// Vectors: experiments/biometric/scripts/export_demo_vectors.py (fixed
// selection rule; a demonstration, not an accuracy estimate). Epsilon: fold-0
// threshold of the LFW View 2 protocol at Gamma = 2047.
// Usage: node scripts/private-e2e-lfw512-v2.mjs <data-dir>/embeddings/demo_vectors.json
//
// Local Ganache; real LFW vectors; simulated committee with transparent SCMV
// stand-ins, no PVSC/coverage/threshold-decryption execution. Software keys and
// benchmark-only Groth16 setup. Optional private attested-match comparison
// retains the same nine public inputs and hides credential/device membership.
import { observePrivateGateway } from "./lib/public-chain-observer.mjs";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { buildEddsa, buildPoseidon, poseidonContract } from "circomlibjs";
import ganache from "ganache";
import solc from "solc";
import { ethers } from "ethers";
import { groth16, wtns } from "snarkjs";
import { DST_PROBE, poseidonCommitmentWide, squaredDistance } from "./commitment.mjs";
import { MESSAGE_ENROLL, computeSessionBinding, createP256ECDHKeyPair, createTrustedCapturePacket,
  deriveChannelKey, deriveP256SharedSecret } from "./trusted-capture-wire.mjs";
import { ScmvGallery, prepare, scmvBase } from "./lib/scmv-model.mjs";
import { ciphertextDigest } from "./lib/biozkfhe-source-model.mjs";
import { BridgeError, EnrollmentBridge, commitmentV2, toU16 } from "./lib/enrollment-bridge.mjs";
import { encodeFinalizedSession } from "./lib/finalized-record.mjs";

const root = resolve(import.meta.dirname, "..");
const ATTESTED = process.env.BIOBIND_MATCH_BACKEND === "attested";
const OBSERVER = process.env.BIOBIND_OBSERVER === "1";
const out = resolve(root, process.env.BIOBIND_OUT ?? "build/private-e2e-lfw512-v2");
const CIRCUIT = ATTESTED ? "auth_private_attested_dev20" : "auth_private_v2_512_b12_dev20";
const VERIFIER = ATTESTED ? "generated/Groth16VerifierPrivateAttested.sol" : "generated/Groth16VerifierPrivateV2_512_b12_dev20.sol";
const wasm = resolve(root, "build", CIRCUIT, `${CIRCUIT}_js`, `${CIRCUIT}.wasm`);
const zkey = resolve(root, "build", CIRCUIT, `${CIRCUIT}_final.zkey`);
const ENC = commitmentV2(12); // { format: 2, bits: 12, packSize: 20, offset: 2048 }
const R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const GAMMA = 2047, L = 512;
const PARAMS = { L, d: 4, n: 3, gamma: GAMMA, T: scmvBase(GAMMA, L) };
const CAP = PARAMS.n * PARAMS.d;
// 1:N dedup threshold calibrated on LFW (dev-workspace/notes/dedup-calibration.md): the
// smallest inner product with calibration-half FMR <= 1e-4 at Gamma = 2047.
const TAU = BigInt(JSON.parse(await readFile(resolve(root, "..", "experiments", "biometric",
  "results", "dedup_calibration.json"), "utf8")).thresholds["FMR<=0.0001"].tau);
const demo = JSON.parse(await readFile(process.argv[2], "utf8"));
const EPSILON = BigInt(JSON.parse(await readFile(resolve(root, "..", "experiments", "biometric",
  "results", "lfw_view2_int12.json"), "utf8")).folds[0].threshold);
// Real quantized vectors (signed, Gamma = 2047) by role. The MCU packet carries them
// u16-offset; the bridge and prover use the circuit encoding (offset 2048).
const realVector = (role) => demo.profiles.b12.signed[role];
const encode = (v) => v.map((x) => x + ENC.offset);
const CRED_DEPTH = 20, DEV_DEPTH = 20, ROOT_HISTORY = 64;
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
    "interfaces/IBioZKFHEFinalizationSource.sol", VERIFIER];
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
  const policyDigest = field("bioBind/policy/lfw-gamma2047/12bit-offset2048/512/commitment-v2");
  const policyHash = id("bioBind/policy/lfw-gamma2047/12bit-offset2048/512/commitment-v2");
  const modelHash = id("model/facenet-pytorch/InceptionResnetV1/vggface2/281cebca");
  const quantizationHash = id("quant/L2-gamma2047-round-half-away/12bit-offset2048/v2");

  const committeeKeys = Array.from({ length: 5 }, (_, i) => new ethers.Wallet(id(`e2e-private-committee-${i}`)));
  const committee = new Committee(committeeKeys);
  const source = await deploy("BioZKFHEEnrollmentSourceCompact.sol", "BioZKFHEEnrollmentSourceCompact",
    committeeKeys.map((w) => w.address), 3, PARAMS.n, PARAMS.d, modelHash, quantizationHash);
  const adapter = await deploy("BioZKFHEFinalizationAdapter.sol", "BioZKFHEFinalizationAdapter", source.address);
  const verifier = await deploy(VERIFIER, "Groth16Verifier");
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
    quantizationHash, policyHash, policyDigest: policyDigest.toString(), scmv: PARAMS, commitment: ENC,
    mcu: { ...mcu, publicKey: mcuKeys.publicKey } });
  let sealed = bridge.initialize();
  let mcuCounter = 0n;
  const now = async () => (await provider.getBlock("latest")).timestamp;
  const destination = { chainId: 31337, gateway: gateway.address };

  // Authentication capture module (AFE), registered in the device tree.
  const afePrv = randomBytes(32);
  const [ax, ay] = eddsa.prv2pub(afePrv).map((p) => F.toObject(p));
  const fw = field("fw/1.0"), model = field("model/inception-vggface2-512"), quant = field("quant/u16-offset");
  const devLeaf = H([DST.DEV, ax, ay, fw, model, quant, policyDigest]);
  await confirmed(gateway.registerDevice(devLeaf, ax, ay, fw, model, quant, policyDigest));
  const devLeaves = [devLeaf];
  const credLeaves = [];

  async function enroll(person, holder, secret, role) {
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
    const packet = createTrustedCapturePacket({ messageType: MESSAGE_ENROLL, vector: toU16(realVector(role)),
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

  const A = await enroll("A", holderA, BigInt(`0x${randomBytes(31).toString("hex")}`), "A_enroll");
  const B = await enroll("B", holderB, BigInt(`0x${randomBytes(31).toString("hex")}`), "B_enroll");
  const Again = await enroll("A", holderC, BigInt(`0x${randomBytes(31).toString("hex")}`), "A_reenroll");
  result.enrollments = [A.row, B.row, Again.row];
  // With a calibrated threshold, a genuine re-enrollment can be missed (non-adversarial
  // miss rate about 17% at this operating point); the check is that the outcome
  // follows the threshold, and the outcome itself is reported.
  const reScore = realVector("A_enroll").reduce((acc, x, i) => acc + BigInt(x) * BigInt(realVector("A_reenroll")[i]), 0n);
  result.reenrollment = { innerProduct: reScore.toString(), tau: TAU.toString(), status: Again.row.status,
    outcome: Again.row.status === "Duplicate" ? "duplicate detected" : "MISSED duplicate: A holds two credentials" };
  result.checks.reenrollmentOutcomeFollowsThreshold = (reScore >= TAU) === (Again.row.status === "Duplicate");
  result.checks.credentialRootMatchesMirror =
    (await (new ethers.Contract(await gateway.credentialTree(), contracts["PoseidonMerkleTree.sol"].PoseidonMerkleTree.abi, owner)).currentRoot()).toString()
    === merklePath(credLeaves, CRED_DEPTH, 0).root.toString();

  // Authentication: holder A, fresh one-time beneficiary, app-scoped pseudonym.
  async function authenticate(holder, liveRole, { oneTime = false, app = "app/e2e", faultyMatcher = false, captureOnly = false } = {}) {
    const beneficiary = ethers.Wallet.createRandom().connect(provider);
    await confirmed(owner.sendTransaction({ to: beneficiary.address, value: ethers.utils.parseEther("1") }));
    const deadline = (await now()) + 3600;
    const rc = await confirmed(gateway.issueChallenge(beneficiary.address, policyDigest, id(app), id("action/1"), oneTime, deadline));
    const ch = rc.events.find((e) => e.event === "ChallengeIssued").args;
    const ctxHash = BigInt((await gateway.ctxHashOf(ch.nonce)).toString());
    const probe = encode(realVector(liveRole));
    const rProbe = BigInt(`0x${randomBytes(31).toString("hex")}`);
    const cProbe = await poseidonCommitmentWide({ roleTag: DST_PROBE, policyDigest, contextDigest: ctxHash, dimension: L,
      salt: rProbe, values: probe, bits: ENC.bits, packSize: ENC.packSize });
    const notAfter = BigInt(deadline);
    // The private signature baseline puts opening checks and matching in the same
    // capture TCB. It signs the enrollment commitment and policy threshold too.
    const distance = squaredDistance(holder.opening.values.map(BigInt), probe.map(BigInt));
    if (ATTESTED && !faultyMatcher && distance > EPSILON)
      return { accepted: false, matcher: "refused", distance: distance.toString() };
    if (ATTESTED) {
      const recomputed = await poseidonCommitmentWide({ roleTag: 1, policyDigest, contextDigest: 0,
        dimension: L, salt: holder.opening.salt, values: holder.opening.values, bits: ENC.bits, packSize: ENC.packSize });
      assert.equal(recomputed.toString(), holder.cEnroll.toString(), "matcher checks the enrollment opening");
    }
    const message = ATTESTED && !captureOnly
      ? [8n, holder.cEnroll, cProbe, ctxHash, policyDigest, model, quant, fw, notAfter, EPSILON]
      : [DST.CAPTURE, cProbe, ctxHash, policyDigest, model, quant, fw, notAfter];
    const sig = eddsa.signPoseidon(afePrv, F.e(H(message)));
    const scope = BigInt(ch.scope.toString());
    const cred = merklePath(credLeaves, CRED_DEPTH, holder.index), dev = merklePath(devLeaves, DEV_DEPTH, 0);
    const input = { credRoot: cred.root, devRoot: dev.root, cProbe, policyDigest, ctxHash, epsilon: EPSILON, notAfter, scope,
      nullifier: H([DST.NULLIFIER, holder.secret, scope]), identitySecret: holder.secret, templateVersion: 1n,
      cEnroll: holder.cEnroll, rEnroll: holder.opening.salt, rProbe, enrollment: holder.opening.values, probe,
      credPathElements: cred.pathElements, credPathIndices: cred.pathIndices, devAx: ax, devAy: ay, devFirmware: fw,
      devModel: model, devQuantization: quant, devPathElements: dev.pathElements, devPathIndices: dev.pathIndices,
      sigR8x: F.toObject(sig.R8[0]), sigR8y: F.toObject(sig.R8[1]), sigS: sig.S };
    if (ATTESTED) for (const name of ["rEnroll", "rProbe", "enrollment", "probe"]) delete input[name];
    if (ATTESTED && !result.attestedBindingControls && !faultyMatcher && !captureOnly) {
      await mkdir(out, {recursive: true});
      result.attestedBindingControls = {};
      for (const name of ["cEnroll", "cProbe", "epsilon", "ctxHash", "notAfter", "identitySecret", "nullifier"]) {
        let rejected = false;
        try {
          await wtns.calculate(str({...input, [name]: BigInt(input[name]) + 1n}), wasm, resolve(out, `invalid-${name}.wtns`));
        } catch (error) {
          assert.match(String(error), /Assert Failed|assertion failed/i);
          rejected = true;
        }
        assert.equal(rejected, true, `attested relation must bind ${name}`);
        result.attestedBindingControls[name] = rejected;
      }
    }
    let proof, publicSignals;
    const t0 = performance.now();
    try {
      ({ proof, publicSignals } = await groth16.fullProve(str(input), wasm, zkey));
    } catch (error) {
      // A tool, file or transport failure is not evidence of circuit rejection.
      assert.match(String(error), /Assert Failed|assertion failed/i);
      return { accepted: false, witness: "rejected", distance: distance.toString() };
    }
    const ms = performance.now() - t0;
    const [pA, pB, pC, pub] = JSON.parse(`[${await groth16.exportSolidityCallData(proof, publicSignals)}]`);
    const r = await confirmed(gateway.connect(beneficiary).authenticate(ch.nonce, pA, pB, pC, pub));
    return { accepted: r.status === 1, gas: gasOf(r), challengeGas: gasOf(rc), proveMs: Math.round(ms),
      distance: distance.toString(), nullifier: input.nullifier.toString(), transactionHash: r.transactionHash };
  }
  const authA1 = await authenticate(A, "A_probe");
  const authA2 = await authenticate(A, "A_reenroll"); // another genuine capture of A
  const authB = await authenticate(B, "B_probe");
  const impostor = await authenticate(A, "B_probe"); // B presents at the AFE against A's credential
  result.authentications = { A1: authA1, A2: authA2, B: authB, impostorOnA: impostor };
  result.checks.genuineAccepted = authA1.accepted && authA2.accepted && authB.accepted;
  result.checks.appPseudonymStableForA = authA1.nullifier === authA2.nullifier;
  result.checks.pseudonymsDifferAcrossHolders = authA1.nullifier !== authB.nullifier;
  result.checks.impostorRejectedAtWitness = ATTESTED ? impostor.matcher === "refused" : impostor.witness === "rejected";
  if (ATTESTED) {
    const fault = await authenticate(A, "B_probe", { faultyMatcher: true });
    const captureOnly = await authenticate(A, "A_probe", { captureOnly: true });
    result.matchingTrustControls = { honestMatcherRefuses: impostor.matcher === "refused",
      faultyAuthorizedMatcherAccepted: fault.accepted, captureOnlySignatureRejected: captureOnly.witness === "rejected",
      caveat: "Fault acceptance violates the trusted matching premise; it is not an attack under the honest-TCB model." };
    assert.equal(fault.accepted, true);
    assert.equal(captureOnly.witness, "rejected");
  }
  if (OBSERVER) {
    const otherA = await authenticate(A, "A_probe", {app: "app/second"});
    const otherB = await authenticate(B, "B_probe", {app: "app/second"});
    result.authentications.A_otherApp = otherA;
    result.authentications.B_otherApp = otherB;
    assert.equal(otherA.accepted && otherB.accepted, true);
    const view = await observePrivateGateway(provider, gateway, [source, adapter]);
    const issuedVisible = view.issued.every(t => t.args.cEnroll && t.args.idc && t.args.sourceRecord);
    const sameScope = view.pairs.some(p => p.sameScope && p.sameNullifier && !p.sameSender);
    const crossScope = view.pairs.some(p => !p.sameScope && !p.sameNullifier && p.commonFunder);
    assert.equal(issuedVisible && sameScope && crossScope, true);
    assert.notEqual(authA1.nullifier, otherA.nullifier);
    result.observerChecks = { issuanceCalldataExposesCommitments: issuedVisible,
      sameScopeLinkDespiteFreshSenders: sameScope, crossScopeCommonFundingVisible: crossScope,
      holderANullifierChangesAcrossScopes: authA1.nullifier !== otherA.nullifier,
      allAuthSendersFresh: new Set(view.authentications.map(a=>a.sender)).size === view.authentications.length,
      allProbeCommitmentsDistinct: new Set(view.authentications.map(a=>a.publicSignals.cProbe)).size === view.authentications.length };
    for (const passed of Object.values(result.observerChecks)) assert.equal(passed, true);
    await mkdir(out, {recursive:true});
    await writeFile(resolve(out, "public-observer.json"), JSON.stringify(view, null, 2)+"\n");
  }
} finally {
  await chain.disconnect();
}

const expected = { idcSubstitutionRejected: "rejected", hostChosenCommitmentRejected: "rejected",
  reenrollmentOutcomeFollowsThreshold: true, credentialRootMatchesMirror: true, genuineAccepted: true,
  appPseudonymStableForA: true, pseudonymsDifferAcrossHolders: true, impostorRejectedAtWitness: true };
const record = {
  generatedAt: new Date().toISOString(),
  scope: "BioBind private profile end to end, recommended configuration: real LFW features (InceptionResnetV1 VGGFace2, 512-D), 12-bit coordinates (Gamma 2047), commitment format v2, device tree depth 20; local Ganache 7.9.2 (Shanghai), solc " + solc.version() + ": MCU packet, R1 bridge, BioZKFHEEnrollmentSourceCompact (t=3 of 5 simulated committee, SCMV L=512), adapter, PrivateAuthGateway (PoseidonT3 trees), " + CIRCUIT + " proofs; epsilon " + EPSILON + "; dedup tau " + TAU + " (LFW-calibrated, FMR<=1e-4)",
  matchingBackend: ATTESTED ? "private attested matching; ZK hides membership/signature" : "private ZK matching",
  node: process.version,
  demoSelection: demo.selection,
  securityWarning: "Simulated committee (PVSC, coverage, threshold decryption not executed and not in gas); software MCU/bridge/AFE keys; benchmark-only Groth16 setup; real LFW vectors; never deploy.",
  ...result,
};
for (const [k, v] of Object.entries(expected)) assert.equal(result.checks[k], v, k);
await mkdir(out, { recursive: true });
await writeFile(resolve(out, "result.json"), `${JSON.stringify(record, (_, v) => (typeof v === "bigint" ? v.toString() : v), 2)}\n`, "utf8");
process.stdout.write(`${JSON.stringify({ checks: result.checks, reenrollment: result.reenrollment, enrollments: result.enrollments, authentications: result.authentications }, null, 2)}\n`);
for (const [k, v] of Object.entries(expected)) assert.equal(result.checks[k], v, k);
if (globalThis.curve_bn128) await globalThis.curve_bn128.terminate();
process.exit(0);
