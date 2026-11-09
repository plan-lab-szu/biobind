import { finalizedRecordFor, rememberFinalized } from "./lib/finalized-record.mjs";
import assert from "node:assert/strict";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { resolve } from "node:path";
import { createHash } from "node:crypto";
import ganache from "ganache";
import solc from "solc";
import { ethers } from "ethers";
import { groth16, wtns } from "snarkjs";
import { DST_ENROLL, DST_PROBE, poseidonCommitment, squaredDistance } from "./commitment.mjs";
import { registerSyntheticPolicy } from "./lib/canonical-policy.mjs";

// Researcher-owned, in-process chain; synthetic inputs; no remote RPC.
const root = resolve(import.meta.dirname, "..");
const out = resolve(root, process.env.BIOBIND_OUT ?? "build/strong-baseline");
const hash = ethers.utils.id;
const json = (v) => JSON.stringify(v, (_, x) => typeof x === "bigint" ? x.toString() : x, 2);
const confirmed = async (tx) => (await tx).wait();
const event = (r, name, arg) => r.events.find((e) => e.event === name).args[arg];

// Match an actual EVM error selector; a transport/tool failure is not a pass.
async function rejected(call, contract, errorName) {
  try { await call(); } catch (error) {
    const selector = contract.interface.getSighash(errorName);
    const values = [error.data, error.error?.data, error.error?.error?.data];
    assert.ok(values.some((v) => typeof v === "string" && v.startsWith(selector)),
      `expected ${errorName}, got ${error.message}`);
    return true;
  }
  assert.fail(`expected ${errorName}`);
}

async function compile() {
  const paths = ["UBCALifecycle.sol", "UBCAAuthGateway.sol",
    "interfaces/IBioZKFHEUniquenessAdapter.sol", "interfaces/IBioZKFHEFinalizationSource.sol",
    "BioZKFHEFinalizationAdapter.sol", "test/LocalBioZKFHEFinalizationSource.sol",
    "test/AttestedMatchVerifier.sol", "test/MergedAttestedMatchGateway.sol",
    "generated/Groth16Verifier128.sol"];
  const sources = Object.fromEntries(await Promise.all(paths.map(async (p) =>
    [p, { content: await readFile(resolve(root, "contracts", p), "utf8") }])));
  const gateway = sources["UBCAAuthGateway.sol"].content;
  const guard = "            publicSignals[4] != policyMatchThresholds[credential.policyHash] ||\n";
  const normalized = gateway.replaceAll("\r\n", "\n");
  assert.equal(normalized.split(guard).length, 2, "exact threshold guard must exist once");
  // Explicit ablation reproducing the earlier missing acceptance check.
  // Source is saved for inspection. It is not used as the strong baseline.
  const unbound = normalized.replace(guard, "")
    .replace("contract UBCAAuthGateway is", "contract UnboundThresholdGateway is");
  sources["UnboundThresholdGateway.sol"] = { content: unbound };
  await writeFile(resolve(out, "UnboundThresholdGateway.sol"), unbound);
  const result = JSON.parse(solc.compile(JSON.stringify({ language: "Solidity", sources,
    settings: { optimizer: { enabled: true, runs: 200 }, evmVersion: "shanghai",
      outputSelection: { "*": { "*": ["abi", "evm.bytecode.object", "evm.deployedBytecode.object"] } } } })));
  const errors = (result.errors ?? []).filter((e) => e.severity === "error");
  assert.equal(errors.length, 0, errors.map((e) => e.formattedMessage).join("\n"));
  return { contracts: result.contracts, sourceSha256: Object.fromEntries(Object.entries(sources)
    .map(([p, {content}]) => [p, createHash("sha256").update(content).digest("hex")])) };
}

async function proofFor(input, label, vk) {
  const path = resolve(out, `${label}.wtns`);
  await wtns.calculate(input, resolve(root, "build/auth_distance_128/auth_distance_128_js/auth_distance_128.wasm"), path, {});
  const { proof, publicSignals } = await groth16.prove(
    resolve(root, "build/proving/auth_distance_128/auth_distance_128_benchmark_final.zkey"), path);
  assert.equal(await groth16.verify(vk, publicSignals, proof), true);
  assert.deepEqual(publicSignals.map(String),
    [input.cEnroll, input.cProbe, input.policyDigest, input.ctxHash, input.epsilon].map(String));
  await writeFile(resolve(out, `${label}.json`), json({ input, proof, publicSignals }));
  return JSON.parse(`[${await groth16.exportSolidityCallData(proof, publicSignals)}]`);
}

async function matchCertificate(verifier, signer, input, policyEpsilon, injectMatcherFault = false) {
  // Honest matching model checks openings, range/dimension (via commitment),
  // and pinned threshold. Fault injection changes ONLY the distance decision.
  assert.equal(input.epsilon, policyEpsilon);
  for (const [roleTag, values, salt, expected, contextDigest] of [
    [DST_ENROLL, input.enrollment, input.rEnroll, input.cEnroll, 0],
    [DST_PROBE, input.probe, input.rProbe, input.cProbe, input.ctxHash],
  ]) {
    const actual = await poseidonCommitment({ roleTag, values, salt,
      policyDigest: input.policyDigest, contextDigest, dimension: 128 });
    assert.equal(actual.toString(), expected);
  }
  if (!injectMatcherFault && squaredDistance(input.enrollment, input.probe) > BigInt(policyEpsilon)) {
    return null;
  }
  const signals = [input.cEnroll, input.cProbe, input.policyDigest, input.ctxHash, input.epsilon];
  const signature = signer._signingKey().signDigest(await verifier.matchDigest(signals));
  return [[signature.r, signature.s], [[signature.v, 0], [0, 0]], [0, 0], signals];
}

async function mergedAttestation(gateway, signer, input, policyEpsilon, statement) {
  // B1' model: the capture TCB verifies the holder-supplied enrollment
  // opening, uses its own fresh probe, and signs one combined statement.
  assert.equal(input.epsilon, policyEpsilon);
  const actual = await poseidonCommitment({ roleTag: DST_ENROLL, values: input.enrollment,
    salt: input.rEnroll, policyDigest: input.policyDigest, contextDigest: 0, dimension: 128 });
  assert.equal(actual.toString(), input.cEnroll);
  if (squaredDistance(input.enrollment, input.probe) > BigInt(policyEpsilon)) return null;
  const full = {...statement, cEnroll: input.cEnroll, epsilon: policyEpsilon};
  return [full, ethers.utils.joinSignature(signer._signingKey().signDigest(
    await gateway.attestedMatchDigest(full)))];
}

async function runProfile(compiled, profile, fixture, vk) {
  const chain = ganache.provider({ chain: { chainId: 31337, hardfork: "shanghai" },
    logging: { quiet: true }, miner: { blockGasLimit: 30000000 },
    wallet: { deterministic: true, totalAccounts: 4 } });
  const provider = new ethers.providers.Web3Provider(chain);
  const [owner, device, holder, outsider] = Object.values(chain.getInitialAccounts())
    .map(({secretKey}) => new ethers.Wallet(secretKey, provider));
  async function deploy(path, name, ...args) {
    const c = compiled.contracts[path][name];
    const instance = await new ethers.ContractFactory(c.abi, `0x${c.evm.bytecode.object}`, owner).deploy(...args);
    await instance.deployTransaction.wait();
    return instance;
  }
  try {
    const attested = profile === "attested-bound";
    const merged = profile === "attested-merged";
    // Merged profile: inherited ZK entrypoint points at a non-contract address.
    const disabledVerifier = "0x000000000000000000000000000000000000dEaD";
    const verifier = merged ? null : attested
      ? await deploy("test/AttestedMatchVerifier.sol", "AttestedMatchVerifier", device.address)
      : await deploy("generated/Groth16Verifier128.sol", "Groth16Verifier");
    const unbound = profile === "zk-unbound-control";
    const gateway = merged
      ? await deploy("test/MergedAttestedMatchGateway.sol", "MergedAttestedMatchGateway", disabledVerifier)
      : await deploy(unbound ? "UnboundThresholdGateway.sol" : "UBCAAuthGateway.sol",
        unbound ? "UnboundThresholdGateway" : "UBCAAuthGateway", verifier.address);
    const source = await deploy("test/LocalBioZKFHEFinalizationSource.sol", "LocalBioZKFHEFinalizationSource");
    const adapter = await deploy("BioZKFHEFinalizationAdapter.sol", "BioZKFHEFinalizationAdapter", source.address);
    await confirmed(gateway.configureUniquenessAdapter(adapter.address));
    await confirmed(adapter.configureAuthorizedConsumer(gateway.address));
    await confirmed(gateway.disableLegacyReceiptPath());

    const modelHash = hash("comparison/model");
    const quantizationHash = hash("comparison/u16");
    const firmwareMeasurement = hash("comparison/software-reference-NOT-hardware");
    const { policyHash } = await registerSyntheticPolicy(gateway, {
      label: "comparison/policy/squared-distance/271/u16/128/v1",
      modelHash, quantizationHash, epsilon: fixture.epsilon,
    });
    const policyDigest = (await gateway.policyFieldDigest(policyHash)).toString();
    const cEnroll = (await poseidonCommitment({ roleTag: DST_ENROLL, policyDigest,
      contextDigest: 0, dimension: 128, salt: fixture.rEnroll, values: fixture.enrollment })).toString();
    const deviceVersionId = event(await confirmed(gateway.registerDevice(device.address,
      firmwareMeasurement, modelHash, quantizationHash, policyHash)), "DeviceRegistered", "deviceVersionId");
    const session = hash("comparison/source-session");
    await confirmed(source.recordImmutableSession(session, rememberFinalized(session, {
      operation: 1, finalized: true, uniquenessAccepted: true,
      expectedBlockCount: 4, verifiedBlockCount: 4, confirmationThreshold: 3, confirmationCount: 3,
      sourceContextHash: hash("source-context"), gallerySnapshotHash: hash("gallery"),
      queryCiphertextDigest: hash("query"), enrollmentCiphertextDigest: hash("enroll"),
      verifiedOutputCollectionDigest: hash("outputs"), modelHash, quantizationHash,
      finalizedAtBlock: await provider.getBlockNumber(),
    })));
    const receipt = await adapter.previewFinalizedUniqueEnrollment(session, finalizedRecordFor(session));
    const request = { receiptId: receipt.receiptId, lineageId: hash("comparison/lineage"), cEnroll,
      policyHash, modelHash, quantizationHash, templateVersion: 1, holder: holder.address,
      deviceVersionId, uniqueInputDigest: receipt.uniqueInputDigest,
      enrollmentContext: hash("comparison/enrollment-context") };
    const enrollSig = ethers.utils.joinSignature(device._signingKey().signDigest(await gateway.enrollmentLinkDigest(request)));
    const controls = {};
    controls.enrollmentSubstitutionRejected = await rejected(
      () => gateway.callStatic.issueFromFinalizedBioZKFHESession(session,
        finalizedRecordFor(session),
        {...request, cEnroll: (BigInt(cEnroll) + 1n).toString()}, enrollSig), gateway, "InvalidEnrollmentLink");
    assert.equal(await adapter.consumedBy(session), ethers.constants.HashZero);
    const credentialId = await gateway.callStatic.issueFromFinalizedBioZKFHESession(session, finalizedRecordFor(session), request, enrollSig);
    await confirmed(gateway.issueFromFinalizedBioZKFHESession(session, finalizedRecordFor(session), request, enrollSig));
    assert.notEqual(await adapter.consumedBy(session), ethers.constants.HashZero);

    async function captureInput(probe, counter) {
      const deadline = (await provider.getBlock("latest")).timestamp + 600;
      const action = hash(`comparison/action/${counter}`);
      const tx = await confirmed(gateway.connect(holder).issueAuthenticationChallenge(action, credentialId, deviceVersionId, deadline));
      const nonce = event(tx, "UBCAAuthChallengeIssued", "nonce");
      const ctxHash = event(tx, "UBCAAuthChallengeIssued", "ctxHash").toString();
      const registryEpochAtIssue = event(tx, "UBCAAuthChallengeIssued", "registryEpochAtIssue");
      const context = { beneficiary: holder.address, action, credentialId, deviceVersionId, registryEpochAtIssue, nonce, deadline };
      // Fixed fixture salts for reproducible synthetic evaluation only.
      const rProbe = (123000n + BigInt(counter)).toString();
      const cProbe = (await poseidonCommitment({ roleTag: DST_PROBE, policyDigest,
        contextDigest: ctxHash, dimension: 128, salt: rProbe, values: probe })).toString();
      const input = {...fixture, probe, cEnroll, cProbe, policyDigest, ctxHash, rProbe};
      const capture = { cProbe, ctxHash, credentialId, deviceVersionId, policyHash, modelHash,
        quantizationHash, firmwareMeasurement, registryEpochAtCapture: await gateway.registryEpoch(), counter, notAfter: deadline };
      const digest = await gateway.captureStatementDigest(capture);
      const signature = ethers.utils.joinSignature(device._signingKey().signDigest(digest));
      const { cProbe: _omitted, ...statement } = capture;
      return { input, context, capture, signature, digest, statement, challengeGas: tx.gasUsed.toNumber() };
    }
    const good = await captureInput(fixture.probe, 1);
    const entry = merged ? "verifyAndConsumeAttestedMatch" : "verifyAndConsumeAuthentication";
    const verify = (a) => gateway.connect(holder).callStatic[entry](...a);
    const submit = (a) => confirmed(gateway.connect(holder)[entry](...a));
    if (merged) return await runMergedProfile();
    const goodEvidence = attested
      ? await matchCertificate(verifier, device, good.input, fixture.epsilon)
      : await proofFor(good.input, `${profile}-good`, vk);
    assert.ok(goodEvidence);
    const args = [...goodEvidence, good.context, good.capture, good.signature];
    if (attested) {
      const outsideMatch = await matchCertificate(verifier, outsider, good.input, fixture.epsilon);
      controls.outsideMatcherSignerRejected = await rejected(() => verify([
        ...outsideMatch, good.context, good.capture, good.signature,
      ]), gateway, "InvalidAuthProof");
    }
    controls.outsideCaptureSignerRejected = await rejected(() => verify([
      ...goodEvidence, good.context, good.capture,
      ethers.utils.joinSignature(outsider._signingKey().signDigest(good.digest)),
    ]), gateway, "InvalidCaptureStatement");
    controls.contextTransplantRejected = await rejected(() => verify([
      ...goodEvidence, {...good.context, action: hash("other-action")}, good.capture, good.signature,
    ]), gateway, "InvalidAuthContext");
    for (const [name, revoke] of [
      ["credential", () => gateway.revokeCredential(credentialId)],
      ["device", () => gateway.revokeDevice(deviceVersionId)],
      ["policy", () => gateway.revokePolicy(policyHash)],
    ]) {
      const snapshot = await provider.send("evm_snapshot", []);
      await confirmed(revoke());
      controls[`${name}RevocationRejected`] = await rejected(() => verify(args), gateway, "InvalidAuthCredential");
      assert.notEqual(await gateway.pendingAuthContexts(good.context.nonce), ethers.constants.HashZero);
      assert.equal(await provider.send("evm_revert", [snapshot]), true);
    }
    controls.validMatchAccepted = await verify(args);
    const accepted = await confirmed(gateway.connect(holder).verifyAndConsumeAuthentication(...args));
    controls.replayRejected = await rejected(() => verify(args), gateway, "InvalidAuthContext");
    assert.equal(await gateway.pendingAuthContexts(good.context.nonce), ethers.constants.HashZero);

    const badProbe = [...fixture.probe];
    badProbe[0] = (BigInt(fixture.enrollment[0]) + 1000n).toString();
    const bad = await captureInput(badProbe, 2);
    const distance = squaredDistance(fixture.enrollment, badProbe);
    assert.ok(distance > BigInt(fixture.epsilon));
    const mismatch = { squaredDistance: distance.toString(), authorizedEpsilon: fixture.epsilon };
    if (attested) {
      mismatch.honestMatcherRefusesCertificate =
        (await matchCertificate(verifier, device, bad.input, fixture.epsilon)) === null;
      assert.equal(mismatch.honestMatcherRefusesCertificate, true);
      // Deliberately violates trusted-matcher correctness; outside honest-TEE model.
      const faulty = await matchCertificate(verifier, device, bad.input, fixture.epsilon, true);
      mismatch.matchOnlyFaultAccepted = await verify([...faulty, bad.context, bad.capture, bad.signature]);
      assert.equal(mismatch.matchOnlyFaultAccepted, true);
    } else {
      // Keep authentic capture and both commitments fixed; change only epsilon.
      const raisedInput = {...bad.input, epsilon: (distance + 16n).toString()};
      const inflated = await proofFor(raisedInput, `${profile}-raised-threshold`, vk);
      mismatch.raisedEpsilon = raisedInput.epsilon;
      mismatch.raisedThresholdProofValid = true;
      const badArgs = [...inflated, bad.context, bad.capture, bad.signature];
      if (unbound) {
        mismatch.raisedThresholdAccepted = await verify(badArgs);
        assert.equal(mismatch.raisedThresholdAccepted, true);
        await confirmed(gateway.connect(holder).verifyAndConsumeAuthentication(...badArgs));
        mismatch.invalidPolicyAcceptanceCommitted =
          (await gateway.pendingAuthContexts(bad.context.nonce)) === ethers.constants.HashZero;
        assert.equal(mismatch.invalidPolicyAcceptanceCommitted, true);
      } else {
        mismatch.raisedThresholdRejected = await rejected(() => verify(badArgs), gateway, "InvalidAuthCredential");
        mismatch.challengePreserved = (await gateway.pendingAuthContexts(bad.context.nonce)) !== ethers.constants.HashZero;
        assert.equal(mismatch.challengePreserved, true);
        assert.equal((await gateway.lastCaptureCounters(deviceVersionId)).toNumber(), 1);
        // A proof generated for a different threshold cannot simply be relabelled.
        const relabelled = [...inflated.slice(0, 3), [...inflated[3]]];
        relabelled[3][4] = fixture.epsilon;
        mismatch.relabelledProofRejected = await rejected(() => verify([
          ...relabelled, bad.context, bad.capture, bad.signature,
        ]), gateway, "InvalidAuthProof");
      }
    }
    return { profile, controls, mismatch, challengeGas: good.challengeGas, authenticationGas: accepted.gasUsed.toNumber() };

    async function runMergedProfile() {
      const [statement, signature] = await mergedAttestation(gateway, device, good.input,
        fixture.epsilon, good.statement);
      const args = [good.context, statement, signature];
      controls.outsideCaptureSignerRejected = await rejected(async () => verify([good.context, statement,
        ethers.utils.joinSignature(outsider._signingKey().signDigest(
          await gateway.attestedMatchDigest(statement)))]), gateway, "InvalidCaptureStatement");
      // Domain separation: an authentic capture-only signature is not a match attestation.
      controls.captureOnlySignatureRejected = await rejected(() => verify([good.context, statement,
        good.signature]), gateway, "InvalidCaptureStatement");
      controls.contextTransplantRejected = await rejected(() => verify([
        {...good.context, action: hash("other-action")}, statement, signature,
      ]), gateway, "InvalidAuthContext");
      for (const [name, revoke] of [
        ["credential", () => gateway.revokeCredential(credentialId)],
        ["device", () => gateway.revokeDevice(deviceVersionId)],
        ["policy", () => gateway.revokePolicy(policyHash)],
      ]) {
        const snapshot = await provider.send("evm_snapshot", []);
        await confirmed(revoke());
        controls[`${name}RevocationRejected`] = await rejected(() => verify(args), gateway, "InvalidAuthCredential");
        assert.notEqual(await gateway.pendingAuthContexts(good.context.nonce), ethers.constants.HashZero);
        assert.equal(await provider.send("evm_revert", [snapshot]), true);
      }
      controls.validMatchAccepted = await verify(args);
      const accepted = await submit(args);
      controls.replayRejected = await rejected(() => verify(args), gateway, "InvalidAuthContext");
      assert.equal(await gateway.pendingAuthContexts(good.context.nonce), ethers.constants.HashZero);

      const badProbe = [...fixture.probe];
      badProbe[0] = (BigInt(fixture.enrollment[0]) + 1000n).toString();
      const bad = await captureInput(badProbe, 2);
      const distance = squaredDistance(fixture.enrollment, badProbe);
      assert.ok(distance > BigInt(fixture.epsilon));
      const mismatch = { squaredDistance: distance.toString(), authorizedEpsilon: fixture.epsilon };
      mismatch.honestCaptureTcbRefusesAttestation =
        (await mergedAttestation(gateway, device, bad.input, fixture.epsilon, bad.statement)) === null;
      assert.equal(mismatch.honestCaptureTcbRefusesAttestation, true);
      // Gateway-side epsilon binding: an authentic-key statement carrying an
      // inflated threshold is rejected (signing it already violates the TCB model).
      const raised = {...bad.statement, cEnroll: good.input.cEnroll, epsilon: (distance + 16n).toString()};
      mismatch.raisedEpsilon = raised.epsilon;
      const raisedSig = ethers.utils.joinSignature(device._signingKey().signDigest(
        await gateway.attestedMatchDigest(raised)));
      mismatch.raisedThresholdRejected = await rejected(() => verify([bad.context, raised, raisedSig]),
        gateway, "InvalidAuthCredential");
      mismatch.challengePreserved = (await gateway.pendingAuthContexts(bad.context.nonce)) !== ethers.constants.HashZero;
      assert.equal(mismatch.challengePreserved, true);
      assert.equal((await gateway.lastCaptureCounters(deviceVersionId)).toNumber(), 1);
      mismatch.matcherOnlyFault = "not applicable: matcher shares the capture TCB and key";
      return { profile, controls, mismatch, challengeGas: good.challengeGas, authenticationGas: accepted.gasUsed.toNumber(),
        publishesCProbe: false };
    }
  } finally { await chain.disconnect(); }
}

async function main() {
  await mkdir(out, {recursive: true});
  const compiled = await compile();
  const fixture = JSON.parse(await readFile(resolve(root, "inputs/generated/auth_distance_128.json")));
  const vk = JSON.parse(await readFile(resolve(root, "build/proving/auth_distance_128/verification_key.json")));
  const profiles = [];
  for (const profile of ["zk-unbound-control", "zk-bound", "attested-bound", "attested-merged"]) {
    console.log(`Running ${profile}`);
    profiles.push(await runProfile(compiled, profile, fixture, vk));
    console.log(json(profiles.at(-1)));
  }
  const result = { generatedAt: new Date().toISOString(), compiler: solc.version(), node: process.version,
    scope: "local synthetic comparison; software capture/matcher; fixture upstream; benchmark-only proving key",
    sourceSha256: compiled.sourceSha256, profiles,
    limits: ["No real TEE, sensor, or BioZKFHE upstream run",
      "Matcher-only fault is outside the honest trusted-matcher model; not a full TEE-compromise claim",
      "attested-bound keeps two signatures and a padded verifier ABI; attested-merged (B1') uses one capture-TCB signature and omits C_probe; neither is a proven gas lower bound",
      "Unbound variant is a documented guard ablation, not a proposed baseline",
      "No empirical novelty claim or named-system vulnerability follows"] };
  await writeFile(resolve(out, "result.json"), json(result));
  await writeFile(resolve(out, "REPORT.md"), `# Strong attested-match comparison\n\nGenerated: ${result.generatedAt}\n\n` +
    `Both bound profiles use the same gateway, enrollment linkage, terminal adapter, capture signature, live-state checks, and freshness transition. Only the matching evidence backend differs.\n\n` +
    `| Profile | Valid match | Enrollment substitution rejected | Revoke/replay controls | Auth gas |\n|---|---|---|---|---:|\n` +
    profiles.map((p) => `| ${p.profile} | ${p.controls.validMatchAccepted} | ${p.controls.enrollmentSubstitutionRejected} | ${p.controls.credentialRevocationRejected && p.controls.deviceRevocationRejected && p.controls.policyRevocationRejected && p.controls.replayRejected} | ${p.authenticationGas} |`).join("\n") +
    `\n\nHonest attested matching refuses the non-match. The unbound-threshold control accepts a real proof for an inflated epsilon. The bound ZK gateway rejects that proof and its relabelled variant. A matcher-only false-positive fault produces an accepted attestation; this violates the baseline's trusted-matching premise and is not a fair attack under the original model.\n\n` +
    result.limits.map((s) => `- ${s}`).join("\n") + "\n");
}

main().catch((e) => { console.error(e); process.exitCode = 1; })
  .finally(async () => { if (globalThis.curve_bn128?.terminate) await globalThis.curve_bn128.terminate(); });
