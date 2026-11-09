// Complete-verifier gas for the homomorphic strategies (FullCheck / SpotCheck) on BN254.
// Unlike pedersen-gas-benchmark.mjs (kernel only), the measured transaction includes nonce
// state, the enrollment digest check, the Fiat-Shamir challenge over all commitments and
// first messages, sample derivation from block randomness, the per-coordinate equations,
// the distance reconstruction, and a Groth16 threshold verifier with five public inputs.
// Usage (from prototype/): .toolchain/node-v24.19.0-win-x64/node.exe scripts/hom-complete-gas.mjs
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { buildBn128 } from "ffjavascript";
import ganache from "ganache";
import solc from "solc";
import { ethers } from "ethers";
import * as snarkjs from "snarkjs";
import { sampleCount } from "./lib/sampling.mjs";

const root = resolve(import.meta.dirname, "..");
const out = resolve(root, "build", "hom-complete-gas");
const N = 128;
const TAU = 1_000_000n;
const H_DLOG = 5n;
const REPS = 3;
const wasm = resolve(out, "threshold_standin_js", "threshold_standin.wasm");
const zkey = resolve(out, "ts_final.zkey");

const mod = (a, m) => ((a % m) + m) % m;
const median = (v) => [...v].sort((a, b) => a - b)[Math.floor(v.length / 2)];
let counter = 0n;
function rand(bound) {
  // deterministic, reproducible pseudo-randomness for the synthetic transcript
  counter += 1n;
  const h = createHash("sha256").update(`biozero-hom-complete/${counter}`).digest("hex");
  return mod(BigInt(`0x${h}`), bound);
}

function calldataCost(hex) {
  const bytes = ethers.utils.arrayify(hex);
  let zero = 0;
  for (const b of bytes) if (b === 0) zero += 1;
  return { bytes: bytes.length, zeroBytes: zero, nonzeroBytes: bytes.length - zero, gas: zero * 4 + (bytes.length - zero) * 16 };
}

async function compile() {
  const files = ["HomomorphicCompleteVerifier.sol", "generated/Groth16VerifierThreshold.sol"];
  const sources = {};
  for (const f of files) sources[f] = { content: await readFile(resolve(root, "contracts", f), "utf8") };
  const input = {
    language: "Solidity",
    sources,
    settings: {
      optimizer: { enabled: true, runs: 200 },
      evmVersion: "shanghai",
      outputSelection: { "*": { "*": ["abi", "evm.bytecode.object", "evm.deployedBytecode.object"] } },
    },
  };
  const output = JSON.parse(solc.compile(JSON.stringify(input)));
  const errors = (output.errors ?? []).filter((e) => e.severity === "error");
  if (errors.length) throw new Error(errors.map((e) => e.formattedMessage).join("\n"));
  return {
    verifier: output.contracts["HomomorphicCompleteVerifier.sol"].HomomorphicCompleteVerifier,
    groth16: output.contracts["generated/Groth16VerifierThreshold.sol"].Groth16Verifier,
  };
}

const curve = await buildBn128();
const r = curve.r;
const point = (s) => {
  const sc = mod(s, r);
  if (sc === 0n) return { x: "0", y: "0" };
  const [x, y] = curve.G1.toObject(curve.G1.toAffine(curve.G1.timesScalar(curve.G1.one, sc)));
  return { x: x.toString(), y: y.toString() };
};
const com = (m, rho) => mod(m + H_DLOG * rho, r);

// Enrollment secrets for one identity.
const me = Array.from({ length: N }, () => rand(1n << 16n));
const rhoE = Array.from({ length: N }, () => rand(r));
const ceScalars = me.map((m, i) => com(m, rhoE[i]));
const ce = ceScalars.map(point);

const pointArray = "tuple(uint256 x,uint256 y)[]";
function challenge(ctxHash, id, nonce, t) {
  const pts = (a) => a.map((p) => [p.x, p.y]);
  const h1 = ethers.utils.keccak256(
    ethers.utils.defaultAbiCoder.encode(
      ["bytes32", "uint256", "uint256", pointArray, pointArray, pointArray],
      [ctxHash, id, nonce, pts(t.ce), pts(t.cp), pts(t.cee)],
    ),
  );
  const enc = ethers.utils.defaultAbiCoder.encode(
    ["bytes32", pointArray, pointArray, pointArray, pointArray],
    [h1, pts(t.cpp), pts(t.cep), pts(t.alpha), pts(t.beta)],
  );
  return mod(BigInt(ethers.utils.keccak256(enc)), r);
}

async function prove(ctxHash, id, nonce) {
  // Fresh probe close to the enrolled template.
  const mp = me.map((m) => {
    const v = m + rand(101n) - 50n;
    return v < 0n ? 0n : v >= 1n << 16n ? (1n << 16n) - 1n : v;
  });
  const rhoP = mp.map(() => rand(r));
  const rhoEE = mp.map(() => rand(r));
  const rhoPP = mp.map(() => rand(r));
  const rhoEP = mp.map(() => rand(r));
  const cpS = mp.map((m, i) => com(m, rhoP[i]));
  const ceeS = me.map((m, i) => com(m * m, rhoEE[i]));
  const cppS = mp.map((m, i) => com(m * m, rhoPP[i]));
  const cepS = me.map((m, i) => com(m * mp[i], rhoEP[i]));

  // relation l: [anchor value, anchor blind, base commitment scalar, base blind, target blind]
  const rel = (i) => [
    [me[i], rhoE[i], ceScalars[i], rhoE[i], rhoEE[i]],
    [mp[i], rhoP[i], cpS[i], rhoP[i], rhoPP[i]],
    [mp[i], rhoP[i], ceScalars[i], rhoE[i], rhoEP[i]],
  ];
  const masks = [];
  const alpha = [];
  const beta = [];
  for (let i = 0; i < N; i += 1) {
    for (const [, , baseS] of rel(i)) {
      const b = [rand(r), rand(r), rand(r)];
      masks.push(b);
      alpha.push(point(com(b[0], b[1])));
      beta.push(point(mod(b[0] * baseS + H_DLOG * b[2], r)));
    }
  }
  const t = {
    ce,
    cp: cpS.map(point),
    cee: ceeS.map(point),
    cpp: cppS.map(point),
    cep: cepS.map(point),
    alpha,
    beta,
  };
  const eps = challenge(ctxHash, id, nonce, t);
  const z = [];
  for (let i = 0; i < N; i += 1) {
    rel(i).forEach(([ma, ra, , rb, rt], l) => {
      const [b1, b2, b3] = masks[3 * i + l];
      z.push(mod(b1 + eps * ma, r), mod(b2 + eps * ra, r), mod(b3 + eps * (rt - rb * ma), r));
    });
  }

  let dScalar = 0n;
  let delta = 0n;
  for (let i = 0; i < N; i += 1) {
    dScalar = mod(dScalar + ceeS[i] + cppS[i] - 2n * cepS[i], r);
    delta += (me[i] - mp[i]) ** 2n;
  }
  const d = point(dScalar);
  const lo = (v) => (BigInt(v) & ((1n << 128n) - 1n)).toString();
  const hi = (v) => (BigInt(v) >> 128n).toString();
  const { proof } = await snarkjs.groth16.fullProve(
    { cxHi: hi(d.x), cxLo: lo(d.x), cyHi: hi(d.y), cyLo: lo(d.y), tau: TAU.toString(), delta: delta.toString() },
    wasm,
    zkey,
  );
  return {
    ...t,
    z: z.map(String),
    pA: [proof.pi_a[0], proof.pi_a[1]],
    pB: [
      [proof.pi_b[0][1], proof.pi_b[0][0]],
      [proof.pi_b[1][1], proof.pi_b[1][0]],
    ],
    pC: [proof.pi_c[0], proof.pi_c[1]],
    delta: delta.toString(),
  };
}

const compiled = await compile();
let eip1193;
try {
  eip1193 = ganache.provider({
    chain: { chainId: 31337, hardfork: "shanghai" },
    miner: { blockGasLimit: 80_000_000 },
    logging: { quiet: true },
    wallet: { deterministic: true, totalAccounts: 2 },
  });
  const provider = new ethers.providers.Web3Provider(eip1193);
  const signer = provider.getSigner(0);
  const g16 = await new ethers.ContractFactory(compiled.groth16.abi, `0x${compiled.groth16.evm.bytecode.object}`, signer).deploy();
  await g16.deployTransaction.wait();
  const factory = new ethers.ContractFactory(compiled.verifier.abi, `0x${compiled.verifier.evm.bytecode.object}`, signer);

  const cases = [1, 2, 4, 8].map((eta) => ({ label: `spot-eta-${eta}`, eta, samples: sampleCount(N, eta) }));
  cases.push({ label: "full-check", eta: null, samples: N });
  const results = [];
  for (const c of cases) {
    const v = await factory.deploy(N, c.samples, TAU, g16.address);
    const deploy = await v.deployTransaction.wait();
    const ctxHash = await v.ctxHash();
    const id = 1;
    const enrollReq = await v.populateTransaction.enroll(id, ce);
    const enrollRcpt = await (await signer.sendTransaction({ ...enrollReq, gasLimit: 79_000_000 })).wait();

    const gasUsed = [];
    let calldata;
    let lastTranscript;
    for (let run = 1; run <= REPS; run += 1) {
      const tr = await prove(ctxHash, id, run);
      const req = await v.populateTransaction.authenticate(id, run, tr);
      calldata = calldataCost(req.data);
      const rcpt = await (await signer.sendTransaction({ ...req, gasLimit: 79_000_000 })).wait();
      if (rcpt.status !== 1) throw new Error(`${c.label} run ${run} failed`);
      gasUsed.push(rcpt.gasUsed.toNumber());
      lastTranscript = tr;
    }

    // Negative controls (static calls, nothing is mined).
    const rejects = async (fn) => {
      try {
        await fn();
        return false;
      } catch {
        return true;
      }
    };
    const replayRejected = await rejects(() => v.callStatic.authenticate(id, REPS, lastTranscript));
    const staleProofRejected = await rejects(async () => {
      const fresh = await prove(ctxHash, id, REPS + 1);
      return v.callStatic.authenticate(id, REPS + 1, { ...fresh, pA: lastTranscript.pA, pB: lastTranscript.pB, pC: lastTranscript.pC });
    });
    const wrongEnrollmentRejected = await rejects(async () => {
      const fresh = await prove(ctxHash, id, REPS + 1);
      const ce2 = [...fresh.ce];
      ce2[0] = fresh.cp[0];
      return v.callStatic.authenticate(id, REPS + 1, { ...fresh, ce: ce2 });
    });
    let tamperedResponseRejected = null;
    if (c.samples === N) {
      tamperedResponseRejected = await rejects(async () => {
        const fresh = await prove(ctxHash, id, REPS + 1);
        const z2 = [...fresh.z];
        z2[9 * (N - 1)] = mod(BigInt(z2[9 * (N - 1)]) + 1n, r).toString();
        return v.callStatic.authenticate(id, REPS + 1, { ...fresh, z: z2 });
      });
    }
    const intrinsic = 21_000 + calldata.gas;
    const res = {
      ...c,
      repetitions: REPS,
      gasUsed,
      medianGasUsed: median(gasUsed),
      calldata,
      intrinsicGas: intrinsic,
      medianExecutionGasAfterIntrinsic: median(gasUsed) - intrinsic,
      enrollmentGas: enrollRcpt.gasUsed.toNumber(),
      deploymentGas: deploy.gasUsed.toNumber(),
      controls: { replayRejected, staleProofRejected, wrongEnrollmentRejected, tamperedResponseRejected },
    };
    if (!replayRejected || !staleProofRejected || !wrongEnrollmentRejected || tamperedResponseRejected === false)
      throw new Error(`${c.label}: a negative control was accepted`);
    results.push(res);
    process.stdout.write(`${c.label}: t=${c.samples} gas=${res.medianGasUsed} calldata=${calldata.bytes}B enroll=${res.enrollmentGas}\n`);
  }

  const record = {
    generatedAt: new Date().toISOString(),
    scope:
      "Complete authentication transaction for the homomorphic strategies at N=128 on BN254: nonce check and update, enrollment-digest check, Fiat-Shamir challenge over all commitments and first messages, sample derivation from block.prevrandao, six equations per examined coordinate, full distance reconstruction, and a Groth16 threshold verifier with five public inputs (the reconstructed commitment as four 128-bit limbs and the threshold). The prover sends the full transcript because the sample is fixed only at inclusion.",
    securityWarning:
      "h = 5G has a known discrete log (insecure commitment key, same EVM cost). The threshold circuit is a measurement stand-in that range-checks delta <= tau but does not prove the Pedersen opening of the reconstructed commitment; Groth16 verification gas depends only on the number of public inputs. Local single-party Groth16 setup, benchmark only.",
    dimension: N,
    threshold: TAU.toString(),
    compiler: solc.version(),
    optimizerRuns: 200,
    evmVersion: "shanghai",
    chain: "Ganache 7.9.2, chain id 31337, block gas limit 80,000,000",
    groth16VerifierDeploymentGas: (await g16.deployTransaction.wait()).gasUsed.toNumber(),
    results,
  };
  await mkdir(out, { recursive: true });
  await writeFile(resolve(out, "results.json"), `${JSON.stringify(record, null, 2)}\n`, "utf8");
} finally {
  if (eip1193) await eip1193.disconnect();
  await curve.terminate();
  if (globalThis.curve_bn128) await globalThis.curve_bn128.terminate();
}
process.exit(0);
