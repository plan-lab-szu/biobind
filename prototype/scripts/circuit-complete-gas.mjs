// Complete-verifier gas for CircuitCheck at N in {128, 512}, with the same state handling as
// hom-complete-gas.mjs: enrollment record, nonce check and update, and chi = H(ctx||id||nonce).
// Usage (from prototype/): .toolchain/node-v24.19.0-win-x64/node.exe scripts/circuit-complete-gas.mjs
import { randomBytes } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import ganache from "ganache";
import solc from "solc";
import { ethers } from "ethers";
import { groth16, wtns } from "snarkjs";
import { DST_PROBE, poseidonCommitment } from "./commitment.mjs";

const root = resolve(import.meta.dirname, "..");
const out = resolve(root, "build", "circuit-complete-gas");
const R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const REPS = 3;
const median = (v) => [...v].sort((a, b) => a - b)[Math.floor(v.length / 2)];
const randomField = () => BigInt(`0x${randomBytes(32).toString("hex")}`) % R;
const big = (o) => JSON.stringify(o, (_, v) => (typeof v === "bigint" ? v.toString() : v), 2);

function calldataCost(hex) {
  const bytes = ethers.utils.arrayify(hex);
  let zero = 0;
  for (const b of bytes) if (b === 0) zero += 1;
  return { bytes: bytes.length, zeroBytes: zero, nonzeroBytes: bytes.length - zero, gas: zero * 4 + (bytes.length - zero) * 16 };
}

async function compile(file, name) {
  const input = {
    language: "Solidity",
    sources: { [file]: { content: await readFile(resolve(root, "contracts", file), "utf8") } },
    settings: {
      optimizer: { enabled: true, runs: 200 },
      evmVersion: "shanghai",
      outputSelection: { "*": { "*": ["abi", "evm.bytecode.object"] } },
    },
  };
  const output = JSON.parse(solc.compile(JSON.stringify(input)));
  const errors = (output.errors ?? []).filter((e) => e.severity === "error");
  if (errors.length) throw new Error(errors.map((e) => e.formattedMessage).join("\n"));
  return output.contracts[file][name];
}

const gateway = await compile("CircuitCompleteVerifier.sol", "CircuitCompleteVerifier");
const results = [];
for (const N of [128, 512]) {
  const g16 = await compile(`generated/Groth16Verifier${N}.sol`, "Groth16Verifier");
  const base = JSON.parse(await readFile(resolve(root, "inputs", "generated", `auth_distance_${N}.json`), "utf8"));
  const wasm = resolve(root, "build", `auth_distance_${N}`, `auth_distance_${N}_js`, `auth_distance_${N}.wasm`);
  const zkey = resolve(root, "build", "proving", `auth_distance_${N}`, `auth_distance_${N}_benchmark_final.zkey`);
  const eip1193 = ganache.provider({
    chain: { chainId: 31337, hardfork: "shanghai" },
    miner: { blockGasLimit: 30_000_000 },
    logging: { quiet: true },
    wallet: { deterministic: true, totalAccounts: 2 },
  });
  try {
    const provider = new ethers.providers.Web3Provider(eip1193);
    const signer = provider.getSigner(0);
    const v = await new ethers.ContractFactory(g16.abi, `0x${g16.evm.bytecode.object}`, signer).deploy();
    await v.deployTransaction.wait();
    const c = await new ethers.ContractFactory(gateway.abi, `0x${gateway.evm.bytecode.object}`, signer).deploy(
      base.epsilon,
      base.policyDigest,
      N,
      v.address,
    );
    const deploy = await c.deployTransaction.wait();
    const id = 1;
    const enroll = await (await c.enroll(id, base.cEnroll)).wait();

    async function prove(nonce) {
      const chi = (await c.digestOf(id, nonce)).toString();
      const rProbe = randomField();
      const cProbe = await poseidonCommitment({
        roleTag: DST_PROBE,
        policyDigest: BigInt(base.policyDigest),
        contextDigest: BigInt(chi),
        dimension: N,
        salt: rProbe,
        values: base.probe.map(BigInt),
        packSize: 15,
      });
      await mkdir(out, { recursive: true });
      const wtnsPath = resolve(out, `w${N}.wtns`);
      await wtns.calculate({ ...base, cProbe, ctxHash: chi, rProbe }, wasm, wtnsPath, {});
      const { proof, publicSignals } = await groth16.prove(zkey, wtnsPath);
      const [pA, pB, pC] = JSON.parse(`[${await groth16.exportSolidityCallData(proof, publicSignals)}]`);
      return { gammaP: cProbe.toString(), pA, pB, pC };
    }

    const gasUsed = [];
    let calldata;
    let last;
    for (let nonce = 1; nonce <= REPS; nonce += 1) {
      const p = await prove(nonce);
      const req = await c.populateTransaction.authenticate(id, nonce, p.gammaP, p.pA, p.pB, p.pC);
      calldata = calldataCost(req.data);
      const rcpt = await (await signer.sendTransaction({ ...req, gasLimit: 29_000_000 })).wait();
      if (rcpt.status !== 1) throw new Error(`N=${N} nonce ${nonce} failed`);
      gasUsed.push(rcpt.gasUsed.toNumber());
      last = p;
    }
    const rejects = async (fn) => {
      try {
        await fn();
        return false;
      } catch {
        return true;
      }
    };
    const replayRejected = await rejects(() => c.callStatic.authenticate(id, REPS, last.gammaP, last.pA, last.pB, last.pC));
    const wrongNonceProofRejected = await rejects(() =>
      c.callStatic.authenticate(id, REPS + 1, last.gammaP, last.pA, last.pB, last.pC),
    );
    if (!replayRejected || !wrongNonceProofRejected) throw new Error(`N=${N}: negative control accepted`);
    const intrinsic = 21_000 + calldata.gas;
    results.push({
      dimension: N,
      repetitions: REPS,
      gasUsed,
      medianGasUsed: median(gasUsed),
      calldata,
      intrinsicGas: intrinsic,
      medianExecutionGasAfterIntrinsic: median(gasUsed) - intrinsic,
      enrollmentGas: enroll.gasUsed.toNumber(),
      deploymentGas: deploy.gasUsed.toNumber(),
      controls: { replayRejected, wrongNonceProofRejected },
    });
    process.stdout.write(`N=${N}: gas=${median(gasUsed)} calldata=${calldata.bytes}B enroll=${enroll.gasUsed}\n`);
  } finally {
    await eip1193.disconnect();
  }
}
const record = {
  generatedAt: new Date().toISOString(),
  scope:
    "Complete CircuitCheck authentication transaction: enrollment-commitment lookup, nonce check and update, chi = keccak(ctx, id, nonce) mod r, Groth16 verification with five public inputs, event. Same state handling as hom-complete-gas.",
  securityWarning: "Groth16 keys from the local benchmark-only setup; never deploy.",
  compiler: solc.version(),
  optimizerRuns: 200,
  evmVersion: "shanghai",
  chain: "Ganache 7.9.2, chain id 31337",
  results,
};
await mkdir(out, { recursive: true });
await writeFile(resolve(out, "results.json"), `${big(record)}\n`, "utf8");
if (globalThis.curve_bn128) await globalThis.curve_bn128.terminate();
process.exit(0);
