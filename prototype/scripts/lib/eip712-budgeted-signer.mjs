import { createHash } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { ethers } from "ethers";

export class BudgetSignerError extends Error {}

const SCOPE_DOMAIN = Buffer.from("BioZERO/budget-scope/v1\0", "ascii");
const CAPTURE_FIELDS = [
  "cProbe", "ctxHash", "credentialId", "deviceVersionId", "policyHash",
  "modelHash", "quantizationHash", "firmwareMeasurement",
  "registryEpochAtCapture", "counter", "notAfter",
];
const CAPTURE_TYPES = { UBCACapture: [
  { name: "cProbe", type: "uint256" },
  { name: "ctxHash", type: "uint256" },
  { name: "credentialId", type: "bytes32" },
  { name: "deviceVersionId", type: "bytes32" },
  { name: "policyHash", type: "bytes32" },
  { name: "modelHash", type: "bytes32" },
  { name: "quantizationHash", type: "bytes32" },
  { name: "firmwareMeasurement", type: "bytes32" },
  { name: "registryEpochAtCapture", type: "uint64" },
  { name: "counter", type: "uint64" },
  { name: "notAfter", type: "uint64" },
] };

function fixedHex(value, length, name) {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]+$/.test(value) ||
      value.length !== 2 + length * 2) {
    throw new TypeError(`${name} must be ${length} hex bytes`);
  }
  return Buffer.from(value.slice(2), "hex");
}

export function budgetScopeId(scope) {
  const fields = [
    fixedHex(scope.applicationId, 32, "applicationId"),
    fixedHex(scope.holder, 20, "holder"),
    fixedHex(scope.credentialId, 32, "credentialId"),
    fixedHex(scope.deviceVersionId, 32, "deviceVersionId"),
    fixedHex(scope.policyHash, 32, "policyHash"),
    fixedHex(scope.budgetPolicyHash, 32, "budgetPolicyHash"),
    fixedHex(scope.windowId, 32, "windowId"),
  ];
  return createHash("sha256").update(SCOPE_DOMAIN)
    .update(Buffer.concat(fields)).digest("hex");
}

function canonicalCapture(capture) {
  return Object.fromEntries(CAPTURE_FIELDS.map((field) => {
    if (capture[field] === undefined || capture[field] === null) {
      throw new TypeError(`capture.${field} missing`);
    }
    return [field, String(capture[field])];
  }));
}

export class Eip712BudgetedSigner {
  constructor({ database, scope, wallet, chainId, gatewayAddress }) {
    if (!(wallet instanceof ethers.Wallet)) throw new TypeError("ethers Wallet required");
    if (!Number.isSafeInteger(chainId) || chainId < 1) {
      throw new TypeError("positive chainId required");
    }
    this.scope = { ...scope };
    this.scopeId = budgetScopeId(scope);
    this.wallet = wallet;
    this.domain = { name: "UBCA Capture", version: "1", chainId,
      verifyingContract: ethers.utils.getAddress(gatewayAddress) };
    this.db = new DatabaseSync(database);
    this.liveReservations = new Set();
    this.db.exec("PRAGMA foreign_keys=ON; PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL");
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS scopes (
        scope_id TEXT PRIMARY KEY, max_exposures INTEGER NOT NULL,
        used INTEGER NOT NULL DEFAULT 0, active INTEGER NOT NULL DEFAULT 1
      );
      CREATE TABLE IF NOT EXISTS attempts (
        attempt_id TEXT PRIMARY KEY, scope_id TEXT NOT NULL REFERENCES scopes(scope_id),
        state TEXT NOT NULL CHECK(state IN ('reserved','committed')),
        transcript BLOB
      );
    `);
  }

  provision(maxExposures) {
    if (!Number.isSafeInteger(maxExposures) || maxExposures < 1) {
      throw new TypeError("positive safe integer budget required");
    }
    try {
      this.db.prepare("INSERT INTO scopes(scope_id,max_exposures) VALUES (?,?)")
        .run(this.scopeId, maxExposures);
    } catch (error) {
      throw new BudgetSignerError(`scope already provisioned: ${error.message}`);
    }
  }

  _transaction(work) {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const result = work();
      this.db.exec("COMMIT");
      return result;
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  _reserve(attemptId) {
    this._transaction(() => {
      const scope = this.db.prepare(
        "SELECT max_exposures,used,active FROM scopes WHERE scope_id=?"
      ).get(this.scopeId);
      if (!scope || scope.active !== 1) throw new BudgetSignerError("inactive scope");
      if (scope.used >= scope.max_exposures) throw new BudgetSignerError("budget exhausted");
      try {
        this.db.prepare(
          "INSERT INTO attempts(attempt_id,scope_id,state) VALUES (?,?,'reserved')"
        ).run(attemptId, this.scopeId);
      } catch (error) {
        throw new BudgetSignerError(`attempt already used: ${error.message}`);
      }
      this.db.prepare("UPDATE scopes SET used=used+1 WHERE scope_id=?").run(this.scopeId);
    });
    this.liveReservations.add(attemptId);
  }

  captureDigest(capture) {
    return ethers.utils._TypedDataEncoder.hash(
      this.domain, CAPTURE_TYPES, canonicalCapture(capture));
  }

  async signCapture({ attemptId, capture }) {
    const attempt = fixedHex(attemptId, 32, "attemptId").toString("hex");
    const statement = canonicalCapture(capture);
    for (const field of ["credentialId", "deviceVersionId", "policyHash"]) {
      if (statement[field].toLowerCase() !== this.scope[field].toLowerCase()) {
        throw new BudgetSignerError(`capture ${field} outside provisioned scope`);
      }
    }
    // This is a signature budget. The host supplies cProbe, so it does not
    // enforce pre-sensor exposure accounting or genuine vector provenance.
    this._reserve(attempt);
    const digest = this.captureDigest(statement);
    const signature = ethers.utils.joinSignature(
      this.wallet._signingKey().signDigest(digest)
    );
    const transcript = Buffer.from(JSON.stringify({
      scopeId: this.scopeId, attemptId: attempt, capture: statement, signature,
    }), "utf8");
    this._transaction(() => {
      if (!this.liveReservations.has(attempt)) {
        throw new BudgetSignerError("reservation belongs to an earlier process");
      }
      const row = this.db.prepare(`
        SELECT attempts.state,scopes.active FROM attempts
        JOIN scopes USING(scope_id) WHERE attempt_id=? AND scope_id=?
      `).get(attempt, this.scopeId);
      if (!row || row.state !== "reserved" || row.active !== 1) {
        throw new BudgetSignerError("reservation invalidated");
      }
      this.db.prepare(
        "UPDATE attempts SET state='committed',transcript=? WHERE attempt_id=?"
      ).run(transcript, attempt);
    });
    this.liveReservations.delete(attempt);
    return { ...JSON.parse(transcript.toString("utf8")), bytes: transcript };
  }

  retransmit(attemptId) {
    const attempt = fixedHex(attemptId, 32, "attemptId").toString("hex");
    const row = this.db.prepare(`
      SELECT attempts.state,attempts.transcript,scopes.active FROM attempts
      JOIN scopes USING(scope_id) WHERE attempt_id=? AND scope_id=?
    `).get(attempt, this.scopeId);
    if (!row || row.state !== "committed" || row.active !== 1) {
      throw new BudgetSignerError("no active committed transcript");
    }
    const bytes = Buffer.from(row.transcript);
    const record = JSON.parse(bytes.toString("utf8"));
    const digest = this.captureDigest(record.capture);
    if (record.scopeId !== this.scopeId || record.attemptId !== attempt ||
        ethers.utils.recoverAddress(digest, record.signature) !== this.wallet.address) {
      throw new BudgetSignerError("stored transcript failed verification");
    }
    return { ...record, bytes };
  }

  revoke() {
    this._transaction(() => {
      const changed = this.db.prepare(
        "UPDATE scopes SET active=0 WHERE scope_id=? AND active=1"
      ).run(this.scopeId).changes;
      if (changed !== 1) throw new BudgetSignerError("scope inactive or absent");
    });
  }

  usage() {
    const row = this.db.prepare(
      "SELECT used,max_exposures,active FROM scopes WHERE scope_id=?"
    ).get(this.scopeId);
    if (!row) throw new BudgetSignerError("unknown scope");
    return { used: row.used, maxExposures: row.max_exposures, active: row.active === 1 };
  }

  close() { this.db.close(); }
}
