import test from "node:test";
import assert from "node:assert/strict";
import {
  DST_ENROLL,
  DST_PROBE,
  packCoordinates,
  poseidonCommitment,
  squaredDistance,
} from "../scripts/commitment.mjs";

const base = {
  policyDigest: 99n,
  contextDigest: 123n,
  dimension: 4,
  salt: 456n,
  values: [10n, 20n, 30n, 40n],
};

test("packing is deterministic and stays below 2^240", () => {
  const packed = packCoordinates(base.values);
  assert.equal(packed.length, 2);
  assert.ok(packed[0] < (1n << 240n));
  assert.equal(packed[1], 0n);
});

test("commitment is deterministic for an identical opening", async () => {
  const first = await poseidonCommitment({ ...base, roleTag: DST_PROBE });
  const second = await poseidonCommitment({ ...base, roleTag: DST_PROBE });
  assert.equal(first, second);
});

test("role, policy, context, salt and coordinates are bound", async () => {
  const original = await poseidonCommitment({ ...base, roleTag: DST_PROBE });
  const variants = [
    { ...base, roleTag: DST_ENROLL },
    { ...base, roleTag: DST_PROBE, policyDigest: base.policyDigest + 1n },
    { ...base, roleTag: DST_PROBE, contextDigest: base.contextDigest + 1n },
    { ...base, roleTag: DST_PROBE, salt: base.salt + 1n },
    {
      ...base,
      roleTag: DST_PROBE,
      values: [base.values[0] + 1n, ...base.values.slice(1)],
    },
  ];

  for (const variant of variants) {
    assert.notEqual(await poseidonCommitment(variant), original);
  }
});

test("coordinate range and dimension mismatches are rejected", async () => {
  assert.throws(() => packCoordinates([65536n]), /outside 16-bit range/);
  await assert.rejects(
    poseidonCommitment({ ...base, roleTag: DST_PROBE, dimension: 3 }),
    /dimension does not match/,
  );
});

test("offset encoding preserves squared distance", () => {
  const signedLeft = [-5n, 0n, 7n];
  const signedRight = [-2n, -1n, 3n];
  const offset = 128n;
  assert.equal(
    squaredDistance(signedLeft, signedRight),
    squaredDistance(
      signedLeft.map((value) => value + offset),
      signedRight.map((value) => value + offset),
    ),
  );
});

