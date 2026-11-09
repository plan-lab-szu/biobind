import test from "node:test";
import assert from "node:assert/strict";
import {
  detectionProbability,
  minimumSamplesForDetection,
  missProbability,
  sampleCount,
} from "../scripts/lib/sampling.mjs";

test("sample count follows min(N, ceil(lambda log2 N))", () => {
  assert.equal(sampleCount(128, 1), 7);
  assert.equal(sampleCount(128, 8), 56);
  assert.equal(sampleCount(8, 8), 8);
});

test("one-coordinate detection is exactly t/N", () => {
  for (const samples of [1, 7, 14, 56, 128]) {
    assert.ok(
      Math.abs(detectionProbability(128, 1, samples) - samples / 128) <
        1e-12,
    );
  }
});

test("full checking cannot miss an inconsistent coordinate", () => {
  assert.equal(missProbability(128, 1, 128), 0);
  assert.equal(detectionProbability(128, 1, 128), 1);
});

test("old table exact-formula audit is reproducible", () => {
  assert.ok(
    Math.abs(detectionProbability(128, 6, 7) - 0.2913718660364151) <
      1e-12,
  );
  assert.ok(
    Math.abs(detectionProbability(128, 6, 14) - 0.5082748357773139) <
      1e-12,
  );
  assert.ok(
    Math.abs(detectionProbability(128, 6, 28) - 0.7802105726162673) <
      1e-12,
  );
  assert.ok(
    Math.abs(detectionProbability(128, 6, 56) - 0.971192826653946) <
      1e-12,
  );
});

test("near-certain one-coordinate detection approaches FullCheck", () => {
  assert.equal(minimumSamplesForDetection(128, 1, 0.95), 122);
  assert.equal(minimumSamplesForDetection(128, 1, 0.99), 127);
  assert.equal(minimumSamplesForDetection(512, 1, 0.99), 507);
});
