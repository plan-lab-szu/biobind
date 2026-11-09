export function sampleCount(dimension, lambda) {
  if (!Number.isInteger(dimension) || dimension <= 0) {
    throw new RangeError("dimension must be a positive integer");
  }
  if (!Number.isFinite(lambda) || lambda <= 0) {
    throw new RangeError("lambda must be positive");
  }
  return Math.min(dimension, Math.ceil(lambda * Math.log2(dimension)));
}

export function missProbability(dimension, badCoordinates, samples) {
  if (!Number.isInteger(dimension) || dimension <= 0) {
    throw new RangeError("dimension must be a positive integer");
  }
  if (
    !Number.isInteger(badCoordinates) ||
    badCoordinates < 0 ||
    badCoordinates > dimension
  ) {
    throw new RangeError("badCoordinates must be an integer in [0, dimension]");
  }
  if (!Number.isInteger(samples) || samples < 0 || samples > dimension) {
    throw new RangeError("samples must be an integer in [0, dimension]");
  }

  if (badCoordinates === 0 || samples === 0) return 1;
  if (samples > dimension - badCoordinates) return 0;

  let probability = 1;
  for (let index = 0; index < samples; index += 1) {
    probability *=
      (dimension - badCoordinates - index) / (dimension - index);
  }
  return probability;
}

export function detectionProbability(dimension, badCoordinates, samples) {
  return 1 - missProbability(dimension, badCoordinates, samples);
}

export function minimumSamplesForDetection(
  dimension,
  badCoordinates,
  targetDetection,
) {
  if (!(targetDetection > 0 && targetDetection <= 1)) {
    throw new RangeError("targetDetection must be in (0, 1]");
  }
  for (let samples = 1; samples <= dimension; samples += 1) {
    if (
      detectionProbability(dimension, badCoordinates, samples) +
        Number.EPSILON >=
      targetDetection
    ) {
      return samples;
    }
  }
  return dimension;
}
