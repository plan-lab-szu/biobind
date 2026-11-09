// Plaintext-level model of BioZKFHE SCMV semantics (BioZKFHE paper, Sec. IV).
// BGV encryption is omitted: homomorphic add/multiply are exact, so slot
// placement, multi-value binding, and similarity recovery behave identically
// on plaintext matrices. This is a semantics model, not an FHE implementation.

export const SOURCE_OP_ENROLL = 1;

/// Smallest safe SCMV base, Eq. (10): T = 2*floor(Gamma^2 + Gamma*sqrt(L) + L/4) + 1.
export function scmvBase(gamma, L) {
  return 2n * BigInt(Math.floor(gamma * gamma + gamma * Math.sqrt(L) + 0.25 * L)) + 1n;
}

/// L2-normalize to Gamma and round component-wise (Sec. IV-C.1). Rounding is
/// half away from zero, matching std::llround in BioZKFHE's
/// source/biozkFHE/scmv_e3_benchmark.cpp (random_embedding).
export function quantize(real, gamma) {
  const norm = Math.sqrt(real.reduce((s, x) => s + x * x, 0));
  return real.map((x) => {
    const y = (x / norm) * gamma;
    return Math.sign(y) * Math.round(Math.abs(y)) + 0; // +0 normalizes -0
  });
}

/// Quantized-vector validity implied by the paper's preparation step:
/// |v_i| <= Gamma and ||v||_2 within Gamma +/- 0.5*sqrt(L).
export function inQuantizationProfile(v, gamma) {
  const L = v.length;
  if (!v.every((x) => Number.isInteger(x) && Math.abs(x) <= gamma)) return false;
  const norm = Math.sqrt(v.reduce((s, x) => s + x * x, 0));
  return Math.abs(norm - gamma) <= 0.5 * Math.sqrt(L);
}

export function slotFor(N, { n, d }) {
  const a = N % (n * d);
  return { a, h: a % d, k: Math.floor(a / d) }; // 0-indexed column and layer
}

const zeros = (L, d) => Array.from({ length: L }, () => Array(d).fill(0n));

/// SCMV.Prepare(v): V_identify replicates v across all d columns; V_enroll
/// places v*T^(k) in column h for the next global index N+1, zeros elsewhere.
export function prepare(v, N, params) {
  const { d } = params;
  const T = params.T;
  const { h, k } = slotFor(N, params);
  const Videntify = v.map((x) => Array(d).fill(BigInt(x)));
  const Venroll = zeros(v.length, d);
  const scale = T ** BigInt(k);
  v.forEach((x, i) => { Venroll[i][h] = BigInt(x) * scale; });
  return { Videntify, Venroll, h, k };
}

function ctr(x, T) {
  let r = ((x % T) + T) % T;
  if (r > T / 2n) r -= T; // centered representative in (-T/2, T/2]
  return r;
}

export class ScmvGallery {
  constructor(params) {
    this.params = params;
    this.blocks = [];
    this.N = 0;
  }

  /// SCMV.Identify + Decrypt (Eqs. 2-4): per-slot inner products, then
  /// recursive centered base-T decomposition into n scores per slot.
  identify(Videntify) {
    const { n, d, T } = this.params;
    const scores = [];
    this.blocks.forEach((W, m) => {
      for (let j = 0; j < d; j++) {
        let z = 0n;
        for (let i = 0; i < W.length; i++) z += Videntify[i][j] * W[i][j];
        for (let t = 0; t < n; t++) {
          const s = ctr(z, T);
          z = (z - s) / T;
          const index = m * n * d + t * d + j;
          if (index < this.N) scores[index] = s;
        }
      }
    });
    return scores;
  }

  /// SCMV.Update (Eq. 5): merge into the last block by addition if it is not
  /// full, otherwise append. The placement inside Venroll is taken as given,
  /// exactly as in the paper's homomorphic update.
  update(Venroll) {
    const { n, d } = this.params;
    if (this.N % (n * d) === 0) {
      this.blocks.push(Venroll.map((row) => [...row]));
    } else {
      const W = this.blocks.at(-1);
      for (let i = 0; i < W.length; i++) for (let j = 0; j < d; j++) W[i][j] += Venroll[i][j];
    }
    this.N += 1;
  }
}

export function innerProduct(a, b) {
  return a.reduce((s, x, i) => s + BigInt(x) * BigInt(b[i]), 0n);
}

/// Deterministic synthetic identities: base direction per person, noisy
/// recaptures around it. Synthetic only; no biometric model or real data.
export function syntheticPeople(seed, L) {
  let state = seed >>> 0 || 1;
  const rand = () => {
    state ^= state << 13; state >>>= 0;
    state ^= state >>> 17;
    state ^= state << 5; state >>>= 0;
    return (state + 0.5) / 4294967296;
  };
  const gaussian = () => Math.sqrt(-2 * Math.log(rand())) * Math.cos(2 * Math.PI * rand());
  const bases = new Map();
  return {
    capture(person, gamma, noise = 0.15) {
      if (!bases.has(person)) bases.set(person, Array.from({ length: L }, gaussian));
      const base = bases.get(person);
      return quantize(base.map((x) => x + noise * gaussian()), gamma);
    },
  };
}
