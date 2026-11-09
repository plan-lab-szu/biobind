pragma circom 2.2.3;

include "./auth_private.circom";

// 512-D, 12-bit coordinates, credential tree depth 20, device tree depth 10.
component main {public [credRoot, devRoot, cProbe, policyDigest, ctxHash, epsilon, notAfter, scope, nullifier]} =
    AuthPrivate(512, 12, 4095, 20, 26, 26, 34, 20, 10);
