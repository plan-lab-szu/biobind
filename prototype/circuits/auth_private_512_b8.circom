pragma circom 2.2.3;

include "./auth_private.circom";

// 512-D, 8-bit coordinates, credential tree depth 20, device tree depth 10.
component main {public [credRoot, devRoot, cProbe, policyDigest, ctxHash, epsilon, notAfter, scope, nullifier]} =
    AuthPrivate(512, 8, 255, 30, 18, 18, 25, 20, 10);
