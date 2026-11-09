pragma circom 2.2.3;

include "./auth_private.circom";

// 512-D, 16-bit coordinates, credential tree depth 20, device tree depth 10.
component main {public [credRoot, devRoot, cProbe, policyDigest, ctxHash, epsilon, notAfter, scope, nullifier]} =
    AuthPrivate(512, 16, 65535, 15, 35, 36, 48, 20, 10);
