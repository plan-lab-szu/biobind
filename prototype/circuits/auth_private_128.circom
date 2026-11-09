pragma circom 2.2.3;

include "./auth_private.circom";

// 128-D, credential tree depth 20 (about 1M leaves), device tree depth 10.
component main {public [credRoot, devRoot, cProbe, policyDigest, ctxHash, epsilon, notAfter, scope, nullifier]} =
    AuthPrivate(128, 16, 65535, 15, 9, 10, 48, 20, 10);
