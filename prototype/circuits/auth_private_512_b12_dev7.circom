pragma circom 2.2.3;

include "./auth_private.circom";

component main {public [credRoot, devRoot, cProbe, policyDigest, ctxHash, epsilon, notAfter, scope, nullifier]} =
    AuthPrivate(512, 12, 4095, 20, 26, 26, 34, 20, 7);
