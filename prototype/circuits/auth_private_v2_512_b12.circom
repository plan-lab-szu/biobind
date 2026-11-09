pragma circom 2.2.3;

include "./auth_private_v2.circom";

component main {public [credRoot, devRoot, cProbe, policyDigest, ctxHash, epsilon, notAfter, scope, nullifier]} =
    AuthPrivateV2(512, 12, 4095, 20, 26, 34, 20, 10);
