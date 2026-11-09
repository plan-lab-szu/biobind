pragma circom 2.2.3;

include "./auth_private_v2.circom";

component main {public [credRoot, devRoot, cProbe, policyDigest, ctxHash, epsilon, notAfter, scope, nullifier]} =
    AuthPrivateV2(128, 16, 65535, 15, 9, 48, 20, 10);
