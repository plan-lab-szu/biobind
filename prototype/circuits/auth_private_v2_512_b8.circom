pragma circom 2.2.3;

include "./auth_private_v2.circom";

component main {public [credRoot, devRoot, cProbe, policyDigest, ctxHash, epsilon, notAfter, scope, nullifier]} =
    AuthPrivateV2(512, 8, 255, 30, 18, 25, 20, 10);
