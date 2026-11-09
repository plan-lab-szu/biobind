// Read only public chain data. No fixture labels, openings, secrets or signer keys.
export async function observePrivateGateway(provider, gateway, extraContracts = []) {
  const interfaces = new Map([gateway, ...extraContracts].map(c => [c.address.toLowerCase(), c.interface]));
  const transactions = [];
  const decimal = x => typeof x === 'boolean' ? x : x?.toString();
  for (let height = 0; height <= await provider.getBlockNumber(); height++) {
    const block = await provider.getBlockWithTransactions(height);
    for (const tx of block.transactions) {
      const receipt = await provider.getTransactionReceipt(tx.hash);
      const row = { hash: tx.hash, block: height, timestamp: block.timestamp,
        from: tx.from, to: tx.to, value: tx.value.toString(), gasUsed: receipt.gasUsed.toString(),
        status: receipt.status, calldata: tx.data, logs: receipt.logs.map(l => ({address:l.address,topics:l.topics,data:l.data})) };
      const iface = interfaces.get(tx.to?.toLowerCase());
      if (iface) {
        try {
          const decoded = iface.parseTransaction(tx);
          row.method = decoded.name;
          row.args = Object.fromEntries(decoded.functionFragment.inputs.map((p, i) =>
            [p.name || String(i), Array.isArray(decoded.args[i]) ? decoded.args[i].map(decimal) : decimal(decoded.args[i])]));
        } catch { /* Keep unparsed calldata, including deployments, as public evidence. */ }
      }
      transactions.push(row);
    }
  }
  const calls = transactions.filter(t => t.to?.toLowerCase() === gateway.address.toLowerCase());
  const issued = calls.filter(t => t.method === 'issue');
  const auth = calls.filter(t => t.method === 'authenticate').map(t => {
    const p = t.args.pub;
    return { transactionHash:t.hash, sender:t.from, nonce:t.args.nonce,
      publicSignals:Object.fromEntries(['credRoot','devRoot','cProbe','policyDigest','ctxHash','epsilon','notAfter','scope','nullifier'].map((n,i)=>[n,p[i]])),
      funders:[...new Set(transactions.filter(f=>f.to===t.from && BigInt(f.value)>0n).map(f=>f.from))] };
  });
  const pairs = [];
  for (let i=0;i<auth.length;i++) for (let j=i+1;j<auth.length;j++) {
    const a=auth[i],b=auth[j];
    pairs.push({i,j,sameScope:a.publicSignals.scope===b.publicSignals.scope,
      sameNullifier:a.publicSignals.nullifier===b.publicSignals.nullifier,
      sameSender:a.sender===b.sender, commonFunder:a.funders.some(f=>b.funders.includes(f)),
      sameProbeCommitment:a.publicSignals.cProbe===b.publicSignals.cProbe});
  }
  return {scope:'All local-chain calldata, logs and transaction metadata; no witness inputs.',
    gateway:gateway.address, transactions, issued, authentications:auth, pairs,
    interpretation:'Same-scope nullifiers intentionally link sessions. Different bytes across scopes do not prove unlinkability. Common funding is observable but does not by itself identify a holder. Enrollment commitments and idc are public in issuance calldata. This small trace is not an anonymity benchmark.'};
}
