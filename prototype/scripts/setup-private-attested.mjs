// Local benchmark setup only. Does not replace any existing BioBind proving key.
import {execFileSync} from 'node:child_process';
import {mkdir, readFile, writeFile, access} from 'node:fs/promises';
import {randomBytes, createHash} from 'node:crypto';
import {resolve} from 'node:path';
const root=resolve(import.meta.dirname,'..'), name='auth_private_attested_dev20';
const out=resolve(root,'build',name), cli=resolve(root,'node_modules/snarkjs/build/cli.cjs');
await mkdir(out,{recursive:true});
const final=resolve(out,`${name}_final.zkey`);
let exists=false; try {await access(final); exists=true;} catch {}
if (exists) throw Error('Benchmark key already exists; preserve it and use the existing artifacts.');
const run=(...args)=>execFileSync(process.execPath,[cli,...args],{cwd:root,stdio:'pipe'}).toString();
const compile=execFileSync(resolve(root,'.toolchain/circom/circom.exe'),
  [resolve(root,'circuits',`${name}.circom`),'--O2','--r1cs','--wasm','--sym','-l',resolve(root,'node_modules'),'-o',out],
  {cwd:root,stdio:'pipe'}).toString();
const r1cs=resolve(out,`${name}.r1cs`);
console.log(compile);
const info=run('r1cs','info',r1cs);
console.log(info);
run('groth16','setup',r1cs,resolve(root,'build/proving/local-benchmark-setup/pot15_final.ptau'),resolve(out,'initial.zkey'));
run('zkey','contribute',resolve(out,'initial.zkey'),final,'--name=benchmark-only',`-e=${randomBytes(32).toString('hex')}`);
run('zkey','export','verificationkey',final,resolve(out,'verification_key.json'));
run('zkey','export','solidityverifier',final,resolve(root,'contracts/generated/Groth16VerifierPrivateAttested.sol'));
const hashes={};
for (const file of ['circuits/auth_private_attested.circom','circuits/auth_private_attested_dev20.circom','circuits/auth_private_v2.circom'])
  hashes[file]=createHash('sha256').update(await readFile(resolve(root,file))).digest('hex');
await writeFile(resolve(out,'setup.json'),JSON.stringify({generatedAt:new Date().toISOString(),
  constraints:Number(/# of Constraints:\s*(\d+)/.exec(info)?.[1]),node:process.version,
  warning:'Local single-contributor benchmark key, not deployable.',sourceSha256:hashes},null,2)+'\n');
