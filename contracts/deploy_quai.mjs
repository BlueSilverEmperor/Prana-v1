/**
 * Deploys QuaiVeroAdapter to Quai Network (Orchard testnet 15000 or mainnet 9) with the `quais` SDK.
 *
 * It either deploys for real and prints the address the chain returned, or it exits non-zero. It never
 * reports a deployment that did not happen. `--dry-run` validates the configuration and prints the plan.
 *
 * Env (all required unless marked):
 *   QUAI_PRIVATE_KEY      deployer key. No default: a public fallback key is owned by whoever sweeps it.
 *   QUAI_RPC              RPC URL (optional, default Orchard cyprus1). Logged without path or query.
 *   QUAI_CHAIN_ID         9 or 15000 (optional, default 15000)
 *   QUAI_CONFIRM_MAINNET  must be "yes" when QUAI_CHAIN_ID=9
 *   QUAI_ZONE             zone name the adapter enforces (optional, default "cyprus1")
 *   VERO_THREAT_REGISTRY, VERO_MULTISEND, VERO_TIMELOCK, QI_TOKEN   constructor addresses
 * Build first: `forge build` (reads out/QuaiVeroAdapter.sol/QuaiVeroAdapter.json).
 */

import { existsSync, readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const HERE = dirname(fileURLToPath(import.meta.url));
const ARTIFACT = join(HERE, 'out', 'QuaiVeroAdapter.sol', 'QuaiVeroAdapter.json');
const DEFAULT_RPC = 'https://orchard.rpc.quai.network/cyprus1';
const NETWORKS = { 9: 'mainnet', 15000: 'orchard' };
const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
const KEY_RE = /^0x[0-9a-fA-F]{64}$/;
const ZONE_RE = /^[a-z]+[0-9]$/;

class DeployConfigError extends Error {}

function requireEnv(env, name, pattern) {
  const value = (env[name] || '').trim();
  if (!value) throw new DeployConfigError(`${name} is required`);
  if (pattern && !pattern.test(value)) throw new DeployConfigError(`${name} is malformed`);
  return value;
}

/** Shows only the RPC origin, so API keys in the path or query never reach logs. */
export function redactRpc(url) {
  try {
    return new URL(url).origin;
  } catch {
    return '<invalid url>';
  }
}

export function readConfig(env = process.env) {
  const chainId = Number(env.QUAI_CHAIN_ID || '15000');
  if (!Number.isInteger(chainId) || !NETWORKS[chainId]) {
    throw new DeployConfigError('QUAI_CHAIN_ID must be 9 (mainnet) or 15000 (orchard)');
  }
  if (chainId === 9 && env.QUAI_CONFIRM_MAINNET !== 'yes') {
    throw new DeployConfigError('Refusing mainnet (chain 9) without QUAI_CONFIRM_MAINNET=yes');
  }
  const zone = (env.QUAI_ZONE || 'cyprus1').trim().toLowerCase();
  if (!ZONE_RE.test(zone)) throw new DeployConfigError('QUAI_ZONE must look like "cyprus1"');
  return {
    chainId,
    network: NETWORKS[chainId],
    rpc: env.QUAI_RPC || DEFAULT_RPC,
    privateKey: requireEnv(env, 'QUAI_PRIVATE_KEY', KEY_RE),
    zone,
    args: {
      threatRegistry: requireEnv(env, 'VERO_THREAT_REGISTRY', ADDRESS_RE),
      multiSend: requireEnv(env, 'VERO_MULTISEND', ADDRESS_RE),
      timelock: requireEnv(env, 'VERO_TIMELOCK', ADDRESS_RE),
      qiToken: requireEnv(env, 'QI_TOKEN', ADDRESS_RE),
    },
  };
}

function loadArtifact() {
  if (!existsSync(ARTIFACT)) throw new DeployConfigError(`Missing ${ARTIFACT}; run \`forge build\` first`);
  const json = JSON.parse(readFileSync(ARTIFACT, 'utf8'));
  const bytecode = json.bytecode?.object;
  if (!Array.isArray(json.abi) || !bytecode) throw new DeployConfigError('Artifact has no abi/bytecode');
  return { abi: json.abi, bytecode };
}

export async function deployQuaiAdapter({ env = process.env, dryRun = false } = {}) {
  const cfg = readConfig(env);
  const artifact = loadArtifact();
  console.log(`[QUAI DEPLOY] chain ${cfg.chainId} (${cfg.network}) via ${redactRpc(cfg.rpc)}, zone ${cfg.zone}`);

  let quais;
  try {
    quais = await import('quais');
  } catch {
    throw new DeployConfigError('The `quais` package is not installed (npm i quais); nothing was deployed');
  }
  const zoneHash = quais.keccak256(quais.toUtf8Bytes(cfg.zone));
  const ctorArgs = [cfg.args.threatRegistry, cfg.args.multiSend, cfg.args.timelock, cfg.args.qiToken, zoneHash];

  if (dryRun) {
    console.log('[QUAI DEPLOY] DRY RUN: configuration valid, nothing deployed. Constructor args:', ctorArgs);
    return { deployed: false, dryRun: true, chainId: cfg.chainId, zone: cfg.zone };
  }

  const provider = new quais.JsonRpcProvider(cfg.rpc, undefined, { usePathing: true });
  const wallet = new quais.Wallet(cfg.privateKey, provider);
  const factory = new quais.ContractFactory(artifact.abi, artifact.bytecode, wallet);
  const contract = await factory.deploy(...ctorArgs);
  await contract.waitForDeployment();
  const address = await contract.getAddress();
  console.log(`[QUAI DEPLOY] QuaiVeroAdapter deployed at ${address}`);
  return { deployed: true, chainId: cfg.chainId, network: cfg.network, zone: cfg.zone, adapterAddress: address };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  deployQuaiAdapter({ dryRun: process.argv.includes('--dry-run') }).then(
    () => process.exit(0),
    (err) => {
      // Only our own config messages are printed verbatim; provider errors can echo the RPC URL.
      const message = err instanceof DeployConfigError ? err.message : `${err.name}: deployment failed (see provider logs)`;
      console.error(`[QUAI DEPLOY] FAILED: ${message}`);
      process.exit(1);
    },
  );
}
