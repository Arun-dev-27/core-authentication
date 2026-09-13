import { parseArgs } from 'node:util';
import { loadEnv, loadEnvFiles } from '@config/configuration';
import { SigningKeyProvider, createKeyProvider } from '@modules/keys/services/key-providers';
import { RotationAction, rotateKeyset } from '@modules/keys/services/keyset';

/**
 * RS256 signing key lifecycle tooling (NEXT -> ACTIVE -> RETIRING -> RETIRED).
 *
 *   npm run keys:generate                 # bootstrap: one ACTIVE key
 *   npm run keys:rotate -- stage          # add NEXT (published in JWKS, not signing)
 *   npm run keys:rotate -- promote        # NEXT -> ACTIVE, ACTIVE -> RETIRING
 *   npm run keys:rotate -- retire         # RETIRING -> RETIRED after --min-retiring-seconds (default 3600)
 *   npm run keys:rotate -- status         # print kids/status (never key material)
 *
 * Provider comes from SIGNING_KEY_PROVIDER (file | ssm). Private keys are never printed.
 */

async function main() {
  loadEnvFiles();
  const env = loadEnv();
  const { positionals, values } = parseArgs({
    allowPositionals: true,
    options: { 'min-retiring-seconds': { type: 'string' }, bits: { type: 'string' } },
  });
  const action = (positionals[0] ?? 'status') as RotationAction | 'status';

  const provider: SigningKeyProvider = createKeyProvider(env);

  let keys = await provider.load().catch((error: Error) => {
    if (action === 'generate') return [];
    throw error;
  });

  if (action !== 'status') {
    if (!['generate', 'stage', 'promote', 'retire'].includes(action)) throw new Error(`unknown action ${action}`);
    keys = rotateKeyset(keys, action, {
      minRetiringSeconds: values['min-retiring-seconds'] ? Number(values['min-retiring-seconds']) : Math.max(3600, env.ASSERTION_TTL_SECONDS + env.KEY_REFRESH_INTERVAL_SECONDS + 300),
      bits: values.bits ? Number(values.bits) : undefined,
    });
    await provider.save(keys);
    console.log(`${action}: saved to ${provider.description}`);
  }

  console.table(keys.map((k) => ({ kid: k.kid, status: k.status, created: k.createdAt, activated: k.activatedAt ?? '', retiring: k.retiringAt ?? '', retired: k.retiredAt ?? '' })));
  if (action === 'stage') {
    console.log('Next: wait at least KEY_REFRESH_INTERVAL_SECONDS + verifier JWKS cache time, then run "promote".');
  }
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
