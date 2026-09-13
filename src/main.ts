import 'reflect-metadata';
import { loadEnv, loadEnvFiles } from '@config/configuration';
import { createApp } from './bootstrap';

async function main() {
  loadEnvFiles();
  const env = loadEnv();
  const app = await createApp(env);
  await app.listen({ port: env.PORT, host: '0.0.0.0' });
}

main().catch((error: unknown) => {
  // Never print the full error object: config errors are already value-free, others may carry request data.
  // eslint-disable-next-line no-console
  console.error('Fatal startup error:', error instanceof Error ? error.message : error);
  process.exit(1);
});
