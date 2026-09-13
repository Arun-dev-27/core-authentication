// Integration tests run against the *_test database and Redis DB index 1 (see .env.test).
process.env.NODE_ENV = 'test';
process.env.ENV_FILE = process.env.ENV_FILE ?? '.env.test';
// eslint-disable-next-line @typescript-eslint/no-require-imports
const { loadEnvFiles } = require('@config/configuration') as typeof import('@config/configuration');
loadEnvFiles();
