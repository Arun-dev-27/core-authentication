import { AppConfig } from '@config/config.module';
import { DomainError } from '@common/errors/domain-error';
import type { FederationClientConfig } from '@shared/types/federation-client.types';
import type { LoginTransaction } from '@shared/types/transaction.types';
import { TransactionsController } from './transactions.controller';

const ISSUER = 'http://localhost:3001';
const RMS = 'http://localhost:4001';
const RMS_ADMIN = 'https://rms-admin.example.test';
const CALLBACK = `${RMS}/auth/core/callback`;
const CALLBACK_2 = `${RMS}/auth/core/callback2`;
const STATE = 'state-abcdefghij-0123456789';

function client(origins: string[], overrides: Partial<FederationClientConfig> = {}): FederationClientConfig {
  return {
    client_id: 'rms-web-dev',
    status: 'ACTIVE',
    authentication_mode: 'EMBEDDED_OR_REDIRECT',
    allowed_embed_origins: origins,
    callback_uri: CALLBACK,
    callback_uris: [CALLBACK, CALLBACK_2],
    ...overrides,
  } as unknown as FederationClientConfig;
}

function setup(opts: { client: FederationClientConfig; nodeEnv?: 'development' | 'production'; csrf?: boolean }) {
  const store = new Map<string, LoginTransaction>();
  const transactions = {
    create: jest.fn(async (input: Omit<LoginTransaction, 'csrf' | 'status' | 'created_at' | 'expires_at'>) => {
      const txn: LoginTransaction = { ...input, csrf: 'csrf-token-for-this-transaction', status: 'PENDING', created_at: '2026-09-14T10:00:00.000Z', expires_at: '2026-09-14T10:05:00.000Z' };
      store.set(txn.transaction_id, txn);
      return txn;
    }),
    get: jest.fn(async (id: string) => store.get(id) ?? null),
    remainingSeconds: jest.fn(async () => 241),
  };
  const registry = { getFresh: jest.fn(async () => opts.client), get: jest.fn(async () => opts.client) };
  const config = new AppConfig({ ISSUER, NODE_ENV: opts.nodeEnv ?? 'development', TRANSACTION_TTL_SECONDS: 300, TRANSACTION_API_RETURNS_CSRF: opts.csrf } as never);
  const controller = new TransactionsController(transactions as never, registry as never, config, { record: jest.fn() } as never);
  return { controller, transactions, registry, store };
}

const code = async (promise: Promise<unknown>) => {
  try {
    await promise;
  } catch (error) {
    return error instanceof DomainError ? error.code : String(error);
  }
  return 'NO_ERROR';
};

describe('TransactionsController (POST /auth/transaction, GET /auth/transaction/:id)', () => {
  it('returns everything an API client needs, from fresh client configuration', async () => {
    const { controller, registry } = setup({ client: client([RMS]) });
    const body = await controller.create({ client_id: 'rms-web-dev', state: STATE, origin: RMS, display: 'embed' });

    expect(registry.getFresh).toHaveBeenCalledWith('rms-web-dev');
    expect(registry.get).not.toHaveBeenCalled();
    expect(body).toMatchObject({
      client_id: 'rms-web-dev',
      display: 'embed',
      state: STATE,
      status: 'PENDING',
      target_origin: RMS,
      callback_uri: null,
      expires_in: 300,
      csrf: 'csrf-token-for-this-transaction',
      csrf_header: 'x-csrf-token',
      required_origin: ISSUER,
    });
    const url = new URL(body.login_url);
    expect(url.origin + url.pathname).toBe(`${ISSUER}/embed/login`);
    expect(Object.fromEntries(url.searchParams)).toEqual({ client_id: 'rms-web-dev', transaction_id: body.transaction_id, state: STATE, display: 'embed', origin: RMS });
  });

  it('selects exactly one of several registered origins', async () => {
    const { controller } = setup({ client: client([RMS, RMS_ADMIN]) });
    expect((await controller.create({ client_id: 'rms-web-dev', state: STATE, origin: RMS_ADMIN })).target_origin).toBe(RMS_ADMIN);
    expect((await controller.create({ client_id: 'rms-web-dev', state: STATE, origin: `${RMS_ADMIN}/` })).target_origin).toBe(RMS_ADMIN);
    expect(await code(controller.create({ client_id: 'rms-web-dev', state: STATE }))).toBe('ORIGIN_NOT_ALLOWED');
    expect(await code(controller.create({ client_id: 'rms-web-dev', state: STATE, origin: 'https://evil.example.test' }))).toBe('ORIGIN_NOT_ALLOWED');
    expect(await code(controller.create({ client_id: 'rms-web-dev', state: STATE, origin: `${RMS_ADMIN}.evil.test` }))).toBe('ORIGIN_NOT_ALLOWED');
  });

  it('defaults to the only registered origin', async () => {
    const { controller } = setup({ client: client([RMS]) });
    expect((await controller.create({ client_id: 'rms-web-dev', state: STATE })).target_origin).toBe(RMS);
  });

  it('applies the current client state: removed origin, suspended client, redirect-only client', async () => {
    expect(await code(setup({ client: client([]) }).controller.create({ client_id: 'rms-web-dev', state: STATE, origin: RMS }))).toBe('ORIGIN_NOT_ALLOWED');
    expect(await code(setup({ client: client([RMS], { status: 'SUSPENDED' } as never) }).controller.create({ client_id: 'rms-web-dev', state: STATE, origin: RMS }))).toBe('CLIENT_NOT_ACTIVE');
    expect(await code(setup({ client: client([RMS], { authentication_mode: 'REDIRECT' } as never) }).controller.create({ client_id: 'rms-web-dev', state: STATE, origin: RMS }))).toBe(
      'AUTHENTICATION_MODE_NOT_ALLOWED',
    );
  });

  it('page display returns the selected callback and passes redirect_uri to the login page', async () => {
    const { controller } = setup({ client: client([RMS]) });
    const body = await controller.create({ client_id: 'rms-web-dev', state: STATE, display: 'page', redirect_uri: CALLBACK_2 });
    expect(body).toMatchObject({ display: 'page', target_origin: null, callback_uri: CALLBACK_2 });
    const params = new URL(body.login_url).searchParams;
    expect(params.get('display')).toBe('page');
    expect(params.get('redirect_uri')).toBe(CALLBACK_2);
    expect(params.has('origin')).toBe(false);
    expect(await code(controller.create({ client_id: 'rms-web-dev', state: STATE, display: 'page', redirect_uri: 'https://evil.example.test/cb' }))).toBe('CALLBACK_NOT_ALLOWED');
  });

  it('CSRF token in the response follows TRANSACTION_API_RETURNS_CSRF (default: off in production)', async () => {
    const without = (body: object) => expect(body).not.toHaveProperty('csrf');
    without(await setup({ client: client([RMS]), nodeEnv: 'production' }).controller.create({ client_id: 'rms-web-dev', state: STATE }));
    without(await setup({ client: client([RMS]), csrf: false }).controller.create({ client_id: 'rms-web-dev', state: STATE }));
    expect(await setup({ client: client([RMS]), nodeEnv: 'production', csrf: true }).controller.create({ client_id: 'rms-web-dev', state: STATE })).toHaveProperty('csrf');
  });

  it('status returns lifecycle data for the owning client only, never the CSRF token or state', async () => {
    const { controller, store } = setup({ client: client([RMS]) });
    const created = await controller.create({ client_id: 'rms-web-dev', state: STATE, origin: RMS });

    const pending = await controller.status(created.transaction_id, 'rms-web-dev');
    expect(pending).toEqual({ transaction_id: created.transaction_id, client_id: 'rms-web-dev', display: 'embed', status: 'PENDING', target_origin: RMS, expires_at: created.expires_at, expires_in: 241 });
    expect(pending).not.toHaveProperty('csrf');
    expect(pending).not.toHaveProperty('state');

    store.set(created.transaction_id, { ...store.get(created.transaction_id)!, status: 'COMPLETED' });
    expect((await controller.status(created.transaction_id, 'rms-web-dev')).status).toBe('COMPLETED');

    expect(await code(controller.status(created.transaction_id, 'ams-web-dev'))).toBe('TRANSACTION_INVALID');
    expect(await code(controller.status('txn_does_not_exist_000000', 'rms-web-dev'))).toBe('TRANSACTION_INVALID');
    expect(await code(controller.status(created.transaction_id, undefined))).not.toBe('NO_ERROR');
  });
});
