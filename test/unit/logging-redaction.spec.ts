import { Writable } from 'node:stream';
import pino from 'pino';
import { REDACT_PATHS } from '@common/logging/logger';

describe('log redaction', () => {
  it('never writes passwords, assertions, logout tokens, cookies or key material', () => {
    const lines: string[] = [];
    const sink = new Writable({
      write(chunk, _enc, cb) {
        lines.push(chunk.toString());
        cb();
      },
    });
    const logger = pino({ redact: { paths: REDACT_PATHS, censor: '[REDACTED]' } }, sink);

    logger.info({
      body: { password: 'hunter2-secret', core_assertion: 'aaa.bbb.ccc-secret' },
      token: { logout_token: 'logout-secret' },
      key: { privateKeyPem: '-----BEGIN PRIVATE KEY----- secret' },
      req: { headers: { cookie: 'federation_session=handle-secret', authorization: 'Bearer admin-secret', 'x-api-key': 'api-secret' } },
    });

    const output = lines.join('\n');
    for (const secret of ['hunter2-secret', 'aaa.bbb.ccc-secret', 'logout-secret', 'BEGIN PRIVATE KEY', 'handle-secret', 'admin-secret', 'api-secret']) {
      expect(output).not.toContain(secret);
    }
    expect(output).toContain('[REDACTED]');
  });
});
