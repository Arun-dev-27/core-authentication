import { Global, Module } from '@nestjs/common';
import { Env, loadEnv } from './configuration';

export class AppConfig {
  readonly issuerOrigin: string;

  constructor(readonly env: Env) {
    this.issuerOrigin = new URL(env.ISSUER).origin;
  }

  /** `iss` claim value - the canonical issuer without trailing slash. */
  get issuer(): string {
    return this.issuerOrigin;
  }

  get isProduction(): boolean {
    return this.env.NODE_ENV === 'production';
  }

  get jwksUri(): string {
    return `${this.issuerOrigin}/.well-known/jwks.json`;
  }
}

@Global()
@Module({
  providers: [{ provide: AppConfig, useFactory: () => new AppConfig(loadEnv()) }],
  exports: [AppConfig],
})
export class ConfigModule {}
