import { Module } from '@nestjs/common';
import { KeysModule } from '@modules/keys/keys.module';
import { AccessTokenVerifier } from './services/access-token.verifier';
import { AssertionService } from './services/assertion.service';

/** RS256 login assertions, logout tokens, service tokens and administrator access tokens - all verifiable via JWKS. */
@Module({
  imports: [KeysModule],
  providers: [AssertionService, AccessTokenVerifier],
  exports: [AssertionService, AccessTokenVerifier],
})
export class AssertionsModule {}
