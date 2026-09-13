import { Module } from '@nestjs/common';
import { AssertionsModule } from '@modules/assertions/assertions.module';
import { AuthzClient } from './services/authz-client.service';

/** HTTP client for the Core Identity Authorization Service, authenticated with self-signed RS256 service tokens (no API keys). */
@Module({
  imports: [AssertionsModule],
  providers: [AuthzClient],
  exports: [AuthzClient],
})
export class AuthorizationClientModule {}
