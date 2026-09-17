import { Module } from '@nestjs/common';
import { CredentialService } from './services/credential.service';

/** Password verification against the existing identity_db login tables (read-only). */
@Module({
  providers: [CredentialService],
  exports: [CredentialService],
})
export class CredentialsModule {}
