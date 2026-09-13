import { Module } from '@nestjs/common';
import { CredentialService } from './services/credential.service';

/** Password verification against the Authentication DB. */
@Module({
  providers: [CredentialService],
  exports: [CredentialService],
})
export class CredentialsModule {}
