import { Module } from '@nestjs/common';
import { CredentialService } from './services/credential.service';
import { LegacyCredentialService } from './services/legacy-credential.service';

/**
 * Password verification against the Authentication DB, plus the optional read-only legacy MMS
 * fallback used when a migrated account's scrypt hash is older than its MMS password.
 */
@Module({
  providers: [CredentialService, LegacyCredentialService],
  exports: [CredentialService],
})
export class CredentialsModule {}
