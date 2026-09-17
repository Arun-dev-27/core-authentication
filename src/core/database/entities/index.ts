import { AuthAuditEvent } from './auth/auth-audit-event.entity';
import { AuthClientCallback } from './auth/auth-client-callback.entity';
import { AuthClientOrigin } from './auth/auth-client-origin.entity';
import { AuthClient } from './auth/auth-client.entity';
import { AuthLoginAttempt } from './auth/auth-login-attempt.entity';
import { AuthSessionClient } from './auth/auth-session-client.entity';
import { AuthSession } from './auth/auth-session.entity';
import { SigningKeyMetadata } from './auth/signing-key-metadata.entity';
import { IdentityUser } from './identity/identity-user.entity';
import { MuminMaster } from './identity/mumin-master.entity';
import { UserEligible } from './identity/user-eligible.entity';

export {
  AuthAuditEvent,
  AuthClient,
  AuthClientCallback,
  AuthClientOrigin,
  AuthLoginAttempt,
  AuthSession,
  AuthSessionClient,
  IdentityUser,
  MuminMaster,
  SigningKeyMetadata,
  UserEligible,
};

/** EXISTING tables owned by the Mumin sync service. Read-only: this service never writes to them. */
export const IDENTITY_SYNCED_ENTITIES = [IdentityUser, UserEligible, MuminMaster];

/** The 8 tables this service owns in the same schema, created only when missing (npm run db:ensure-auth-tables). */
export const AUTH_ENTITIES = [
  AuthSession,
  AuthSessionClient,
  AuthLoginAttempt,
  AuthAuditEvent,
  AuthClient,
  AuthClientOrigin,
  AuthClientCallback,
  SigningKeyMetadata,
];

export const IDENTITY_DB_ENTITIES = [...IDENTITY_SYNCED_ENTITIES, ...AUTH_ENTITIES];
