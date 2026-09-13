/**
 * Application error with a stable machine-readable code.
 * Messages are user-safe: they never reveal whether an account exists, and never contain secrets.
 */
export class DomainError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly status = 400,
    readonly details?: Record<string, unknown>,
    readonly headers?: Record<string, string>,
  ) {
    super(message);
    this.name = 'DomainError';
  }
}

/** Which CSRF defence failed - returned as details.reason so integrators can fix their request. */
export type CsrfFailure = 'ORIGIN_HEADER_MISMATCH' | 'CSRF_TOKEN_MISSING' | 'CSRF_TOKEN_MISMATCH';

const CSRF_MESSAGES: Record<CsrfFailure, string> = {
  ORIGIN_HEADER_MISMATCH: 'The request could not be verified: it must be sent from the Identity Federation origin. Please reload and try again.',
  CSRF_TOKEN_MISSING: 'The request could not be verified: the x-csrf-token header is missing. Please reload and try again.',
  CSRF_TOKEN_MISMATCH: 'The request could not be verified: x-csrf-token does not belong to this transaction. Please reload and try again.',
};

export const Errors = {
  invalidRequest: (message: string) => new DomainError('INVALID_REQUEST', message, 400),
  clientNotFound: () => new DomainError('CLIENT_NOT_FOUND', 'Unknown client', 400),
  clientInactive: () => new DomainError('CLIENT_NOT_ACTIVE', 'This application is not currently enabled for sign-in', 403),
  modeNotAllowed: () => new DomainError('AUTHENTICATION_MODE_NOT_ALLOWED', 'This sign-in mode is not enabled for the application', 403),
  originNotAllowed: () => new DomainError('ORIGIN_NOT_ALLOWED', 'The requesting origin is not registered for this application', 403),
  callbackNotAllowed: () => new DomainError('CALLBACK_NOT_ALLOWED', 'The callback URI is not registered for this application', 400),
  transactionInvalid: () => new DomainError('TRANSACTION_INVALID', 'The sign-in request has expired. Please start again.', 400),
  transactionUsed: () => new DomainError('TRANSACTION_ALREADY_USED', 'This sign-in request was already completed', 409),
  csrf: (reason: CsrfFailure = 'CSRF_TOKEN_MISMATCH') => new DomainError('CSRF_VALIDATION_FAILED', CSRF_MESSAGES[reason], 403, { reason }),
  invalidCredentials: () => new DomainError('INVALID_CREDENTIALS', 'Invalid ITS ID or password', 401),
  accountUnavailable: () => new DomainError('ACCOUNT_UNAVAILABLE', 'This account cannot sign in. Please contact support.', 403),
  tooManyAttempts: (retryAfter: number) =>
    new DomainError('TOO_MANY_ATTEMPTS', 'Too many sign-in attempts. Please try again later.', 429, { retry_after: retryAfter }, {
      'retry-after': String(retryAfter),
    }),
  sessionRequired: () => new DomainError('SESSION_REQUIRED', 'Your session has expired. Please sign in again.', 401),
  unauthorized: () => new DomainError('UNAUTHENTICATED', 'Authentication required', 401),
  dependencyUnavailable: () => new DomainError('DEPENDENCY_UNAVAILABLE', 'Sign-in is temporarily unavailable. Please try again shortly.', 503),
};
