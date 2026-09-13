export type TransactionDisplay = 'embed' | 'page' | 'portal';

export interface LoginTransaction {
  transaction_id: string;
  client_id: string | null;
  state: string | null;
  display: TransactionDisplay;
  /** Exact registered origin that will receive the postMessage (embed only). */
  embed_origin: string | null;
  /** Exact registered callback (page/form_post fallback). */
  callback_uri: string | null;
  csrf: string;
  /** Portal only: federation session this transaction's CSRF token is bound to once the user is signed in. */
  sid?: string | null;
  status: 'PENDING' | 'COMPLETED';
  created_at: string;
  expires_at: string;
}
