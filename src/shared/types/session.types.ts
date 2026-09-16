export interface FederationSession {
  sid: string;
  its_id: string;
  identity_type: 'ITS' | 'NON_ITS';
  display_name: string | null;
  auth_method: string;
  /** epoch seconds */
  auth_time: number;
  created_at: string;
  expires_at: string;
  absolute_expires_at: string;
  is_active: boolean;
  /** sha256 of the cookie handle; the handle itself is never stored */
  handle_hash: string;
  /** Client IP this session was established from; the cookie is only honoured from the same one. */
  ip_address: string | null;
  /** User-Agent this session was established with, capped at USER_AGENT_MAX_LENGTH. */
  user_agent: string | null;
}
