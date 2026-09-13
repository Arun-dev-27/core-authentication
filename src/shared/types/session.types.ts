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
}
