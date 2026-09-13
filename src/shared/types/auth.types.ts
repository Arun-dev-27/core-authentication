export type IdentityType = 'ITS' | 'NON_ITS';

export interface AuthenticatedUser {
  id: string;
  itsId: string;
  identityType: IdentityType;
  username: string;
  displayName: string | null;
}
