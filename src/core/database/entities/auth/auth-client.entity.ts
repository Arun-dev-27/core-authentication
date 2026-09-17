import { Column, Entity, OneToMany, PrimaryGeneratedColumn } from 'typeorm';
import type { FederationClientConfig } from '@shared/types/federation-client.types';
import { AuthClientCallback } from './auth-client-callback.entity';
import { AuthClientOrigin } from './auth-client-origin.entity';

/** `auth_clients` - a registered client application allowed to use Embedded Login. */
@Entity({ name: 'auth_clients' })
export class AuthClient {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'client_id', type: 'varchar', length: 64, unique: true })
  clientId: string;

  @Column({ type: 'varchar', length: 255 })
  name: string;

  @Column({ name: 'application_code', type: 'varchar', length: 64 })
  applicationCode: string;

  @Column({ name: 'application_name', type: 'varchar', length: 255 })
  applicationName: string;

  @Column({ name: 'business_unit', type: 'varchar', length: 255, nullable: true })
  businessUnit: string | null;

  @Column({ type: 'varchar', length: 255, nullable: true })
  utility: string | null;

  @Column({ type: 'varchar', length: 32 })
  environment: string;

  @Column({ name: 'client_type', type: 'varchar', length: 16, default: 'WEB' })
  clientType: string;

  @Column({ name: 'authentication_mode', type: 'varchar', length: 24 })
  authenticationMode: FederationClientConfig['authentication_mode'];

  @Column({ type: 'varchar', length: 24, default: 'PENDING' })
  status: FederationClientConfig['status'];

  @Column({ name: 'initiate_login_uri', type: 'varchar', length: 2048, nullable: true })
  initiateLoginUri: string | null;

  @Column({ name: 'created_at', type: 'timestamptz', default: () => 'now()' })
  createdAt: Date;

  @Column({ name: 'updated_at', type: 'timestamptz', default: () => 'now()' })
  updatedAt: Date;

  @OneToMany(() => AuthClientOrigin, (origin) => origin.client)
  origins: AuthClientOrigin[];

  @OneToMany(() => AuthClientCallback, (callback) => callback.client)
  callbacks: AuthClientCallback[];
}
